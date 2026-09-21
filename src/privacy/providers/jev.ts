import type { CoverageLevel } from '../../runtime/types.js';
import { redactText } from '../../runtime/redaction.js';
import type {
  AdjudicateOptions,
  AdjudicationRequest,
  AdjudicationResult,
  AdjudicationVerdict,
  PiiCandidate,
  PiiChunk,
  PrivacyAdjudicator,
} from '../types.js';

const DEFAULT_ENDPOINT = 'https://api.typesafe.ai/v1/systemone';
const DEFAULT_MODEL = 'jev-latest';
const MAX_RESPONSE_BYTES = 2_000_000;
const REQUEST_TIMEOUT_MS = 45_000;
/** 429 and 529 are documented as retryable; anything else fails the batch. */
const MAX_ATTEMPTS = 3;
const BASE_BACKOFF_MS = 500;

/** Shared judging standard, sent once per request rather than per question. */
const CRITERIA = {
  true: '该片段确实是某个真实自然人的敏感个人信息，泄露后会危害该自然人的权益',
  false:
    '该片段不是自然人的个人信息，或只是测试数据、占位示例、文档说明、检测规则或正则本身、' +
    '公开的企业工商信息、虚构作品内容，或与自然人无关的技术标识（订单号、哈希、SKU、构建号、版本号、trace id）',
} as const;

interface JevAnswer {
  type?: string;
  noul?: number;
}

interface JevResponse {
  model?: string;
  answers?: Record<string, JevAnswer>;
  usage?: { input_tokens?: number; output_tokens?: number };
}

export interface JevAdjudicatorOptions {
  apiKey?: string;
  endpoint?: string;
  model?: string;
  fetchImpl?: typeof fetch;
}

/**
 * Rough input-token estimate used only for batch sizing.
 *
 * CJK codepoints cost roughly one token each; Latin text roughly a quarter per
 * character. The estimate is intentionally conservative — overshooting wastes a
 * little headroom, undershooting costs a `max_tokens_exceeded` round trip.
 */
export function estimateTokens(text: string): number {
  let cjk = 0;
  for (const ch of text) if (ch.charCodeAt(0) > 0x2e80) cjk++;
  return Math.ceil(cjk + (text.length - cjk) / 4) + 8;
}

/**
 * Adjudicates candidate spans and prose chunks with TypeSafe's Jev model.
 *
 * Only ever asked to *judge* spans found by local extractors; it is never asked
 * to produce them, because the API exposes no extraction primitive — Choice,
 * Score and Noul all return judgments constrained to inputs the caller supplied.
 */
export class JevAdjudicator implements PrivacyAdjudicator {
  readonly name = 'jev';
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly model: string;
  private readonly fetchImpl: typeof fetch;
  /** Latched after an auth or redirect failure so a bad key cannot be retried in a loop. */
  private disabled = false;

  constructor(options: JevAdjudicatorOptions = {}) {
    this.apiKey = options.apiKey ?? process.env.TYPESAFE_API_KEY ?? '';
    this.endpoint = options.endpoint ?? process.env.TYPESAFE_ENDPOINT ?? DEFAULT_ENDPOINT;
    this.model = options.model ?? process.env.TYPESAFE_MODEL ?? DEFAULT_MODEL;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  get available(): boolean {
    return Boolean(this.apiKey) && !this.disabled && typeof this.fetchImpl === 'function';
  }

  async adjudicate(request: AdjudicationRequest, options: AdjudicateOptions): Promise<AdjudicationResult> {
    const items = buildQuestionItems(request);
    if (!this.available || items.length === 0) {
      return {
        candidateVerdicts: [],
        chunkVerdicts: [],
        coverage: this.available ? 'full' : 'unsupported',
        provider: this.name,
      };
    }

    const batches = splitByTokenBudget(items, options.tokenBudget, request.sharedContext);
    const verdicts = new Map<string, AdjudicationVerdict>();
    const errors: string[] = [];
    const usage = { inputTokens: 0, outputTokens: 0, requests: 0 };
    let answered = 0;
    let model: string | undefined;

    for (const batch of batches) {
      if (usage.requests >= options.maxRequests) {
        errors.push(`request budget exhausted after ${usage.requests} requests`);
        break;
      }
      try {
        const response = await this.ask(batch, request.sharedContext, options.signal);
        usage.requests += 1;
        usage.inputTokens += response.usage?.input_tokens ?? 0;
        usage.outputTokens += response.usage?.output_tokens ?? 0;
        model ??= response.model;
        for (const item of batch) {
          const probability = response.answers?.[item.id]?.noul;
          if (typeof probability !== 'number' || !Number.isFinite(probability) || probability < 0 || probability > 1) continue;
          verdicts.set(item.id, { id: item.id, isPii: probability >= options.threshold, probability });
          answered += 1;
        }
      } catch (error) {
        usage.requests += 1;
        errors.push(redactText(error instanceof Error ? error.message : String(error)));
      }
    }

    // A batch that failed leaves its inputs unjudged. Reporting `full` there
    // would let an unchecked span read as cleared, so coverage degrades instead.
    const coverage: CoverageLevel = answered === items.length ? 'full' : answered > 0 ? 'partial' : 'observe_only';

    const candidateIds = new Set(request.candidates.map((c) => c.id));
    return {
      candidateVerdicts: [...verdicts.values()].filter((v) => candidateIds.has(v.id)),
      chunkVerdicts: [...verdicts.values()].filter((v) => !candidateIds.has(v.id)),
      coverage,
      provider: this.name,
      model,
      usage,
      errors: errors.length ? errors : undefined,
    };
  }

  private async ask(items: QuestionItem[], sharedContext: string | undefined, signal?: AbortSignal): Promise<JevResponse> {
    let lastError: Error | undefined;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      try {
        return await this.askOnce(items, sharedContext, signal);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (!isRetryable(lastError) || attempt === MAX_ATTEMPTS - 1) break;
        // Exponential backoff with jitter; the service sheds load under 529 and
        // retrying in lockstep across batches would simply re-create the spike.
        const delay = BASE_BACKOFF_MS * 2 ** attempt + Math.floor(Math.random() * BASE_BACKOFF_MS);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
    throw lastError ?? new Error('TypeSafe request failed');
  }

  private async askOnce(items: QuestionItem[], sharedContext: string | undefined, signal?: AbortSignal): Promise<JevResponse> {
    const questions: Record<string, unknown> = {};
    for (const item of items) {
      questions[item.id] = { type: 'noul', instructions: item.instructions, criteria: CRITERIA };
    }
    const body = JSON.stringify({
      model: this.model,
      state: sharedContext ? { 判定口径: sharedContext } : '一批需要逐条判定的文本片段',
      questions,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    signal?.addEventListener('abort', () => controller.abort(), { once: true });
    try {
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: { Authorization: `Bearer ${this.apiKey}`, 'Content-Type': 'application/json' },
        body,
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) this.disabled = true;
        throw new Error(`TypeSafe HTTP ${response.status}`);
      }
      const text = await response.text();
      if (text.length > MAX_RESPONSE_BYTES) throw new Error('TypeSafe response exceeds size limit');
      return JSON.parse(text) as JevResponse;
    } finally {
      clearTimeout(timer);
    }
  }
}

/** Rate limiting and overload are transient; auth and schema errors are not. */
function isRetryable(error: Error): boolean {
  const status = /TypeSafe HTTP (\d{3})/.exec(error.message)?.[1];
  if (!status) return false;
  const code = Number(status);
  return code === 429 || code >= 500;
}

interface QuestionItem {
  id: string;
  instructions: string;
  tokens: number;
}

function candidateInstructions(candidate: PiiCandidate): string {
  return (
    `候选片段是「${candidate.value}」，出现在这句话中：「${candidate.context}」。` +
    '这个片段本身是否是某个真实自然人的敏感个人信息？'
  );
}

function chunkInstructions(chunk: PiiChunk): string {
  return (
    `下面这句话本身是否携带了可识别到具体自然人的敏感个人信息（身份证号、银行账户、` +
    `医疗健康状况、生物识别、行踪轨迹、精确住址、未成年人信息、个人财务状况）？句子：「${chunk.text}」`
  );
}

function buildQuestionItems(request: AdjudicationRequest): QuestionItem[] {
  const items: QuestionItem[] = [];
  for (const candidate of request.candidates) {
    const instructions = candidateInstructions(candidate);
    items.push({ id: candidate.id, instructions, tokens: estimateTokens(instructions) });
  }
  for (const chunk of request.chunks) {
    const instructions = chunkInstructions(chunk);
    items.push({ id: `s${chunk.index}`, instructions, tokens: estimateTokens(instructions) });
  }
  return items;
}

/**
 * Split questions into requests that fit the token budget.
 *
 * The API caps a request by total tokens, not question count, so batching is
 * budgeted rather than counted. Batch size does not affect answers: the same
 * span judged in a batch of 20 and a batch of 400 returns the same verdict.
 */
export function splitByTokenBudget(items: QuestionItem[], budget: number, sharedContext?: string): QuestionItem[][] {
  const overhead = sharedContext ? estimateTokens(sharedContext) : 0;
  const batches: QuestionItem[][] = [];
  let current: QuestionItem[] = [];
  let used = overhead;

  for (const item of items) {
    if (current.length > 0 && used + item.tokens > budget) {
      batches.push(current);
      current = [];
      used = overhead;
    }
    current.push(item);
    used += item.tokens;
  }
  if (current.length) batches.push(current);
  return batches;
}
