import { sha256 } from '../utils/hash.js';
import type { CoverageLevel, PiiCategory } from '../runtime/types.js';
import { chunkLocator, splitChunks } from './chunks.js';
import { extractCandidates } from './candidates.js';
import { OfflineAdjudicator } from './providers/offline.js';
import { hasSoftSignal, isStructuredNoise } from './soft-signals.js';
import {
  DEFAULT_ADJUDICATE_OPTIONS,
  type AdjudicateOptions,
  type AdjudicationResult,
  type PiiCandidate,
  type PiiChunk,
  type PiiLocalization,
  type PrivacyAdjudicator,
  type PrivacyScope,
} from './types.js';

/**
 * Bumped whenever question wording or criteria change. Cached verdicts are keyed
 * on it so a prompt change invalidates stale judgments instead of silently
 * reusing answers to a different question.
 */
export const PROMPT_VERSION = 1;

/** 1-based line number for an absolute character offset. */
function lineAt(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

/** Rough pre-flight estimate used only to reserve budget before sending. */
function estimateRequestTokens(candidates: PiiCandidate[], chunks: PiiChunk[]): number {
  let total = 0;
  for (const candidate of candidates) total += candidate.value.length + candidate.context.length + 60;
  for (const chunk of chunks) total += chunk.text.length + 60;
  return total;
}

export interface PrivacyFinding {
  category: PiiCategory;
  /** 1-based line in the analysed text; pinning findings to line 1 hides where they are. */
  line: number;
  /** Present only for value-level findings; semantic findings have no span. */
  span?: { start: number; end: number; value: string };
  chunkIndex: number;
  localization: PiiLocalization;
  probability: number;
  source: 'deterministic' | 'semantic';
}

export interface SemanticPrivacyReport {
  findings: PrivacyFinding[];
  /** Spans that can be masked character-by-character. */
  valueCount: number;
  /** Sentences flagged with no extractable span; only whole-chunk handling is sound. */
  flaggedChunks: number;
  /** Coarsest localization achieved, so downstream can state what it knows. */
  localization: PiiLocalization;
  coverage: CoverageLevel;
  provider: string;
  model?: string;
  candidatesExamined: number;
  chunksExamined: number;
  /** Sentences deliberately not sent, by local policy rather than failure. */
  chunksSkipped: number;
  scope: PrivacyScope;
  /** True when the shared token ceiling cut the analysis short. */
  budgetExhausted: boolean;
  usage?: { inputTokens: number; outputTokens: number; requests: number };
  errors?: string[];
  fromCache: boolean;
}

export interface VerdictCache {
  get(key: string): SemanticPrivacyReport | undefined;
  set(key: string, report: SemanticPrivacyReport): void;
}

export interface AnalyzeOptions extends Partial<AdjudicateOptions> {
  adjudicator?: PrivacyAdjudicator;
  cache?: VerdictCache;
  /** Context every judgment must consult, e.g. an organisation's own numbers. */
  sharedContext?: string;
  /** Which tracks to send; defaults to `filtered`. */
  scope?: PrivacyScope;
}

/** In-memory cache; a scan repeatedly visits the same text through several rules. */
export class MemoryVerdictCache implements VerdictCache {
  private readonly entries = new Map<string, SemanticPrivacyReport>();
  get(key: string): SemanticPrivacyReport | undefined {
    return this.entries.get(key);
  }
  set(key: string, report: SemanticPrivacyReport): void {
    this.entries.set(key, report);
  }
}

function cacheKey(text: string, provider: string, threshold: number, scope: PrivacyScope): string {
  // Scope is part of the key: a `candidates` run examined strictly less than a
  // `filtered` run, so reusing its verdicts under a wider scope would report
  // unexamined sentences as clean.
  return sha256([PROMPT_VERSION, provider, threshold, scope, text].join('\u0000'));
}

/**
 * Decide which sentences are worth judging.
 *
 * Sentences already carrying a confirmed-candidate span are dropped: the span is
 * the stronger, maskable finding. Structured noise and sentences with no soft
 * signal are dropped because they are the bulk of an agent's footprint and
 * almost never carry a personal disclosure.
 */
function selectChunks(chunks: PiiChunk[], covered: Set<number>, scope: PrivacyScope): PiiChunk[] {
  if (scope === 'candidates') return [];
  if (scope === 'full') return chunks;
  return chunks.filter(
    (chunk) => !covered.has(chunk.index) && !isStructuredNoise(chunk.text) && hasSoftSignal(chunk.text),
  );
}

/**
 * Locate personal data in free text by judging locally extracted spans.
 *
 * Deterministic rules already cover structured `field: value` data well; this
 * path exists for prose, where those rules recall almost nothing because the
 * field-name anchor they depend on is absent.
 *
 * Two localizations come out, and the difference is not cosmetic:
 *  - `value`  a span was confirmed; it can be masked in place
 *  - `chunk`  a sentence carries personal information with no extractable span
 *             ("上周刚做完手术"), so only whole-sentence handling is sound
 */
export async function analyzePrivacy(text: string, options: AnalyzeOptions = {}): Promise<SemanticPrivacyReport> {
  const adjudicator = options.adjudicator ?? new OfflineAdjudicator();
  const settings: AdjudicateOptions = { ...DEFAULT_ADJUDICATE_OPTIONS, ...options };
  const scope = options.scope ?? 'filtered';
  const key = cacheKey(text, adjudicator.name, settings.threshold, scope);

  const cached = options.cache?.get(key);
  if (cached) return { ...cached, fromCache: true };

  const chunks = splitChunks(text);
  const candidates = extractCandidates(text, chunkLocator(chunks));
  const byId = new Map<string, PiiCandidate>(candidates.map((c) => [c.id, c]));

  const coveredChunks = new Set(candidates.map((c) => c.chunkIndex));
  const selectedChunks = selectChunks(chunks, coveredChunks, scope);

  // Reserve the whole request against the shared ceiling before sending. A
  // partial reservation would leave a scan half-analysed with no way to say so.
  const estimated = estimateRequestTokens(candidates, selectedChunks);
  const budgetExhausted = settings.budget ? !settings.budget.tryConsume(estimated) : false;

  const result: AdjudicationResult = budgetExhausted
    ? { candidateVerdicts: [], chunkVerdicts: [], coverage: 'partial', provider: adjudicator.name }
    : await adjudicator.adjudicate(
        { candidates, chunks: selectedChunks, sharedContext: options.sharedContext },
        settings,
      );

  const findings: PrivacyFinding[] = [];
  for (const verdict of result.candidateVerdicts) {
    if (!verdict.isPii) continue;
    const candidate = byId.get(verdict.id);
    if (!candidate) continue;
    findings.push({
      category: candidate.category,
      line: lineAt(text, candidate.start),
      span: { start: candidate.start, end: candidate.end, value: candidate.value },
      chunkIndex: candidate.chunkIndex,
      localization: 'value',
      probability: verdict.probability,
      source: 'semantic',
    });
  }

  // A chunk already covered by a confirmed span adds nothing: the span is the
  // stronger, maskable finding and the chunk would double-count it.
  const chunksWithValue = new Set(findings.map((f) => f.chunkIndex));
  for (const verdict of result.chunkVerdicts) {
    if (!verdict.isPii) continue;
    const index = Number.parseInt(verdict.id.slice(1), 10);
    if (!Number.isInteger(index) || chunksWithValue.has(index)) continue;
    findings.push({
      category: 'health_record',
      line: lineAt(text, chunks[index]?.start ?? 0),
      chunkIndex: index,
      localization: 'chunk',
      probability: verdict.probability,
      source: 'semantic',
    });
  }

  // Charge any undercount back to the shared ceiling before the next file.
  if (settings.budget && result.usage) {
    settings.budget.reconcile(estimated, result.usage.inputTokens);
  }

  const valueCount = findings.filter((f) => f.localization === 'value').length;
  const flaggedChunks = findings.filter((f) => f.localization === 'chunk').length;

  const report: SemanticPrivacyReport = {
    findings,
    valueCount,
    flaggedChunks,
    localization: flaggedChunks > 0 ? 'chunk' : valueCount > 0 ? 'value' : 'none',
    coverage: result.coverage,
    provider: result.provider,
    model: result.model,
    candidatesExamined: candidates.length,
    chunksExamined: selectedChunks.length,
    chunksSkipped: chunks.length - selectedChunks.length,
    scope,
    budgetExhausted,
    usage: result.usage,
    errors: result.errors,
    fromCache: false,
  };

  options.cache?.set(key, report);
  return report;
}

/**
 * Mask confirmed findings.
 *
 * Value findings are masked in place. Chunk findings replace the whole sentence,
 * because masking part of "上周刚做完手术" leaves "上周刚做完██" — still a
 * disclosure. Redacting the sentence is the only sound option, not a fallback.
 */
export function maskFindings(text: string, report: SemanticPrivacyReport, chunks = splitChunks(text)): string {
  const spans: Array<{ start: number; end: number }> = [];
  for (const finding of report.findings) {
    if (finding.span) {
      spans.push({ start: finding.span.start, end: finding.span.end });
      continue;
    }
    const chunk = chunks[finding.chunkIndex];
    if (chunk) spans.push({ start: chunk.start, end: chunk.end });
  }
  spans.sort((a, b) => b.start - a.start);

  let masked = text;
  for (const span of spans) {
    masked = masked.slice(0, span.start) + '[REDACTED]' + masked.slice(span.end);
  }
  return masked;
}
