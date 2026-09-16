import { randomUUID } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { loadConfig, type AgentGuardConfig } from '../config.js';
import { writeAuditLog } from '../runtime/audit.js';
import { evaluateRuntimeAction, type RuntimeEvaluation } from '../runtime/decision.js';
import type {
  AgentLifecycleCapabilities,
  LlmRequestPurpose,
  RuntimeAction,
  RuntimeAuditEvent,
  RuntimeDecision,
} from '../runtime/types.js';

export interface DshGenerateOptions {
  readonly provider: string;
  readonly model: string;
  readonly messages: ReadonlyArray<unknown>;
  readonly system?: string;
  readonly tools?: ReadonlyArray<unknown>;
  readonly signal?: AbortSignal;
  readonly sessionId?: string;
  readonly purpose?: 'compaction' | 'session-title';
}

export interface DshStreamChunk {
  readonly type: string;
  readonly [key: string]: unknown;
}

export type DshLlmStreamNext = () => AsyncIterable<DshStreamChunk>;

export interface DshLlmPrivacyDependencies {
  runtimeMode?: 'observe' | 'protect';
  failureMode?: 'allow' | 'deny';
  loadAgentGuardConfig?: () => AgentGuardConfig;
  evaluate?: (action: RuntimeAction, config: AgentGuardConfig) => Promise<RuntimeEvaluation>;
  writeAudit?: (path: string, event: RuntimeAuditEvent) => void;
  createRequestId?: () => string;
  agents?: { get(id: string): unknown };
  approval?: { request(request: Record<string, unknown>): Promise<string> };
  responseBufferLimitBytes?: number;
  responseBufferLimitChunks?: number;
  onError?: (error: unknown, action: RuntimeAction) => void;
}

interface DshResponseObservation {
  readonly inspectionParts: string[];
  inspectionBytes: number;
  serializedBytes: number;
  chunkCount: number;
  complete: boolean;
  truncated: boolean;
}

interface DshResponseLimits {
  readonly bytes: number;
  readonly chunks: number;
}

const DEFAULT_RESPONSE_BUFFER_BYTES = 8 * 1024 * 1024;
const DEFAULT_RESPONSE_BUFFER_CHUNKS = 8_192;

export const DSH_LLM_CAPABILITIES: AgentLifecycleCapabilities = {
  userPrompt: 'none',
  promptExpansion: 'none',
  modelRequest: 'blocking',
  modelResponse: 'blocking',
  preTool: 'blocking',
  postTool: 'blocking',
  toolOutputRewrite: true,
  postToolBatch: 'none',
  configChange: 'none',
  modelSwitch: 'none',
  assistantDisplay: 'none',
  finalDestination: false,
  credentialFacts: false,
  exactPayloadBytes: false,
  retryAndFallback: false,
  auxiliaryModelCalls: false,
};

export const DSH_LLM_CAPABILITY_GAPS = {
  finalDestination: 'unsupported',
  credentialFacts: 'unsupported',
  exactPayloadBytes: 'unsupported',
  retryAndFallback: 'unsupported',
  directSdkCalls: 'unsupported',
  auxiliaryModelCalls: 'partial-via-unified-service',
} as const;

const DSH_MISSING_TRANSPORT_FACTS = [
  'final_destination',
  'credential_kind',
  'credential_presence',
  'exact_payload_bytes',
  'retry_and_fallback',
  'auxiliary_model_calls',
] as const;

export function buildDshLlmRequestAction(
  options: DshGenerateOptions,
  requestId: string,
): RuntimeAction {
  const sessionId = options.sessionId || `dsh:unscoped:${requestId}`;
  const projected = projectGenerateOptions(options);
  return {
    sessionId,
    agentHost: 'dsh',
    actionType: 'llm_request',
    toolName: 'llm/stream',
    input: JSON.stringify(projected.payload),
    lifecycleStage: 'model_request',
    canBlockCurrentAction: true,
    coverageLevel: 'partial',
    missingFacts: [...DSH_MISSING_TRANSPORT_FACTS],
    llm: {
      schemaVersion: 1,
      requestId,
      sessionId,
      purpose: dshPurpose(options.purpose),
      lifecycleStage: 'model_request',
      canBlockCurrentAction: true,
      provider: options.provider,
      model: options.model,
      credentialKind: 'unknown',
      credentialPresent: 'unknown',
      attachmentBytes: projected.attachmentBytes,
      messageCount: options.messages.length,
      filePathCount: projected.fileCount,
    },
    metadata: {
      rawProtocol: 'dsh-llm-stream',
      semanticPayloadVisible: true,
      transportFactsVisible: false,
      unifiedLlmService: true,
      attempt: 'unknown',
      endpoint: 'unknown',
      directSdkCalls: DSH_LLM_CAPABILITY_GAPS.directSdkCalls,
      auxiliaryModelCalls: DSH_LLM_CAPABILITY_GAPS.auxiliaryModelCalls,
      imageCount: projected.imageCount,
    },
  };
}

/** Installable shape for DSH's `llm/stream` waterfall. */
export function createDshLlmPrivacyListener(dependencies: DshLlmPrivacyDependencies = {}): (
  options: DshGenerateOptions,
  next: DshLlmStreamNext,
) => AsyncIterable<DshStreamChunk> {
  return (options, next) => protectDshLlmStream(options, next, dependencies);
}

async function* protectDshLlmStream(
  options: DshGenerateOptions,
  next: DshLlmStreamNext,
  dependencies: DshLlmPrivacyDependencies,
): AsyncIterable<DshStreamChunk> {
  const requestId = (dependencies.createRequestId ?? randomUUID)();
  const requestAction = buildDshLlmRequestAction(options, requestId);
  let requestEvaluation: RuntimeEvaluation;
  try {
    requestEvaluation = await evaluateAndAudit(requestAction, dependencies);
  } catch (error) {
    dependencies.onError?.(error, requestAction);
    if (
      (dependencies.runtimeMode ?? 'observe') === 'observe'
      || (dependencies.failureMode ?? 'deny') === 'allow'
    ) {
      yield* next();
      return;
    }
    yield gateError('AGENTGUARD_GATE_ERROR', 'AgentGuard could not evaluate this model request.');
    return;
  }

  if ((dependencies.runtimeMode ?? 'observe') === 'protect') {
    const requestGate = await enforceDecision(
      requestEvaluation.decision,
      requestAction,
      options,
      dependencies,
      'request',
    );
    if (requestGate) {
      yield requestGate;
      return;
    }
  }

  const limits = responseLimits(dependencies);
  const observation = createResponseObservation();
  if ((dependencies.runtimeMode ?? 'observe') === 'observe') {
    try {
      for await (const chunk of next()) {
        observeResponseChunk(observation, chunk, limits);
        yield chunk;
      }
    } finally {
      const responseAction = buildDshLlmResponseAction(options, requestAction, observation);
      try {
        await evaluateAndAudit(responseAction, dependencies);
      } catch (error) {
        dependencies.onError?.(error, responseAction);
      }
    }
    return;
  }

  const chunks: DshStreamChunk[] = [];
  for await (const chunk of next()) {
    if (!observeResponseChunk(observation, chunk, limits)) {
      auditResponseLimit(
        buildDshLlmResponseAction(options, requestAction, observation),
        dependencies,
      );
      yield gateError(
        'AGENTGUARD_RESPONSE_LIMIT',
        'AgentGuard blocked a model response that exceeded its inspection limit.',
      );
      return;
    }
    chunks.push(chunk);
  }

  const responseAction = buildDshLlmResponseAction(options, requestAction, observation);
  let responseEvaluation: RuntimeEvaluation;
  try {
    responseEvaluation = await evaluateAndAudit(responseAction, dependencies);
  } catch (error) {
    dependencies.onError?.(error, responseAction);
    if ((dependencies.failureMode ?? 'deny') === 'allow') {
      yield* chunks;
      return;
    }
    yield gateError('AGENTGUARD_GATE_ERROR', 'AgentGuard could not evaluate this model response.');
    return;
  }

  if ((dependencies.runtimeMode ?? 'observe') === 'protect') {
    const responseGate = await enforceDecision(
      responseEvaluation.decision,
      responseAction,
      options,
      dependencies,
      'response',
    );
    if (responseGate) {
      yield responseGate;
      return;
    }
  }
  yield* chunks;
}

function auditResponseLimit(
  action: RuntimeAction,
  dependencies: DshLlmPrivacyDependencies,
): void {
  const event: RuntimeAuditEvent = {
    ...action,
    actionId: `act_dsh_response_limit_${action.llm?.requestId ?? 'unknown'}`,
    decision: 'block',
    policyDecision: 'block',
    riskScore: 100,
    riskLevel: 'critical',
    reasons: [{
      code: 'RESPONSE_INSPECTION_LIMIT',
      severity: 'critical',
      title: 'Model response exceeded inspection limit',
      description: 'AgentGuard failed closed before releasing an oversized DSH model response.',
    }],
    policyVersion: 'dsh-response-buffer-v1',
    enforcementStatus: 'enforced',
    metadata: {
      ...action.metadata,
      evaluation: 'adapter-guard',
      policySource: 'default',
      runtimeMode: 'protect',
      enforcementApplied: true,
    },
  };
  try {
    const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
    (dependencies.writeAudit ?? writeAuditLog)(config.auditPath, event);
  } catch (error) {
    dependencies.onError?.(error, action);
  }
}

async function evaluateAndAudit(
  action: RuntimeAction,
  dependencies: DshLlmPrivacyDependencies,
): Promise<RuntimeEvaluation> {
  const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
  const evaluation = dependencies.evaluate
    ? await dependencies.evaluate(action, config)
    : await evaluateRuntimeAction({ action, policyCachePath: config.policyCachePath });
  const runtimeMode = dependencies.runtimeMode ?? 'observe';
  const enforcementStatus = runtimeMode === 'protect'
    ? 'enforced'
    : evaluation.decision.decision === 'block' || evaluation.decision.decision === 'require_approval'
      ? 'would_block'
      : 'observed';
  const event: RuntimeAuditEvent = {
    ...action,
    actionId: evaluation.decision.actionId,
    decision: evaluation.decision.decision,
    policyDecision: evaluation.decision.policyDecision ?? evaluation.decision.decision,
    riskScore: evaluation.decision.riskScore,
    riskLevel: evaluation.decision.riskLevel,
    reasons: evaluation.decision.reasons,
    policyVersion: evaluation.decision.policyVersion,
    coverageLevel: evaluation.decision.coverageLevel ?? action.coverageLevel,
    enforcementStatus,
    missingFacts: unique([
      ...(action.missingFacts ?? []),
      ...(evaluation.decision.missingFacts ?? []),
    ]),
    metadata: {
      ...action.metadata,
      evaluation: 'local-oss',
      policySource: evaluation.policySource,
      runtimeMode,
      enforcementApplied: runtimeMode === 'protect',
    },
  };
  try {
    (dependencies.writeAudit ?? writeAuditLog)(config.auditPath, event);
  } catch {
    // Audit persistence cannot reveal or change the DSH model-call result.
  }
  return evaluation;
}

async function enforceDecision(
  decision: RuntimeDecision,
  action: RuntimeAction,
  options: DshGenerateOptions,
  dependencies: DshLlmPrivacyDependencies,
  phase: 'request' | 'response',
): Promise<DshStreamChunk | null> {
  if (decision.decision === 'allow' || decision.decision === 'warn') return null;
  if (decision.decision === 'block') {
    return gateError(
      phase === 'request' ? 'AGENTGUARD_BLOCKED' : 'AGENTGUARD_RESPONSE_BLOCKED',
      `AgentGuard blocked this model ${phase}.`,
    );
  }

  const agent = options.sessionId ? dependencies.agents?.get(options.sessionId) : undefined;
  if (!agent || !dependencies.approval) {
    return gateError(
      'AGENTGUARD_APPROVAL_UNAVAILABLE',
      `AgentGuard approval is unavailable for this model ${phase}.`,
    );
  }
  let outcome: string;
  try {
    outcome = await dependencies.approval.request({
      agent,
      toolName: 'llm/stream',
      reason: approvalReason(decision, phase),
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (error) {
    dependencies.onError?.(error, action);
    return gateError(
      'AGENTGUARD_APPROVAL_UNAVAILABLE',
      `AgentGuard approval is unavailable for this model ${phase}.`,
    );
  }
  return outcome === 'allowed-once'
    ? null
    : gateError(
      'AGENTGUARD_APPROVAL_DENIED',
      `AgentGuard approval was not granted for this model ${phase}.`,
    );
}

function approvalReason(decision: RuntimeDecision, phase: 'request' | 'response'): string {
  const codes = [...new Set(decision.reasons.map(reason => safeToken(reason.code)).filter(Boolean))].slice(0, 5);
  const suffix = codes.length > 0 ? ` Reasons: ${codes.join(', ')}.` : '';
  return `AgentGuard requires approval for this model ${phase}.${suffix}`;
}

function safeToken(value: unknown): string {
  return typeof value === 'string' ? value.replace(/[^A-Za-z0-9._:-]+/g, '_').slice(0, 64) : '';
}

function gateError(code: string, message: string): DshStreamChunk {
  return { type: 'finish', reason: { kind: 'error', failure: { code, message } } };
}

function buildDshLlmResponseAction(
  options: DshGenerateOptions,
  request: RuntimeAction,
  observation: DshResponseObservation,
): RuntimeAction {
  const fullyInspected = observation.complete && !observation.truncated;
  const missingFacts = fullyInspected
    ? ['response_source'] as const
    : ['complete_response', 'response_source'] as const;
  return {
    sessionId: request.sessionId,
    agentHost: 'dsh',
    actionType: 'llm_response',
    toolName: 'llm/stream',
    input: observation.inspectionParts.join('\n'),
    lifecycleStage: 'model_response',
    canBlockCurrentAction: true,
    coverageLevel: fullyInspected ? 'partial' : 'unsupported',
    missingFacts: [...missingFacts],
    llm: {
      schemaVersion: 1,
      requestId: request.llm!.requestId,
      sessionId: request.sessionId,
      purpose: request.llm!.purpose,
      lifecycleStage: 'model_response',
      canBlockCurrentAction: true,
      provider: options.provider,
      model: options.model,
      credentialKind: 'unknown',
      credentialPresent: 'unknown',
    },
    metadata: {
      rawProtocol: 'dsh-llm-stream',
      responseChunkCount: observation.chunkCount,
      responseInspectionBytes: observation.inspectionBytes,
      responseInspectionTruncated: observation.truncated,
      responseSourceVisible: false,
      unifiedLlmService: true,
    },
  };
}

function createResponseObservation(): DshResponseObservation {
  return {
    inspectionParts: [],
    inspectionBytes: 0,
    serializedBytes: 0,
    chunkCount: 0,
    complete: false,
    truncated: false,
  };
}

function responseLimits(dependencies: DshLlmPrivacyDependencies): DshResponseLimits {
  return {
    bytes: positiveInteger(dependencies.responseBufferLimitBytes) ?? DEFAULT_RESPONSE_BUFFER_BYTES,
    chunks: positiveInteger(dependencies.responseBufferLimitChunks) ?? DEFAULT_RESPONSE_BUFFER_CHUNKS,
  };
}

function observeResponseChunk(
  observation: DshResponseObservation,
  chunk: DshStreamChunk,
  limits: DshResponseLimits,
): boolean {
  observation.chunkCount += 1;
  if (chunk.type === 'finish') {
    const reason = asRecord(chunk.reason);
    observation.complete = reason?.kind !== 'error' && reason?.kind !== 'aborted';
  }
  if (observation.truncated) return false;

  let serialized: string;
  try {
    serialized = JSON.stringify(chunk);
  } catch {
    observation.truncated = true;
    return false;
  }
  const chunkBytes = Buffer.byteLength(serialized, 'utf8');
  observation.serializedBytes += chunkBytes;
  if (observation.chunkCount > limits.chunks || observation.serializedBytes > limits.bytes) {
    observation.truncated = true;
    return false;
  }

  const inspection = responseChunkInspectionText(chunk);
  if (inspection) {
    const inspectionBytes = Buffer.byteLength(inspection, 'utf8');
    if (observation.inspectionBytes + inspectionBytes > limits.bytes) {
      observation.truncated = true;
      return false;
    }
    observation.inspectionParts.push(inspection);
    observation.inspectionBytes += inspectionBytes;
  }
  return true;
}

function responseChunkInspectionText(chunk: DshStreamChunk): string {
  if (chunk.type === 'text-delta' || chunk.type === 'reasoning-delta') {
    return typeof chunk.text === 'string' ? chunk.text : '';
  }
  if (chunk.type === 'tool-call-delta') {
    const name = typeof chunk.name === 'string' ? chunk.name : 'unknown';
    const args = typeof chunk.argumentsDelta === 'string' ? chunk.argumentsDelta : '';
    return `{"tool_call":"${safeToken(name)}","arguments":${args}}`;
  }
  if (chunk.type === 'block-end') {
    const block = asRecord(chunk.block);
    if (block?.type === 'tool-call') {
      const name = typeof block.name === 'string' ? block.name : 'unknown';
      const args = typeof block.arguments === 'string' ? block.arguments : '';
      return `{"tool_call":"${safeToken(name)}","arguments":${args}}`;
    }
    if ((block?.type === 'text' || block?.type === 'reasoning') && typeof block.text === 'string') {
      return block.text;
    }
  }
  return '';
}

function dshPurpose(purpose: DshGenerateOptions['purpose']): LlmRequestPurpose {
  if (purpose === 'compaction') return 'compaction';
  if (purpose === 'session-title') return 'title';
  return 'unknown';
}

function projectGenerateOptions(options: DshGenerateOptions): {
  payload: Record<string, unknown>;
  attachmentBytes: number;
  fileCount: number;
  imageCount: number;
} {
  let attachmentBytes = 0;
  let fileCount = 0;
  let imageCount = 0;
  const messages = options.messages.map((message) => {
    const record = asRecord(message);
    const content = Array.isArray(record?.content) ? record.content.map(projectBlock) : [];
    return {
      role: typeof record?.role === 'string' ? record.role : 'unknown',
      content,
    };
  });

  function projectBlock(value: unknown): Record<string, unknown> {
    const block = asRecord(value);
    const type = typeof block?.type === 'string' ? block.type : 'unknown';
    if (type === 'text' || type === 'reasoning') {
      return { type, text: typeof block?.text === 'string' ? block.text : '' };
    }
    if (type === 'tool-call') {
      return {
        type,
        name: typeof block?.name === 'string' ? block.name : '',
        arguments: typeof block?.arguments === 'string' ? block.arguments : '',
      };
    }
    if (type === 'tool-result') {
      return {
        type,
        isError: block?.isError === true,
        content: Array.isArray(block?.content) ? block.content.map(projectBlock) : [],
      };
    }
    if (type === 'image' || type === 'file') {
      const attachment = asRecord(block?.attachment);
      const bytes = nonNegativeInteger(attachment?.bytes) ?? 0;
      attachmentBytes += bytes;
      if (type === 'image') imageCount += 1;
      else fileCount += 1;
      const mediaType = typeof attachment?.mediaType === 'string'
        ? attachment.mediaType
        : typeof attachment?.mimeType === 'string'
          ? attachment.mimeType
          : undefined;
      return {
        type,
        attachment: {
          name: typeof attachment?.name === 'string' ? attachment.name : '',
          bytes,
          ...(mediaType ? { mediaType } : {}),
        },
      };
    }
    return { type };
  }

  const tools = options.tools?.map((tool) => {
    const record = asRecord(tool);
    return {
      name: typeof record?.name === 'string' ? record.name : '',
      description: typeof record?.description === 'string' ? record.description : '',
      parameters: asRecord(record?.parameters) ?? {},
    };
  });
  return {
    payload: {
      provider: options.provider,
      model: options.model,
      ...(options.system === undefined ? {} : { system: options.system }),
      messages,
      ...(tools === undefined ? {} : { tools }),
    },
    attachmentBytes,
    fileCount,
    imageCount,
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function nonNegativeInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function positiveInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
