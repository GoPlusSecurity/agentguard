import { AgentGuardCloudClient } from '../cloud/client.js';
import { loadConfig, type AgentGuardConfig } from '../config.js';
import { isAbsolute, resolve } from 'node:path';
import { writeAuditLog } from '../runtime/audit.js';
import {
  evaluateRuntimeAction,
  type RuntimeEvaluation,
} from '../runtime/decision.js';
import type { RuntimeAction, RuntimeActionType, RuntimeAuditEvent, RuntimeDecision } from '../runtime/types.js';
import { planDshEnforcement, type DshRuntimePhase } from './enforcement-plan.js';
import {
  mergeDshPostDecisions,
  mergeDshPreDecisions,
  translateDshPostDecision,
  translateDshPreDecision,
} from './enforcement-adapter.js';
import {
  applyDshOwnerPolicy,
  type DshOwnerPolicies,
} from './owner-policy.js';

export const DSH_RUNTIME_MODE = 'observe' as const;
export const DSH_PROTECT_MODE = 'protect' as const;
export type DshRuntimeMode = 'off' | typeof DSH_RUNTIME_MODE | typeof DSH_PROTECT_MODE;
export type DshRuntimeFailureMode = 'allow' | 'deny';
export type DshPostResponseMode = 'audit' | 'block-malicious';
export type DshUnknownToolDecision = 'ask' | 'deny' | 'allow';

export interface DshRuntimeConfig {
  /** `protect` enforces pre-execute policy and enables explicit post containment. */
  mode?: DshRuntimeMode;
  /** Unexpected evaluator failures fail closed by default in protect mode. */
  failureMode?: DshRuntimeFailureMode;
  /** Operator-authored exact tool-name to plugin/package owner bindings. */
  attribution?: DshRuntimeAttributionConfig;
  /** Per-owner monotonic decision floors; cannot weaken shared policy. */
  ownerPolicies?: DshOwnerPolicies;
  /** `block-malicious` suppresses post-execute results only when policy returns block. */
  postResponseMode?: DshPostResponseMode;
  /** Decision for tools that cannot be classified into a known runtime action in protect mode. */
  unknownToolDecision?: DshUnknownToolDecision;
}

export interface DshRuntimeAttributionConfig {
  readonly toolOwners?: Readonly<Record<string, string>>;
}

export interface DshToolExecution {
  readonly callId: unknown;
  readonly rootCallId: unknown;
  readonly name: string;
  readonly arguments: unknown;
  readonly parent?: unknown;
  readonly agent?: {
    readonly id?: unknown;
    readonly session?: {
      readonly header?: {
        readonly cwd?: unknown;
        readonly origin?: unknown;
        readonly delegationDepth?: unknown;
        readonly agentPreset?: unknown;
      };
    };
  };
}

export interface DshPreToolDecision {
  kind: 'allow' | 'deny' | 'ask';
  reason?: string;
}

export type DshPreExecuteNext = () => Promise<DshPreToolDecision>;

export interface DshToolExecutionResult {
  readonly isError: boolean;
  readonly value?: unknown;
  readonly content?: ReadonlyArray<{
    readonly type?: unknown;
    readonly text?: unknown;
  }>;
  readonly error?: {
    readonly message?: unknown;
  };
  readonly meta?: unknown;
}

export interface DshContentBlock {
  readonly type: string;
  readonly [key: string]: unknown;
}

export type DshPostToolDecision = {
  kind: 'accept';
  content?: ReadonlyArray<DshContentBlock>;
} | {
  kind: 'block';
  feedback: ReadonlyArray<DshContentBlock>;
};

export type DshPostExecuteNext = () => Promise<DshPostToolDecision>;

export interface DshRuntimeDependencies {
  loadAgentGuardConfig?: () => AgentGuardConfig;
  evaluate?: typeof evaluateRuntimeAction;
  writeAudit?: typeof writeAuditLog;
  fetchPolicyFor?: (config: AgentGuardConfig) => (() => Promise<import('../runtime/types.js').EffectiveRuntimePolicy | null>) | undefined;
  onError?: (error: unknown, exec: DshToolExecution) => void;
  runtimeMode?: Exclude<DshRuntimeMode, 'off'>;
  attribution?: DshRuntimeAttributionConfig;
  ownerPolicies?: DshOwnerPolicies;
  unknownToolDecision?: DshUnknownToolDecision;
}

export interface DshRuntimeObservation {
  action: RuntimeAction;
  evaluation: RuntimeEvaluation;
  event: RuntimeAuditEvent;
}

const SHELL_TOOLS = new Set([
  'bash', 'terminal', 'shell', 'exec', 'exec_command', 'execute_command', 'execute_code',
  'run_command', 'run_shell_command', 'spawn_process',
]);
const READ_TOOLS = new Set([
  'read', 'read_file', 'file_read', 'read_image', 'view_image', 'open_file',
  'list_directory', 'list_files', 'glob', 'grep', 'search_files',
]);
const WRITE_TOOLS = new Set([
  'write', 'write_file', 'file_write', 'edit', 'patch', 'apply_patch', 'str_replace_editor',
  'create_file', 'delete_file', 'move_file', 'rename_file', 'copy_file',
]);
const WEB_SEARCH_TOOLS = new Set(['web_search', 'search_query', 'image_query']);
const NETWORK_TOOLS = new Set([
  'web_fetch', 'fetch', 'browser', 'browser_navigate', 'open_url', 'visit_url',
  'http_request', 'download', 'navigate',
]);
const DSH_OWNER_ID_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9@._/:-]{0,159}$/;
const MAX_DSH_TOOL_OWNER_BINDINGS = 500;

/** Validate and snapshot operator-authored DSH tool ownership bindings. */
export function normalizeDshRuntimeAttribution(value: unknown): DshRuntimeAttributionConfig {
  if (value === undefined) return {};
  const attribution = asRecord(value);
  if (!attribution) throw new Error('AgentGuard DSH runtime attribution must be an object');
  const rawOwners = attribution.toolOwners;
  if (rawOwners === undefined) return {};
  const owners = asRecord(rawOwners);
  if (!owners) throw new Error('AgentGuard DSH runtime attribution.toolOwners must be an object');
  const entries = Object.entries(owners);
  if (entries.length > MAX_DSH_TOOL_OWNER_BINDINGS) {
    throw new Error(`AgentGuard DSH runtime attribution.toolOwners supports at most ${MAX_DSH_TOOL_OWNER_BINDINGS} bindings`);
  }
  const toolOwners: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [toolName, ownerValue] of entries) {
    if (!toolName || toolName !== toolName.trim() || toolName.length > 160) {
      throw new Error('AgentGuard DSH runtime attribution tool names must be non-empty exact names of at most 160 characters');
    }
    if (typeof ownerValue !== 'string' || !DSH_OWNER_ID_PATTERN.test(ownerValue)) {
      throw new Error(`invalid AgentGuard DSH owner id for tool ${JSON.stringify(toolName)}`);
    }
    toolOwners[toolName] = ownerValue;
  }
  return { toolOwners };
}

/** AgentGuard tools are excluded so the scanner cannot recursively police itself. */
export function isAgentGuardDshTool(name: string): boolean {
  return name.startsWith('agentguard_');
}

export function mapDshToolToRuntimeAction(name: string): RuntimeActionType {
  const normalized = name.trim().toLowerCase();
  if (SHELL_TOOLS.has(normalized)) return 'shell';
  if (READ_TOOLS.has(normalized)) return 'file_read';
  if (WRITE_TOOLS.has(normalized)) return 'file_write';
  if (WEB_SEARCH_TOOLS.has(normalized)) return 'web_search';
  if (NETWORK_TOOLS.has(normalized) || normalized.startsWith('browser_')) return 'network';
  if (normalized.includes('deploy') || normalized.includes('publish')) return 'deploy';
  if (normalized.includes('skill') && normalized.includes('install')) return 'skill_install';
  if (normalized.startsWith('mcp_') || normalized.startsWith('mcp.')) return 'mcp_tool';
  return 'other';
}

export function buildDshRuntimeAction(
  exec: DshToolExecution,
  attribution: DshRuntimeAttributionConfig = {}
): RuntimeAction {
  const actionType = mapDshToolToRuntimeAction(exec.name);
  const args = asRecord(exec.arguments);
  const sessionHeader = exec.agent?.session?.header;
  const sessionCwd = firstString(sessionHeader?.cwd);
  const explicitCwd = args ? firstString(args.workdir, args.cwd, args.working_directory) : '';
  const effectiveCwd = resolveDshCwd(explicitCwd, sessionCwd);
  const sourceOwner = configuredToolOwner(exec.name, attribution);
  const agentPreset = firstString(sessionHeader?.agentPreset);
  const delegationDepth = nonNegativeInteger(sessionHeader?.delegationDepth);
  const sessionOrigin = sessionHeader?.origin === 'subagent' ? 'subagent' : 'top-level';
  return {
    sessionId: stringValue(exec.agent?.id) || `dsh:${stringValue(exec.rootCallId) || stringValue(exec.callId)}`,
    agentHost: 'dsh',
    actionType,
    toolName: exec.name,
    input: actionInput(actionType, args, exec.arguments),
    ...(effectiveCwd ? { cwd: effectiveCwd } : {}),
    metadata: {
      rawProtocol: 'dsh-native',
      callId: stringValue(exec.callId),
      rootCallId: stringValue(exec.rootCallId),
      nested: exec.parent !== undefined,
      invocationSource: exec.parent === undefined ? 'model-direct' : 'nested-tool',
      sessionOrigin,
      ...(delegationDepth !== undefined ? { delegationDepth } : {}),
      ...(agentPreset ? { agentPreset } : {}),
      sourceAttribution: sourceOwner ? 'configured-tool-owner' : 'unknown',
      ...(sourceOwner ? { sourceOwner } : {}),
      ...actionMetadata(actionType, args),
    },
  };
}

export async function observeDshToolCall(
  exec: DshToolExecution,
  dependencies: DshRuntimeDependencies = {}
): Promise<DshRuntimeObservation | null> {
  if (isAgentGuardDshTool(exec.name)) return null;

  const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
  const action = buildDshRuntimeAction(exec, dependencies.attribution);
  action.metadata = { ...action.metadata, runtimePhase: 'pre' };
  return evaluateAndAuditDshAction(
    action,
    config,
    dependencies,
    dependencies.runtimeMode ?? DSH_RUNTIME_MODE,
    false
  );
}

export async function protectDshToolCall(
  exec: DshToolExecution,
  dependencies: DshRuntimeDependencies = {}
): Promise<DshRuntimeObservation | null> {
  if (isAgentGuardDshTool(exec.name)) return null;

  const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
  const action = buildDshRuntimeAction(exec, dependencies.attribution);
  action.metadata = { ...action.metadata, runtimePhase: 'pre' };
  return evaluateAndAuditDshAction(action, config, dependencies, DSH_PROTECT_MODE, true);
}

export async function observeDshToolResult(
  exec: DshToolExecution,
  result: DshToolExecutionResult,
  dependencies: DshRuntimeDependencies = {}
): Promise<DshRuntimeObservation | null> {
  if (isAgentGuardDshTool(exec.name)) return null;
  const action = buildDshRuntimeAction(exec, dependencies.attribution);
  if (action.actionType !== 'network' && action.actionType !== 'browser') return null;
  action.metadata = {
    ...action.metadata,
    runtimePhase: 'post',
    hookPhase: 'post',
    responseIsError: result.isError,
    ...responseMetadata(result),
  };
  const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
  return evaluateAndAuditDshAction(
    action,
    config,
    dependencies,
    dependencies.runtimeMode ?? DSH_RUNTIME_MODE,
    false
  );
}

export async function protectDshToolResult(
  exec: DshToolExecution,
  result: DshToolExecutionResult,
  dependencies: DshRuntimeDependencies = {}
): Promise<DshRuntimeObservation | null> {
  if (isAgentGuardDshTool(exec.name)) return null;
  const action = buildDshRuntimeAction(exec, dependencies.attribution);
  if (action.actionType !== 'network' && action.actionType !== 'browser') return null;
  action.metadata = {
    ...action.metadata,
    runtimePhase: 'post',
    hookPhase: 'post',
    responseIsError: result.isError,
    ...responseMetadata(result),
  };
  const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
  return evaluateAndAuditDshAction(action, config, dependencies, DSH_PROTECT_MODE, 'block-only');
}

async function evaluateAndAuditDshAction(
  action: RuntimeAction,
  config: AgentGuardConfig,
  dependencies: DshRuntimeDependencies,
  runtimeMode: Exclude<DshRuntimeMode, 'off'>,
  enforcementApplied: boolean | 'block-only'
): Promise<DshRuntimeObservation> {
  const evaluate = dependencies.evaluate ?? evaluateRuntimeAction;
  const sharedEvaluation = await evaluate({
    action,
    policyCachePath: config.policyCachePath,
    fetchPolicy: dependencies.fetchPolicyFor
      ? dependencies.fetchPolicyFor(config)
      : defaultFetchPolicy(config),
  });
  const guardedEvaluation = applyUnknownToolDecision(
    sharedEvaluation,
    action,
    runtimeMode,
    dependencies.unknownToolDecision ?? 'ask',
  );
  const evaluation = applyDshOwnerPolicy(guardedEvaluation, action, dependencies.ownerPolicies);
  const phase: DshRuntimePhase = action.metadata?.runtimePhase === 'post' ? 'post' : 'pre';
  const shadowPlan = planDshEnforcement(evaluation.decision.decision, phase);
  const decisionApplied = enforcementApplied === 'block-only'
    ? phase === 'post' && evaluation.decision.decision === 'block'
    : enforcementApplied;
  const remainingGates = decisionApplied ? [] : shadowPlan.enforcementGates;
  const event: RuntimeAuditEvent = {
    ...action,
    actionId: evaluation.decision.actionId,
    decision: evaluation.decision.decision,
    riskScore: evaluation.decision.riskScore,
    riskLevel: evaluation.decision.riskLevel,
    reasons: evaluation.decision.reasons,
    policyVersion: evaluation.decision.policyVersion,
    metadata: {
      ...action.metadata,
      evaluation: 'local-oss',
      policySource: evaluation.policySource,
      runtimeMode,
      enforcementApplied: decisionApplied,
      ...(decisionApplied ? { hookDecisionApplied: shadowPlan.hookDecision } : {}),
      shadowHookDecision: shadowPlan.hookDecision,
      shadowDisposition: shadowPlan.disposition,
      enforcementGates: remainingGates,
    },
  };

  try {
    (dependencies.writeAudit ?? writeAuditLog)(config.auditPath, event);
  } catch {
    // Phase 2A is fail-open: audit I/O cannot change DSH tool behavior.
  }
  return { action, evaluation, event };
}

export function createDshPreExecuteObserver(
  dependencies: DshRuntimeDependencies = {}
): (exec: DshToolExecution, next: DshPreExecuteNext) => Promise<DshPreToolDecision> {
  return async (exec, next) => {
    try {
      await observeDshToolCall(exec, dependencies);
    } catch (error) {
      dependencies.onError?.(error, exec);
    }
    // Phase 2A never translates the evaluated decision into enforcement.
    return next();
  };
}

export function createDshPreExecuteProtector(
  dependencies: DshRuntimeDependencies = {},
  failureMode: DshRuntimeFailureMode = 'deny'
): (exec: DshToolExecution, next: DshPreExecuteNext) => Promise<DshPreToolDecision> {
  return async (exec, next) => {
    if (isAgentGuardDshTool(exec.name)) return next();

    let agentguardDecision: DshPreToolDecision;
    try {
      const protectedCall = await protectDshToolCall(exec, dependencies);
      if (!protectedCall) return next();
      agentguardDecision = translateDshPreDecision(protectedCall.evaluation.decision);
    } catch (error) {
      dependencies.onError?.(error, exec);
      if (failureMode === 'allow') return next();
      agentguardDecision = {
        kind: 'deny',
        reason: 'AgentGuard denied this tool call because runtime policy evaluation failed.',
      };
    }

    if (agentguardDecision.kind === 'deny') return agentguardDecision;
    const downstream = await next();
    return mergeDshPreDecisions(agentguardDecision, downstream);
  };
}

function applyUnknownToolDecision(
  evaluation: RuntimeEvaluation,
  action: RuntimeAction,
  runtimeMode: Exclude<DshRuntimeMode, 'off'>,
  configuredDecision: DshUnknownToolDecision,
): RuntimeEvaluation {
  if (runtimeMode !== DSH_PROTECT_MODE || action.actionType !== 'other' || configuredDecision === 'allow') {
    return evaluation;
  }

  const deny = configuredDecision === 'deny';
  const currentDecision = evaluation.decision.decision;
  const enforcedDecision = deny ? 'block' : 'require_approval';
  const finalDecision = currentDecision === 'block'
    || (!deny && currentDecision === 'require_approval')
    ? currentDecision
    : enforcedDecision;
  const unknownReason = {
    code: 'UNKNOWN_TOOL',
    severity: deny ? 'critical' : 'high',
    title: 'Unknown tool requires an explicit decision',
    description: deny
      ? 'The DSH tool could not be classified and protect policy denies unknown tools.'
      : 'The DSH tool could not be classified and protect policy requires approval for unknown tools.',
    evidence: action.toolName,
  } as const;
  const decision: RuntimeDecision = {
    ...evaluation.decision,
    decision: finalDecision,
    riskScore: deny ? Math.max(95, evaluation.decision.riskScore) : Math.max(20, evaluation.decision.riskScore),
    riskLevel: deny ? 'critical' : evaluation.decision.riskLevel === 'safe' ? 'medium' : evaluation.decision.riskLevel,
    reasons: [...evaluation.decision.reasons, unknownReason],
  };
  return { ...evaluation, decision };
}

export function createDshPostExecuteObserver(
  dependencies: DshRuntimeDependencies = {}
): (
  exec: DshToolExecution,
  result: DshToolExecutionResult,
  next: DshPostExecuteNext
) => Promise<DshPostToolDecision> {
  return async (exec, result, next) => {
    try {
      await observeDshToolResult(exec, result, dependencies);
    } catch (error) {
      dependencies.onError?.(error, exec);
    }
    // Response observations are audit-only and never replace or block the result.
    return next();
  };
}

export function createDshPostExecuteProtector(
  dependencies: DshRuntimeDependencies = {}
): (
  exec: DshToolExecution,
  result: DshToolExecutionResult,
  next: DshPostExecuteNext
) => Promise<DshPostToolDecision> {
  return async (exec, result, next) => {
    let observed: DshRuntimeObservation | null;
    try {
      observed = await protectDshToolResult(exec, result, dependencies);
    } catch (error) {
      dependencies.onError?.(error, exec);
      // Post-result evaluation has no resumable failure channel; preserve downstream behavior.
      return next();
    }
    const downstream = await next();
    if (!observed || observed.evaluation.decision.decision !== 'block') return downstream;
    return mergeDshPostDecisions(
      translateDshPostDecision(observed.evaluation.decision),
      downstream
    );
  };
}

function defaultFetchPolicy(config: AgentGuardConfig): (() => Promise<import('../runtime/types.js').EffectiveRuntimePolicy | null>) | undefined {
  const client = new AgentGuardCloudClient(config);
  return client.connected ? () => client.fetchEffectivePolicy() : undefined;
}

function actionInput(actionType: RuntimeActionType, args: Record<string, unknown> | null, raw: unknown): string {
  if (args) {
    if (actionType === 'shell') return firstString(args.command, args.cmd, args.script, args.code, args.input) || stableJson(raw);
    if (actionType === 'file_read' || actionType === 'file_write') {
      return firstString(args.path, args.file_path, args.filePath, args.file, args.filename, args.target, args.destination) || stableJson(raw);
    }
    if (actionType === 'web_search') return firstString(args.query, args.q, args.search, args.term) || stableJson(raw);
    if (actionType === 'network' || actionType === 'browser') {
      const request = firstRecord(args.request, args.options);
      return firstString(args.url, args.uri, args.href, args.target, request?.url, request?.uri) || stableJson(raw);
    }
  }
  return stableJson(raw);
}

function actionMetadata(
  actionType: RuntimeActionType,
  args: Record<string, unknown> | null
): Record<string, unknown> {
  if (!args || (actionType !== 'network' && actionType !== 'browser')) return {};
  const request = firstRecord(args.request, args.options);
  const method = firstString(args.method, request?.method).toUpperCase();
  const bodyPreview = firstString(
    args.body,
    args.body_preview,
    args.bodyPreview,
    args.data,
    request?.body,
    request?.body_preview,
    request?.bodyPreview,
    request?.data
  );
  const headers = firstRecord(args.headers, args.requestHeaders, request?.headers, request?.requestHeaders);
  return {
    ...(method ? { method } : {}),
    ...(bodyPreview ? { bodyPreview } : {}),
    ...(headers ? { headers } : {}),
  };
}

function responseMetadata(result: DshToolExecutionResult): Record<string, unknown> {
  const value = asRecord(result.value);
  const meta = asRecord(result.meta);
  const response = firstRecord(value?.response, value?.result, meta?.response);
  const headers = firstRecord(
    value?.responseHeaders,
    value?.headers,
    response?.headers,
    meta?.responseHeaders,
    meta?.headers
  );
  const body = firstString(
    value?.responseBodyPreview,
    value?.responseBody,
    value?.body,
    value?.text,
    value?.content,
    response?.body,
    response?.text,
    result.error?.message,
    textContent(result.content)
  );
  const contentType = firstString(
    value?.responseContentType,
    value?.contentType,
    value?.content_type,
    response?.contentType,
    response?.content_type,
    meta?.responseContentType,
    meta?.contentType,
    meta?.content_type,
    headerValue(headers, 'content-type')
  );
  return {
    ...definedMetadata('responseStatusCode', value?.responseStatusCode, value?.statusCode, value?.status, response?.statusCode, response?.status, meta?.statusCode, meta?.status),
    ...definedMetadata('responseBodyBytes', value?.responseBodyBytes, value?.bytes, value?.contentLength, response?.bodyBytes, response?.bytes, response?.contentLength, meta?.responseBodyBytes, meta?.contentLength),
    ...(headers ? { responseHeaders: headers } : {}),
    ...(contentType ? { responseContentType: contentType } : {}),
    ...(body ? { responseBodyPreview: body.slice(0, 8_192) } : {}),
  };
}

function textContent(content: DshToolExecutionResult['content']): string {
  if (!content) return '';
  return content
    .filter(block => block.type === 'text' && typeof block.text === 'string')
    .map(block => block.text as string)
    .join('\n');
}

function headerValue(headers: Record<string, unknown> | undefined, name: string): string {
  if (!headers) return '';
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  return typeof entry?.[1] === 'string' ? entry[1] : '';
}

function definedMetadata(key: string, ...values: unknown[]): Record<string, unknown> {
  for (const value of values) {
    if (value !== undefined && value !== null) return { [key]: value };
  }
  return {};
}

function resolveDshCwd(explicitCwd: string, sessionCwd: string): string {
  if (!explicitCwd) return sessionCwd;
  if (isAbsolute(explicitCwd) || !sessionCwd) return explicitCwd;
  return resolve(sessionCwd, explicitCwd);
}

function configuredToolOwner(name: string, attribution: DshRuntimeAttributionConfig): string {
  const owners = attribution.toolOwners;
  if (!owners || !Object.hasOwn(owners, name)) return '';
  const owner = owners[name];
  return typeof owner === 'string' && DSH_OWNER_ID_PATTERN.test(owner) ? owner : '';
}

function nonNegativeInteger(value: unknown): number | undefined {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : undefined;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function firstRecord(...values: unknown[]): Record<string, unknown> | undefined {
  for (const value of values) {
    const record = asRecord(value);
    if (record) return record;
  }
  return undefined;
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function stringValue(value: unknown): string {
  return value === undefined || value === null ? '' : String(value);
}

function stableJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '';
  } catch {
    return '[unserializable DSH tool arguments]';
  }
}
