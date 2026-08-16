import { AgentGuardCloudClient } from '../cloud/client.js';
import { loadConfig, type AgentGuardConfig } from '../config.js';
import { writeAuditLog } from '../runtime/audit.js';
import {
  evaluateRuntimeAction,
  type RuntimeEvaluation,
} from '../runtime/decision.js';
import type { RuntimeAction, RuntimeActionType, RuntimeAuditEvent } from '../runtime/types.js';

export const DSH_RUNTIME_MODE = 'observe' as const;

export interface DshRuntimeConfig {
  /** Phase 2A supports observation only. `off` disables the lifecycle listener. */
  mode?: 'off' | 'observe';
}

export interface DshToolExecution {
  readonly callId: unknown;
  readonly rootCallId: unknown;
  readonly name: string;
  readonly arguments: unknown;
  readonly parent?: unknown;
  readonly agent?: {
    readonly id?: unknown;
  };
}

export interface DshPreToolDecision {
  kind: 'allow' | 'deny' | 'ask';
  reason?: string;
}

export type DshPreExecuteNext = () => Promise<DshPreToolDecision>;

export interface DshRuntimeDependencies {
  loadAgentGuardConfig?: () => AgentGuardConfig;
  evaluate?: typeof evaluateRuntimeAction;
  writeAudit?: typeof writeAuditLog;
  fetchPolicyFor?: (config: AgentGuardConfig) => (() => Promise<import('../runtime/types.js').EffectiveRuntimePolicy | null>) | undefined;
  onError?: (error: unknown, exec: DshToolExecution) => void;
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

export function buildDshRuntimeAction(exec: DshToolExecution): RuntimeAction {
  const actionType = mapDshToolToRuntimeAction(exec.name);
  const args = asRecord(exec.arguments);
  return {
    sessionId: stringValue(exec.agent?.id) || `dsh:${stringValue(exec.rootCallId) || stringValue(exec.callId)}`,
    agentHost: 'dsh',
    actionType,
    toolName: exec.name,
    input: actionInput(actionType, args, exec.arguments),
    metadata: {
      rawProtocol: 'dsh-native',
      callId: stringValue(exec.callId),
      rootCallId: stringValue(exec.rootCallId),
      nested: exec.parent !== undefined,
      sourceAttribution: 'unknown',
    },
  };
}

export async function observeDshToolCall(
  exec: DshToolExecution,
  dependencies: DshRuntimeDependencies = {}
): Promise<DshRuntimeObservation | null> {
  if (isAgentGuardDshTool(exec.name)) return null;

  const config = (dependencies.loadAgentGuardConfig ?? loadConfig)();
  const evaluate = dependencies.evaluate ?? evaluateRuntimeAction;
  const action = buildDshRuntimeAction(exec);
  const evaluation = await evaluate({
    action,
    policyCachePath: config.policyCachePath,
    fetchPolicy: dependencies.fetchPolicyFor
      ? dependencies.fetchPolicyFor(config)
      : defaultFetchPolicy(config),
  });
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
      runtimeMode: DSH_RUNTIME_MODE,
      enforcementApplied: false,
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

function defaultFetchPolicy(config: AgentGuardConfig): (() => Promise<import('../runtime/types.js').EffectiveRuntimePolicy | null>) | undefined {
  const client = new AgentGuardCloudClient(config);
  return client.connected ? () => client.fetchEffectivePolicy() : undefined;
}

function actionInput(actionType: RuntimeActionType, args: Record<string, unknown> | null, raw: unknown): string {
  if (args) {
    if (actionType === 'shell') return firstString(args.command, args.cmd, args.script, args.code) || stableJson(raw);
    if (actionType === 'file_read' || actionType === 'file_write') {
      return firstString(args.path, args.file_path, args.filePath, args.target) || stableJson(raw);
    }
    if (actionType === 'web_search') return firstString(args.query, args.q, args.search) || stableJson(raw);
    if (actionType === 'network' || actionType === 'browser') {
      return firstString(args.url, args.uri, args.href, args.target) || stableJson(raw);
    }
  }
  return stableJson(raw);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
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
