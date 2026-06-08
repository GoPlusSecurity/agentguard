import { cwd } from 'node:process';
import { dirname, join } from 'node:path';
import { AgentGuardCloudClient } from '../cloud/client.js';
import type { AgentGuardConfig } from '../config.js';
import { consumeApprovedApproval, writePendingApproval, type ApprovalRecord } from './approvals.js';
import { flushEventSpool, spoolEvent, writeAuditLog } from './audit.js';
import { evaluateLocalAction } from './evaluator.js';
import { resolveRuntimePolicy } from './policy.js';
import { isAgentGuardCliCommand } from './self-command.js';
import type { RuntimeAction, RuntimeAgentHost, RuntimeAuditEvent, RuntimeActionType, RuntimeDecision } from './types.js';

export interface ProtectOptions {
  config: AgentGuardConfig;
  rawInput?: unknown;
  stdinText?: string;
  agentHost?: RuntimeAgentHost;
  actionType?: RuntimeActionType;
  toolName?: string;
  sessionId?: string;
  decisionMode?: 'local-first' | 'cloud';
  phase?: 'pre' | 'post';
  filesystemAllowlist?: string[];
}

export interface ProtectResult {
  decision: RuntimeDecision;
  event: RuntimeAuditEvent;
  approvalChannel?: 'agent' | null;
  pendingApproval?: ApprovalRecord;
  policySource: 'cloud' | 'cache' | 'default' | 'cloud-decision';
}

export async function protectAction(options: ProtectOptions): Promise<ProtectResult | null> {
  const action = buildRuntimeAction(options);
  if (!action.input) return null;
  if (isAgentGuardRuntimeAction(action)) return null;
  const approvalStorePath = resolveApprovalStorePath(options.config);

  const client = new AgentGuardCloudClient(options.config);
  if (client.connected) {
    await flushEventSpool(options.config.eventSpoolPath, (events) => client.ingestEvents(events)).catch(() => undefined);
  }

  let decision: RuntimeDecision;
  let policySource: ProtectResult['policySource'];
  const postToolCall = options.phase === 'post';
  if (options.decisionMode === 'cloud' && client.connected) {
    decision = normalizeRuntimeDecision(await client.evaluateAction(action));
    policySource = 'cloud-decision';
  } else {
    const { policy, source } = await resolveRuntimePolicy({
      cachePath: options.config.policyCachePath,
      fetchPolicy: client.connected ? () => client.fetchEffectivePolicy() : undefined,
    });
    decision = normalizeRuntimeDecision(await evaluateLocalAction(policy, action, {
      filesystemAllowlist: options.filesystemAllowlist,
    }));
    policySource = source;
  }
  const approvedGrant = !postToolCall && decision.decision === 'require_approval'
    ? consumeApprovedApproval(approvalStorePath, action)
    : null;
  if (approvedGrant) {
    decision = { ...decision, decision: 'allow' };
  }
  if (shouldSuppressRuntimeReport(decision)) return null;

  const event: RuntimeAuditEvent = {
    ...action,
    actionId: decision.actionId,
    decision: decision.decision,
    riskScore: decision.riskScore,
    riskLevel: decision.riskLevel,
    reasons: decision.reasons,
    policyVersion: decision.policyVersion,
    metadata: {
      ...(action.metadata || {}),
      evaluation: policySource === 'cloud-decision' ? 'cloud' : 'local-oss',
      policySource,
      ...(approvedGrant
        ? {
            approvedByLocalGrant: true,
            approvalActionId: approvedGrant.actionId,
            approvalOnce: approvedGrant.once,
            approvalExpiresAt: approvedGrant.expiresAt,
          }
        : {}),
    },
  };

  try {
    writeAuditLog(options.config.auditPath, event);
  } catch {
    // Audit I/O must not mask the policy decision, especially for agent hooks.
  }

  let approvalChannel: ProtectResult['approvalChannel'];
  if (client.connected && policySource !== 'cloud-decision') {
    await client.ingestEvents([event]).catch(() => spoolEvent(options.config.eventSpoolPath, event));
  }
  if (!postToolCall && decision.decision === 'require_approval') {
    approvalChannel = 'agent';
  }
  const pendingApproval = !postToolCall && decision.decision === 'require_approval' && !approvedGrant
    ? writePendingApproval(approvalStorePath, action, decision)
    : undefined;

  return { decision, event, approvalChannel, pendingApproval, policySource };
}

function isAgentGuardRuntimeAction(action: RuntimeAction): boolean {
  return action.actionType === 'shell' && isAgentGuardCliCommand(action.input);
}

function resolveApprovalStorePath(config: AgentGuardConfig): string {
  return config.approvalStorePath || join(dirname(config.auditPath), 'approvals.json');
}

function normalizeRuntimeDecision(decision: RuntimeDecision): RuntimeDecision {
  const rawDecision = (decision as unknown as { decision?: string }).decision;
  if (rawDecision === 'require_approve') {
    return { ...decision, decision: 'require_approval' };
  }
  return decision;
}

function shouldSuppressRuntimeReport(decision: RuntimeDecision): boolean {
  return decision.riskScore < 20 || decision.riskLevel === 'safe';
}

export function formatProtectResult(result: ProtectResult, json = false): string {
  if (!json) {
    const agentApproval = formatAgentApproval(result);
    if (agentApproval) return agentApproval;
  }

  if (json) {
    return JSON.stringify({
      decision: publicDecision(result.decision.decision),
      cloudDecision: result.decision.decision,
      actionId: result.decision.actionId,
      riskScore: result.decision.riskScore,
      riskLevel: result.decision.riskLevel,
      reasons: result.decision.reasons,
      approvalChannel: result.approvalChannel,
      approvalCommand: result.pendingApproval ? approvalCommand(result.pendingApproval) : undefined,
      approvalInstruction: result.pendingApproval ? approvalInstruction(result.pendingApproval) : undefined,
      approvalExpiresAt: result.pendingApproval?.expiresAt,
      policySource: result.policySource,
    }, null, 2);
  }

  const reasonCount = result.decision.reasons.length;
  if (result.decision.decision === 'block') {
    return `BLOCKED by AgentGuard (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}, reasons: ${reasonCount}).`;
  }
  if (result.decision.decision === 'require_approval') {
    return `CONFIRM required by AgentGuard (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}, reasons: ${reasonCount}).${approvalHint(result)}`;
  }
  if (result.decision.decision === 'warn') {
    return `WARN from AgentGuard (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}, reasons: ${reasonCount}).`;
  }
  return 'ALLOW by AgentGuard.';
}

export function exitCodeForDecision(decision: RuntimeDecision, result?: Pick<ProtectResult, 'approvalChannel'>): number {
  if (decision.decision === 'require_approval' && result?.approvalChannel === 'agent') return 0;
  return decision.decision === 'block' || decision.decision === 'require_approval' ? 2 : 0;
}

function publicDecision(decision: RuntimeDecision['decision']): 'allow' | 'warn' | 'confirm' | 'block' {
  return decision === 'require_approval' ? 'confirm' : decision;
}

function formatAgentApproval(result: ProtectResult): string | null {
  if (result.decision.decision !== 'require_approval' || result.approvalChannel !== 'agent') return null;

  const reason = formatApprovalReason(result);
  if (result.event.agentHost === 'claude-code') {
    return JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: reason,
      },
    });
  }

  if (result.event.agentHost === 'codex') {
    return JSON.stringify({
      decision: 'confirm',
      actionId: result.decision.actionId,
      riskScore: result.decision.riskScore,
      riskLevel: result.decision.riskLevel,
      reasons: result.decision.reasons,
      approvalChannel: 'agent',
      message: reason,
      approvalCommand: result.pendingApproval ? approvalCommand(result.pendingApproval) : undefined,
      approvalInstruction: result.pendingApproval ? approvalInstruction(result.pendingApproval) : undefined,
      approvalExpiresAt: result.pendingApproval?.expiresAt,
    }, null, 2);
  }

  return null;
}

function formatApprovalReason(result: ProtectResult): string {
  const reasonSummary = result.decision.reasons
    .map((reason) => reason.title)
    .filter(Boolean)
    .slice(0, 3)
    .join(', ');
  return (
    `GoPlus AgentGuard requires approval for this action` +
    ` (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}).` +
    (reasonSummary ? ` Reasons: ${reasonSummary}.` : '') +
    approvalHint(result)
  );
}

function approvalHint(result: ProtectResult): string {
  if (!result.pendingApproval) return '';
  return ` ${approvalInstruction(result.pendingApproval)}`;
}

function approvalInstruction(record: ApprovalRecord): string {
  return (
    `Approve once (only after explicit user approval): ${approvalCommand(record)}.` +
    ' Do not run this approval command yourself unless the user explicitly approves this exact action.'
  );
}

function approvalCommand(record: ApprovalRecord): string {
  return `agentguard approve --action-id ${record.actionId} --once`;
}

function buildRuntimeAction(options: ProtectOptions): RuntimeAction {
  const raw = parseRawInput(options.rawInput, options.stdinText);
  const envActionType = process.env.AGENTGUARD_ACTION_TYPE as RuntimeActionType | undefined;
  const envAgentHost = process.env.AGENTGUARD_AGENT_HOST as RuntimeAgentHost | undefined;
  const toolName = options.toolName || process.env.AGENTGUARD_TOOL_NAME || pickToolName(raw);
  const actionType = options.actionType || envActionType || mapToolToRuntimeAction(toolName, raw);
  const toolInput = pickToolInput(raw);

  return {
    sessionId: options.sessionId || process.env.AGENTGUARD_SESSION_ID || pickSessionId(raw),
    agentHost: options.agentHost || envAgentHost || 'claude-code',
    actionType,
    toolName,
    input: process.env.TOOL_INPUT || pickInput(raw, actionType, toolInput),
    cwd: pickCwd(raw),
    sourceSkill: pickSourceSkill(raw),
    metadata: {
      rawProtocol: raw ? 'stdin-json' : 'env',
      ...(options.phase === 'post' ? { hookPhase: 'post' } : {}),
      ...pickNetworkMetadata(raw, toolInput),
    },
  };
}

function parseRawInput(rawInput: unknown, stdinText?: string): Record<string, unknown> | null {
  if (rawInput && typeof rawInput === 'object') return rawInput as Record<string, unknown>;
  const text = stdinText?.trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text) as unknown;
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return { content: text };
  }
}

function pickToolName(raw: Record<string, unknown> | null): string {
  if (!raw) return 'Tool';
  return String(raw.tool_name || raw.toolName || raw.name || 'Tool');
}

function mapToolToRuntimeAction(toolName: string, raw: Record<string, unknown> | null): RuntimeActionType {
  const lower = toolName.toLowerCase();
  if (toolName === 'Bash' || lower.includes('shell') || lower.includes('exec')) return 'shell';
  if (toolName === 'Read' || lower.includes('read')) return 'file_read';
  if (['Write', 'Edit', 'MultiEdit'].includes(toolName) || lower.includes('write')) return 'file_write';
  if (lower.includes('websearch') || lower.includes('web_search') || lower.includes('search_query')) return 'web_search';
  if (lower.includes('web') || lower.includes('browser')) return 'network';
  if (raw?.actionType && typeof raw.actionType === 'string') return raw.actionType as RuntimeActionType;
  if (raw?.action_type && typeof raw.action_type === 'string') return raw.action_type as RuntimeActionType;
  return 'other';
}

function pickInput(
  raw: Record<string, unknown> | null,
  actionType: RuntimeActionType,
  toolInput = pickToolInput(raw)
): string {
  if (!raw) return '';
  if (typeof raw.input === 'string') return raw.input;
  if (typeof raw.content === 'string') return raw.content;
  if (actionType === 'shell') {
    const command = firstString(raw.command, raw.cmd);
    if (command) return command;
  }
  if (toolInput) {
    if (actionType === 'shell') {
      const command = firstString(toolInput.command, toolInput.cmd);
      if (command) return command;
    }
    const filePath = toolInput.file_path || toolInput.filePath || toolInput.path || toolInput.target;
    if ((actionType === 'file_read' || actionType === 'file_write') && typeof filePath === 'string') return filePath;
    if (actionType === 'web_search') {
      const query = firstString(toolInput.query, toolInput.q, toolInput.search, toolInput.url);
      if (query) return query;
    }
    const url = toolInput.url || toolInput.uri || toolInput.href;
    if (typeof url === 'string') return url;
    return JSON.stringify(toolInput);
  }
  return JSON.stringify(raw);
}

function pickToolInput(raw: Record<string, unknown> | null): Record<string, unknown> | undefined {
  return firstRecord(
    raw?.tool_input,
    raw?.toolInput,
    raw?.params,
    raw?.args,
    raw?.input
  );
}

function pickNetworkMetadata(
  raw: Record<string, unknown> | null,
  toolInput: Record<string, unknown> | undefined
): Record<string, unknown> {
  const response = firstRecord(
    raw?.tool_response,
    raw?.toolResponse,
    raw?.tool_output,
    raw?.toolOutput,
    raw?.response,
    raw?.result,
    raw?.output
  );
  const method = firstString(toolInput?.method, raw?.method).toUpperCase();
  const bodyPreview = firstString(toolInput?.body, toolInput?.body_preview, toolInput?.bodyPreview, raw?.body);
  const responseBodyPreview = firstString(
    toolInput?.responseBodyPreview,
    toolInput?.response_body_preview,
    toolInput?.responsePreview,
    toolInput?.response_body,
    toolInput?.responseBody,
    response?.body,
    response?.content,
    response?.text,
    response?.responseBody,
    raw?.responseBodyPreview,
    raw?.responsePreview,
    raw?.response_body,
    raw?.responseBody,
    raw?.result,
    raw?.output
  );
  const responseContentType = firstString(
    toolInput?.responseContentType,
    toolInput?.response_content_type,
    response?.contentType,
    response?.content_type,
    raw?.responseContentType,
    raw?.response_content_type,
    toolInput?.contentType,
    toolInput?.content_type
  );
  const headers = firstRecord(toolInput?.headers, toolInput?.requestHeaders, raw?.headers, raw?.requestHeaders);
  const responseHeaders = firstRecord(toolInput?.responseHeaders, response?.headers, raw?.responseHeaders);
  return {
    ...(method ? { method } : {}),
    ...(bodyPreview ? { bodyPreview } : {}),
    ...(headers ? { headers } : {}),
    ...(responseBodyPreview ? { responseBodyPreview } : {}),
    ...(responseContentType ? { responseContentType } : {}),
    ...(responseHeaders ? { responseHeaders } : {}),
    ...definedMetadata('responseStatusCode', toolInput?.responseStatusCode, response?.statusCode, response?.status, raw?.responseStatusCode),
    ...definedMetadata('statusCode', toolInput?.statusCode, raw?.statusCode),
    ...definedMetadata('responseBodyBytes', toolInput?.responseBodyBytes, response?.bodyBytes, response?.bytes, raw?.responseBodyBytes),
    ...definedMetadata('responseBytes', toolInput?.responseBytes, raw?.responseBytes),
    ...definedMetadata('contentLength', toolInput?.contentLength, response?.contentLength, raw?.contentLength),
  };
}

function definedMetadata(key: string, ...values: unknown[]): Record<string, unknown> {
  for (const value of values) {
    if (value !== undefined) return { [key]: value };
  }
  return {};
}

function firstRecord(...values: unknown[]): Record<string, unknown> | undefined {
  for (const value of values) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  }
  return undefined;
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function pickSessionId(raw: Record<string, unknown> | null): string {
  const sessionId = raw?.session_id || raw?.sessionId;
  return typeof sessionId === 'string' ? sessionId : `sess_local_${Date.now()}`;
}

function pickCwd(raw: Record<string, unknown> | null): string {
  const value = raw?.cwd;
  return typeof value === 'string' ? value : cwd();
}

function pickSourceSkill(raw: Record<string, unknown> | null): string | undefined {
  const value = raw?.sourceSkill || raw?.initiating_skill;
  return typeof value === 'string' ? value : undefined;
}
