import { cwd } from 'node:process';
import { AgentGuardCloudClient } from '../cloud/client.js';
import type { AgentGuardConfig } from '../config.js';
import { flushEventSpool, spoolEvent, writeAuditLog } from './audit.js';
import { evaluateLocalAction } from './evaluator.js';
import { resolveRuntimePolicy } from './policy.js';
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
}

export interface ProtectResult {
  decision: RuntimeDecision;
  event: RuntimeAuditEvent;
  approvalChannel?: 'agent' | null;
  policySource: 'cloud' | 'cache' | 'default' | 'cloud-decision';
}

export async function protectAction(options: ProtectOptions): Promise<ProtectResult | null> {
  const action = buildRuntimeAction(options);
  if (!action.input) return null;

  const client = new AgentGuardCloudClient(options.config);
  if (client.connected) {
    await flushEventSpool(options.config.eventSpoolPath, (events) => client.ingestEvents(events)).catch(() => undefined);
  }

  let decision: RuntimeDecision;
  let policySource: ProtectResult['policySource'];
  if (options.decisionMode === 'cloud' && client.connected) {
    decision = normalizeRuntimeDecision(await client.evaluateAction(action));
    policySource = 'cloud-decision';
  } else {
    const { policy, source } = await resolveRuntimePolicy({
      cachePath: options.config.policyCachePath,
      fetchPolicy: client.connected ? () => client.fetchEffectivePolicy() : undefined,
    });
    decision = normalizeRuntimeDecision(await evaluateLocalAction(policy, action));
    policySource = source;
  }

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
  if (decision.decision === 'require_approval') {
    approvalChannel = 'agent';
  }

  return { decision, event, approvalChannel, policySource };
}

function normalizeRuntimeDecision(decision: RuntimeDecision): RuntimeDecision {
  const rawDecision = (decision as unknown as { decision?: string }).decision;
  if (rawDecision === 'require_approve') {
    return { ...decision, decision: 'require_approval' };
  }
  return decision;
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
      policySource: result.policySource,
    }, null, 2);
  }

  const reasonCount = result.decision.reasons.length;
  if (result.decision.decision === 'block') {
    return `BLOCKED by AgentGuard (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}, reasons: ${reasonCount}).`;
  }
  if (result.decision.decision === 'require_approval') {
    return `CONFIRM required by AgentGuard (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}, reasons: ${reasonCount}).`;
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
    (reasonSummary ? ` Reasons: ${reasonSummary}.` : '')
  );
}

function buildRuntimeAction(options: ProtectOptions): RuntimeAction {
  const raw = parseRawInput(options.rawInput, options.stdinText);
  const envActionType = process.env.AGENTGUARD_ACTION_TYPE as RuntimeActionType | undefined;
  const envAgentHost = process.env.AGENTGUARD_AGENT_HOST as RuntimeAgentHost | undefined;
  const toolName = options.toolName || process.env.AGENTGUARD_TOOL_NAME || pickToolName(raw);
  const actionType = options.actionType || envActionType || mapToolToRuntimeAction(toolName, raw);

  return {
    sessionId: options.sessionId || process.env.AGENTGUARD_SESSION_ID || pickSessionId(raw),
    agentHost: options.agentHost || envAgentHost || 'claude-code',
    actionType,
    toolName,
    input: process.env.TOOL_INPUT || pickInput(raw, actionType),
    cwd: pickCwd(raw),
    sourceSkill: pickSourceSkill(raw),
    metadata: { rawProtocol: raw ? 'stdin-json' : 'env' },
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
  if (lower.includes('web') || lower.includes('browser')) return 'network';
  if (raw?.actionType && typeof raw.actionType === 'string') return raw.actionType as RuntimeActionType;
  return 'other';
}

function pickInput(raw: Record<string, unknown> | null, actionType: RuntimeActionType): string {
  if (!raw) return '';
  if (typeof raw.input === 'string') return raw.input;
  if (typeof raw.content === 'string') return raw.content;
  const toolInput = (raw.tool_input || raw.toolInput || raw.params) as Record<string, unknown> | undefined;
  if (toolInput && typeof toolInput === 'object') {
    if (actionType === 'shell' && typeof toolInput.command === 'string') return toolInput.command;
    const filePath = toolInput.file_path || toolInput.path;
    if ((actionType === 'file_read' || actionType === 'file_write') && typeof filePath === 'string') return filePath;
    const url = toolInput.url || toolInput.query;
    if (typeof url === 'string') return url;
    return JSON.stringify(toolInput);
  }
  return JSON.stringify(raw);
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
