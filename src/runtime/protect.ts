import { cwd } from 'node:process';
import { dirname, join } from 'node:path';
import { closeSync, openSync, readSync } from 'node:fs';
import { AgentGuardCloudClient } from '../cloud/client.js';
import type { AgentGuardConfig } from '../config.js';
import { consumeApprovedApproval, writePendingApproval, type ApprovalRecord } from './approvals.js';
import { flushEventSpool, spoolEvent, writeAuditLog } from './audit.js';
import { evaluateRuntimeAction } from './decision.js';
import { isAgentGuardCliCommand } from './self-command.js';
import { redactText } from './redaction.js';
import type {
  CoverageLevel,
  CredentialKind,
  EnforcementStatus,
  LlmEgressRequestMetadata,
  LlmEndpointTier,
  LlmRequestPurpose,
  MissingLlmFact,
  RuntimeAction,
  RuntimeAgentHost,
  RuntimeAuditEvent,
  RuntimeActionType,
  RuntimeDecision,
  RuntimeLifecycleStage,
} from './types.js';

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
  /** Persist low-risk/safe decisions for observer lifecycles that require a complete audit trail. */
  auditSafe?: boolean;
}

export interface ProtectResult {
  decision: RuntimeDecision;
  event: RuntimeAuditEvent;
  approvalChannel?: 'agent' | null;
  pendingApproval?: ApprovalRecord;
  policySource: 'cloud' | 'cache' | 'default' | 'cloud-decision';
}

type CodexHookEvent =
  | 'UserPromptSubmit'
  | 'PreToolUse'
  | 'PermissionRequest'
  | 'PostToolUse'
  | 'PreCompact'
  | 'PostCompact';

type ClaudeHookEvent =
  | 'UserPromptSubmit'
  | 'UserPromptExpansion'
  | 'PreToolUse'
  | 'PostToolUse'
  | 'PostToolUseFailure'
  | 'PostToolBatch'
  | 'ConfigChange'
  | 'PreModelSwitch'
  | 'PostModelSwitch'
  | 'MessageDisplay'
  | 'Stop'
  | 'InstructionsLoaded'
  | 'PreCompact'
  | 'PostCompact';

const CLAUDE_CONFIG_READ_LIMIT = 256 * 1024;
const CLAUDE_LARGE_CONTEXT_TOKENS = 100_000;

export async function protectAction(options: ProtectOptions): Promise<ProtectResult | null> {
  const action = buildRuntimeAction(options);
  const codexHookEvent = pickCodexHookEventFromAction(action);
  const claudeHookEvent = pickClaudeHookEventFromAction(action);
  const selfApprovalAttempt = (codexHookEvent === 'PreToolUse' || claudeHookEvent === 'PreToolUse')
    && isAgentGuardApprovalCommand(action);
  if (!action.input) return null;
  if (isAgentGuardRuntimeAction(action) && !selfApprovalAttempt) return null;
  const approvalStorePath = resolveApprovalStorePath(options.config);

  const client = new AgentGuardCloudClient(options.config);
  if (client.connected) {
    await flushEventSpool(options.config.eventSpoolPath, (events) => client.ingestEvents(events)).catch(() => undefined);
  }

  let decision: RuntimeDecision;
  let policySource: ProtectResult['policySource'];
  const postToolCall = options.phase === 'post' || codexHookEvent === 'PostToolUse'
    || claudeHookEvent === 'PostToolUse' || claudeHookEvent === 'PostToolUseFailure';
  const canEnforce = action.canBlockCurrentAction !== false;
  if (options.decisionMode === 'cloud' && client.connected) {
    decision = normalizeRuntimeDecision(await client.evaluateAction(action));
    policySource = 'cloud-decision';
  } else {
    const evaluation = await evaluateRuntimeAction({
      action,
      policyCachePath: options.config.policyCachePath,
      fetchPolicy: client.connected ? () => client.fetchEffectivePolicy() : undefined,
      filesystemAllowlist: options.filesystemAllowlist,
    });
    decision = normalizeRuntimeDecision(evaluation.decision);
    policySource = evaluation.policySource;
  }
  decision = enforceNativeHookDecision(action, decision, selfApprovalAttempt);
  const approvedGrant = canEnforce && !postToolCall && decision.decision === 'require_approval'
    ? consumeApprovedApproval(approvalStorePath, action)
    : null;
  if (approvedGrant) {
    decision = { ...decision, decision: 'allow' };
  }
  const auditSafe = options.auditSafe || codexHookEvent === 'PermissionRequest'
    || codexHookEvent === 'PreCompact' || codexHookEvent === 'PostCompact'
    || isClaudeObserverEvent(claudeHookEvent);
  if (!auditSafe && shouldSuppressRuntimeReport(decision)) return null;

  const event: RuntimeAuditEvent = {
    ...action,
    actionId: decision.actionId,
    decision: decision.decision,
    policyDecision: decision.policyDecision ?? decision.decision,
    riskScore: decision.riskScore,
    riskLevel: decision.riskLevel,
    reasons: decision.reasons,
    policyVersion: decision.policyVersion,
    coverageLevel: decision.ruleEvaluations?.length
      ? mergeCoverage(action.coverageLevel, decision.coverageLevel)
      : action.coverageLevel ?? decision.coverageLevel,
    enforcementStatus: action.enforcementStatus ?? enforcementStatusFor(action, decision),
    missingFacts: uniqueMissingFacts([...(action.missingFacts ?? []), ...(decision.missingFacts ?? [])]),
    metadata: {
      ...(action.metadata || {}),
      evaluation: policySource === 'cloud-decision' ? 'cloud' : 'local-oss',
      policySource,
      ...(decision.ruleEvaluations?.length ? { privacyRules: decision.ruleEvaluations } : {}),
      ...(decision.piiSummary ? { privacySummary: decision.piiSummary } : {}),
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
  if (client.connected && policySource !== 'cloud-decision'
      && !isCodexCompactEvent(codexHookEvent) && !isClaudeMetadataOnlyEvent(claudeHookEvent)) {
    await client.ingestEvents([event]).catch(() => spoolEvent(options.config.eventSpoolPath, event));
  }
  if (canEnforce && !postToolCall && decision.decision === 'require_approval') {
    approvalChannel = 'agent';
  }
  const pendingApproval = canEnforce && !postToolCall && decision.decision === 'require_approval' && !approvedGrant
    ? writePendingApproval(approvalStorePath, action, decision)
    : undefined;

  return { decision, event, approvalChannel, pendingApproval, policySource };
}

function isAgentGuardRuntimeAction(action: RuntimeAction): boolean {
  return action.actionType === 'shell' && isAgentGuardCliCommand(action.input);
}

function isAgentGuardApprovalCommand(action: RuntimeAction): boolean {
  if (action.actionType !== 'shell') return false;
  const normalized = action.input.replace(/\\(.)/gs, '$1').replace(/["']/g, ' ');
  return /(?:^|[^A-Za-z0-9_-])(?:[^\s;|&()]*[\\/])?agentguard(?:[^A-Za-z0-9_-]|$)/i.test(normalized)
    && /(?:^|[^A-Za-z0-9_-])approve(?:[^A-Za-z0-9_-]|$)/i.test(normalized);
}

function enforceNativeHookDecision(
  action: RuntimeAction,
  decision: RuntimeDecision,
  selfApprovalAttempt: boolean,
): RuntimeDecision {
  const event = pickCodexHookEventFromAction(action);
  const claudeEvent = pickClaudeHookEventFromAction(action);
  const scansVisibleContent = event === 'UserPromptSubmit' || event === 'PostToolUse'
    || claudeEvent === 'UserPromptSubmit' || claudeEvent === 'PostToolUse'
    || claudeEvent === 'PostToolBatch' || claudeEvent === 'PostToolUseFailure'
    || claudeEvent === 'MessageDisplay' || claudeEvent === 'Stop' || claudeEvent === 'ConfigChange';
  const containsSensitiveContent = scansVisibleContent
    && (redactText(action.input) !== action.input || action.metadata?.configSensitive === true);
  const untrustedExpansion = claudeEvent === 'UserPromptExpansion'
    && isUntrustedClaudePromptExpansion(action.metadata);
  const explicitModelSwitch = claudeEvent === 'PreModelSwitch'
    && isExplicitClaudeModelSwitch(action.metadata);
  const largeContextModelSwitch = claudeEvent === 'PreModelSwitch'
    && isLargeContextClaudeModelSwitch(action.metadata);
  const dangerousConfig = (claudeEvent === 'ConfigChange' && action.metadata?.configDangerous === true)
    || (claudeEvent === 'PreToolUse' && action.actionType === 'file_write'
      && isDangerousClaudeConfig(action.input));
  if (!selfApprovalAttempt && !containsSensitiveContent && !untrustedExpansion
      && !explicitModelSwitch && !largeContextModelSwitch && !dangerousConfig) return decision;

  const approvalRequired = (explicitModelSwitch || largeContextModelSwitch)
    && !selfApprovalAttempt && !containsSensitiveContent && !untrustedExpansion;

  return {
    ...decision,
    decision: approvalRequired ? 'require_approval' : 'block',
    policyDecision: approvalRequired ? 'require_approval' : 'block',
    riskScore: approvalRequired ? 55 : 100,
    riskLevel: approvalRequired ? 'high' : 'critical',
    coverageLevel: 'partial',
    reasons: [{
      code: selfApprovalAttempt ? 'AGENT_SELF_APPROVAL'
        : untrustedExpansion ? 'UNTRUSTED_PROMPT_EXPANSION'
          : largeContextModelSwitch ? 'LARGE_CONTEXT_MODEL_SWITCH'
            : approvalRequired ? 'MODEL_SWITCH_APPROVAL'
            : dangerousConfig ? 'DANGEROUS_CONFIG_CHANGE' : 'PII_EGRESS',
      severity: approvalRequired ? 'high' : 'critical',
      title: selfApprovalAttempt ? 'Agent approval command denied'
        : untrustedExpansion ? 'Untrusted prompt expansion blocked'
          : approvalRequired ? 'Explicit model switch requires approval'
            : dangerousConfig ? 'Dangerous configuration change blocked' : 'Sensitive content blocked',
      description: selfApprovalAttempt
        ? 'Approval must be performed explicitly by the user outside the agent tool path.'
        : untrustedExpansion
          ? 'The expansion metadata identifies an untrusted command, skill, or MCP prompt source.'
          : approvalRequired
            ? 'An explicit model switch with existing context requires user approval.'
            : dangerousConfig
              ? 'The changed configuration adds unsafe permissions, forwarding, or hook transport behavior.'
              : 'The locally visible hook content contains sensitive data and was blocked.',
      evidence: '[REDACTED]',
    }],
  };
}

function isUntrustedClaudePromptExpansion(metadata: Record<string, unknown> | undefined): boolean {
  const source = String(metadata?.commandSource || '').toLowerCase();
  const type = String(metadata?.expansionType || '').toLowerCase();
  if (source === 'builtin' || source === 'built-in' || source === 'system') return false;
  return source.length > 0 || ['command', 'custom_command', 'skill', 'mcp_prompt'].includes(type);
}

function isExplicitClaudeModelSwitch(metadata: Record<string, unknown> | undefined): boolean {
  const source = String(metadata?.modelSwitchSource || '').toLowerCase();
  return source === 'user' || source === 'manual' || source === 'sdk' || source === 'api';
}

function isLargeContextClaudeModelSwitch(metadata: Record<string, unknown> | undefined): boolean {
  return typeof metadata?.contextTokens === 'number'
    && metadata.contextTokens >= CLAUDE_LARGE_CONTEXT_TOKENS;
}

function isDangerousClaudeConfig(input: string): boolean {
  return /["']permissions["']\s*:\s*\{[\s\S]{0,2000}["']allow["']\s*:\s*\[[\s\S]{0,2000}(?:Bash|PowerShell)\(\*\)/i.test(input)
    || /["'][^"']*(?:endpoint|base_url|http|prompt|agent)[^"']*["']\s*:\s*["']https?:\/\//i.test(input)
    || /["'](?:forward_headers|forwardCredentials|key_forwarding)["']\s*:/i.test(input);
}

function isCodexCompactEvent(event: CodexHookEvent | undefined): boolean {
  return event === 'PreCompact' || event === 'PostCompact';
}

function isClaudeObserverEvent(event: ClaudeHookEvent | undefined): boolean {
  return event === 'PostToolUseFailure' || event === 'PostModelSwitch' || event === 'MessageDisplay'
    || event === 'Stop' || event === 'InstructionsLoaded' || event === 'PreCompact' || event === 'PostCompact';
}

function isClaudeMetadataOnlyEvent(event: ClaudeHookEvent | undefined): boolean {
  return event === 'InstructionsLoaded' || event === 'PreCompact' || event === 'PostCompact';
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
  const codexHook = formatCodexHookResult(result);
  if (!json && codexHook !== null) return codexHook;
  const claudeHook = formatClaudeHookResult(result);
  if (!json && claudeHook !== null) return claudeHook;

  if (!json) {
    const agentApproval = formatAgentApproval(result);
    if (agentApproval) return agentApproval;
  }

  if (json) {
    return JSON.stringify({
      decision: publicEnforcedDecision(result),
      policyDecision: result.decision.policyDecision ?? result.decision.decision,
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
      coverageLevel: result.event.coverageLevel,
      enforcementStatus: result.event.enforcementStatus,
      canBlockCurrentAction: result.event.canBlockCurrentAction,
      missingFacts: result.event.missingFacts,
    }, null, 2);
  }

  const reasonCount = result.decision.reasons.length;
  if (isNonEnforcingObservation(result)) {
    return (
      `OBSERVED by AgentGuard (policy decision: ${result.decision.policyDecision ?? result.decision.decision}, ` +
      `enforcement: ${result.event.enforcementStatus}, action: ${result.decision.actionId}, ` +
      `risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}, reasons: ${reasonCount}).`
    );
  }
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

export function exitCodeForDecision(
  decision: RuntimeDecision,
  result?: Pick<ProtectResult, 'approvalChannel' | 'event'>
): number {
  if (result?.event.canBlockCurrentAction === false) return 0;
  if (result?.event.agentHost === 'codex' && pickCodexHookEventFromAction(result.event)) return 0;
  if (result?.event.agentHost === 'claude-code' && pickClaudeHookEventFromAction(result.event)) return 0;
  if (
    decision.decision === 'require_approval' &&
    result?.approvalChannel === 'agent' &&
    result.event.agentHost === 'claude-code'
  ) return 0;
  return decision.decision === 'block' || decision.decision === 'require_approval' ? 2 : 0;
}

function enforcementStatusFor(action: RuntimeAction, decision: RuntimeDecision) {
  const effectiveCoverage = decision.ruleEvaluations?.length
    ? mergeCoverage(action.coverageLevel, decision.coverageLevel)
    : action.coverageLevel ?? decision.coverageLevel;
  if (effectiveCoverage === 'unsupported') return 'unsupported' as const;
  const policyDecision = decision.policyDecision ?? decision.decision;
  if (action.canBlockCurrentAction === false) {
    return policyDecision === 'block' || policyDecision === 'require_approval'
      ? 'would_block' as const
      : 'observed' as const;
  }
  if (policyDecision !== decision.decision && (policyDecision === 'block' || policyDecision === 'require_approval')) {
    return 'would_block' as const;
  }
  return 'enforced' as const;
}

function mergeCoverage(
  actionCoverage: RuntimeAuditEvent['coverageLevel'],
  decisionCoverage: RuntimeDecision['coverageLevel'],
): RuntimeAuditEvent['coverageLevel'] {
  const levels = [actionCoverage, decisionCoverage].filter(Boolean);
  if (levels.includes('unsupported')) return 'unsupported';
  if (levels.includes('observe_only')) return 'observe_only';
  if (levels.includes('partial')) return 'partial';
  return levels.includes('full') ? 'full' : undefined;
}

function uniqueMissingFacts(
  values: NonNullable<RuntimeAuditEvent['missingFacts']>,
): NonNullable<RuntimeAuditEvent['missingFacts']> {
  return [...new Set(values)];
}

function publicDecision(decision: RuntimeDecision['decision']): 'allow' | 'warn' | 'confirm' | 'block' {
  return decision === 'require_approval' ? 'confirm' : decision;
}

function publicEnforcedDecision(result: ProtectResult): 'allow' | 'warn' | 'confirm' | 'block' {
  if (isNonEnforcingObservation(result)) return 'warn';
  if (result.event.agentHost === 'codex' && result.decision.decision === 'require_approval') return 'block';
  return publicDecision(result.decision.decision);
}

function isNonEnforcingObservation(result: ProtectResult): boolean {
  return result.event.enforcementStatus === 'would_block'
    || result.event.enforcementStatus === 'observed'
    || result.event.enforcementStatus === 'unsupported'
    || result.event.canBlockCurrentAction === false;
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
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: safeCodexReason(result, true),
      },
    });
  }

  return null;
}

function formatCodexHookResult(result: ProtectResult): string | null {
  if (result.event.agentHost !== 'codex') return null;
  const event = pickCodexHookEventFromAction(result.event);
  if (!event) return null;
  const decision = result.decision.decision;
  const denied = decision === 'block' || decision === 'require_approval';
  const reason = safeCodexReason(result, decision === 'require_approval');

  if (event === 'UserPromptSubmit') {
    if (denied) return JSON.stringify({ decision: 'block', reason });
    if (decision === 'warn') return JSON.stringify({ systemMessage: reason });
    return '';
  }
  if (event === 'PreToolUse') {
    if (denied) {
      return JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: reason,
        },
      });
    }
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  if (event === 'PermissionRequest') {
    return JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PermissionRequest',
        decision: denied
          ? { behavior: 'deny', message: reason }
          : { behavior: 'allow' },
      },
    });
  }
  if (event === 'PostToolUse') {
    if (denied) {
      return JSON.stringify({
        decision: 'block',
        reason: `${reason} Tool side effects already occurred and were not undone.`,
      });
    }
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  return '';
}

function formatClaudeHookResult(result: ProtectResult): string | null {
  if (result.event.agentHost !== 'claude-code') return null;
  const event = pickClaudeHookEventFromAction(result.event);
  if (!event) return null;
  const decision = result.decision.decision;
  const denied = decision === 'block' || decision === 'require_approval';
  const reason = safeCodexReason(result, decision === 'require_approval');

  if (event === 'UserPromptSubmit' || event === 'UserPromptExpansion') {
    if (denied) return JSON.stringify({ decision: 'block', reason });
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  if (event === 'PreToolUse') {
    if (denied) {
      return JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: decision === 'require_approval' ? 'ask' : 'deny',
          permissionDecisionReason: reason,
        },
      });
    }
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  if (event === 'PostToolUse') {
    if (Object.prototype.hasOwnProperty.call(result.event.metadata || {}, 'claudeUpdatedToolOutput')) {
      return JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PostToolUse',
          updatedToolOutput: result.event.metadata?.claudeUpdatedToolOutput,
        },
      });
    }
    return denied || decision === 'warn'
      ? JSON.stringify({ systemMessage: `${reason} Output schema was not rewritten; PostToolBatch remains the continuation gate.` })
      : '';
  }
  if (event === 'PostToolBatch') {
    if (denied) {
      return JSON.stringify({
        decision: 'block',
        reason: `${reason} Tool results already exist; the current model continuation was stopped. Session-resume retransmission is not guaranteed blocked.`,
      });
    }
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  if (event === 'ConfigChange') {
    if (denied) {
      return JSON.stringify({
        decision: 'block',
        reason: `${reason} The configuration was not applied to this session; disk content was not rolled back.`,
      });
    }
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  if (event === 'PreModelSwitch') {
    if (denied) {
      return JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreModelSwitch',
          permissionDecision: decision === 'require_approval' ? 'ask' : 'deny',
          permissionDecisionReason: reason,
        },
      });
    }
    return decision === 'warn' ? JSON.stringify({ systemMessage: reason }) : '';
  }
  if (event === 'MessageDisplay') {
    const updatedMessage = result.event.metadata?.claudeUpdatedMessage;
    if (typeof updatedMessage === 'string') {
      return JSON.stringify({ displayContent: updatedMessage });
    }
    return '';
  }
  return '';
}

function safeCodexReason(result: ProtectResult, approvalRequired = false): string {
  const ruleIds = result.decision.reasons
    .map((reason) => /^[A-Z][A-Z0-9_]{0,63}$/.test(reason.code) ? reason.code : 'POLICY')
    .filter(Boolean)
    .slice(0, 6)
    .join(',') || 'POLICY';
  return (
    `AgentGuard ${approvalRequired ? 'approval required' : 'policy decision'}; ` +
    `action=${safeCodexActionId(result.decision.actionId)}; risk=${result.decision.riskLevel}; rules=${ruleIds}; reason=[REDACTED].` +
    (approvalRequired ? ' Approve this action id explicitly outside the agent, then retry.' : '')
  );
}

function safeCodexActionId(value: string): string {
  return /^[A-Za-z0-9_-]{1,160}$/.test(value) ? value : 'act_redacted';
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
  const wrapper = process.env.AGENTGUARD_CODEX_WRAPPER;
  const envAgentHost = process.env.AGENTGUARD_AGENT_HOST as RuntimeAgentHost | undefined;
  const agentHost = options.agentHost || envAgentHost || 'claude-code';
  const nativeCodexHook = agentHost === 'codex' && Boolean(wrapper);
  const nativeClaudeHook = agentHost === 'claude-code' && process.env.AGENTGUARD_CLAUDE_HOOK === '1';
  const raw = parseRawInput(options.rawInput, options.stdinText, nativeCodexHook || nativeClaudeHook);
  if (nativeCodexHook) validateNativeCodexHook(raw, wrapper);
  if (nativeClaudeHook) validateNativeClaudeHook(raw);
  const codexHookEvent = agentHost === 'codex' ? pickCodexHookEvent(raw) : undefined;
  const claudeHookEvent = agentHost === 'claude-code' ? pickClaudeHookEvent(raw) : undefined;
  const envActionType = process.env.AGENTGUARD_ACTION_TYPE as RuntimeActionType | undefined;
  const toolName = options.toolName || process.env.AGENTGUARD_TOOL_NAME || pickToolName(raw);
  const actionType = options.actionType || envActionType || (claudeHookEvent
    ? claudeActionType(claudeHookEvent, toolName, raw)
    : codexActionType(codexHookEvent, toolName, raw));
  const toolInput = pickToolInput(raw);
  const nativeLifecycle = claudeHookEvent
    ? claudeLifecycleFields(claudeHookEvent)
    : codexLifecycleFields(codexHookEvent);
  const sessionId = options.sessionId || process.env.AGENTGUARD_SESSION_ID || pickSessionId(raw);
  const claudeBatch = claudeHookEvent === 'PostToolBatch' ? claudeBatchFacts(raw, sessionId) : undefined;
  const claudeConfig = claudeHookEvent === 'ConfigChange' ? readClaudeConfigChange(raw) : undefined;
  const verifiedOutput = claudeHookEvent === 'PostToolUse'
    ? redactVerifiedClaudeToolOutput(toolName, raw?.tool_response ?? raw?.toolResponse)
    : undefined;
  const displayMessage = claudeHookEvent === 'MessageDisplay'
    ? firstString(raw?.delta)
    : '';
  const actionInput = process.env.TOOL_INPUT
    || pickInput(raw, actionType, toolInput, codexHookEvent, claudeHookEvent, claudeConfig?.input);
  const unknownSensitiveToolOutput = claudeHookEvent === 'PostToolUse'
    && verifiedOutput === undefined && redactText(actionInput) !== actionInput;

  return {
    sessionId,
    agentHost,
    actionType,
    toolName,
    input: actionInput,
    cwd: pickCwd(raw),
    sourceSkill: pickSourceSkill(raw),
    lifecycleStage: nativeLifecycle.lifecycleStage
      ?? pickEnum(raw?.lifecycleStage ?? raw?.lifecycle_stage, LIFECYCLE_STAGES),
    canBlockCurrentAction: nativeLifecycle.canBlockCurrentAction
      ?? pickBoolean(raw?.canBlockCurrentAction ?? raw?.can_block_current_action),
    coverageLevel: nativeLifecycle.coverageLevel
      ?? pickEnum(raw?.coverageLevel ?? raw?.coverage_level, COVERAGE_LEVELS),
    enforcementStatus: (unknownSensitiveToolOutput ? 'would_block' : nativeLifecycle.enforcementStatus)
      ?? pickEnum(raw?.enforcementStatus ?? raw?.enforcement_status, ENFORCEMENT_STATUSES),
    missingFacts: nativeLifecycle.missingFacts
      ?? pickEnumArray(raw?.missingFacts ?? raw?.missing_facts, MISSING_LLM_FACTS),
    llm: claudeBatch?.llm ?? pickLlmMetadata(raw),
    metadata: {
      rawProtocol: raw ? 'stdin-json' : 'env',
      ...(codexHookEvent ? { codexHookEvent } : {}),
      ...(claudeHookEvent ? { claudeHookEvent } : {}),
      ...(options.phase === 'post' ? { hookPhase: 'post' } : {}),
      ...pickNetworkMetadata(raw, toolInput),
      ...pickFilePathMetadata(raw),
      ...claudeEventMetadata(claudeHookEvent, raw),
      ...(claudeBatch?.metadata || {}),
      ...(claudeConfig ? {
        configBytesRead: claudeConfig.bytesRead,
        configDangerous: claudeConfig.dangerous,
        configSensitive: claudeConfig.sensitive,
      } : {}),
      ...(verifiedOutput !== undefined ? { claudeUpdatedToolOutput: verifiedOutput } : {}),
      ...(displayMessage && redactText(displayMessage) !== displayMessage
        ? { claudeUpdatedMessage: redactText(displayMessage) }
        : {}),
    },
  };
}

function validateNativeCodexHook(raw: Record<string, unknown> | null, wrapper: string | undefined): void {
  if (!raw || typeof raw.session_id !== 'string' || typeof raw.cwd !== 'string') throw invalidCodexPayload();
  const event = pickCodexHookEvent(raw);
  const validPair = wrapper === 'user-prompt'
    ? event === 'UserPromptSubmit'
    : wrapper === 'pre-tool'
      ? event === 'PreToolUse' || event === 'PermissionRequest'
      : wrapper === 'post-tool'
        ? event === 'PostToolUse' || event === 'PreCompact' || event === 'PostCompact'
        : false;
  if (!event || !validPair) throw invalidCodexPayload();

  if (event === 'UserPromptSubmit') {
    if (typeof raw.prompt !== 'string') throw invalidCodexPayload();
    return;
  }
  if (event === 'PreToolUse' || event === 'PermissionRequest' || event === 'PostToolUse') {
    if (typeof raw.tool_name !== 'string' || !raw.tool_name || !isPlainRecord(raw.tool_input)) {
      throw invalidCodexPayload();
    }
    if (event === 'PostToolUse' && !Object.prototype.hasOwnProperty.call(raw, 'tool_response')) {
      throw invalidCodexPayload();
    }
    return;
  }
  if (typeof raw.trigger !== 'string'
      || !(typeof raw.transcript_path === 'string' || raw.transcript_path === null)) throw invalidCodexPayload();
}

function invalidCodexPayload(): Error {
  return new Error('Invalid Codex hook payload.');
}

function validateNativeClaudeHook(raw: Record<string, unknown> | null): void {
  if (!raw || typeof raw.session_id !== 'string' || typeof raw.cwd !== 'string') throw invalidClaudePayload();
  const event = pickClaudeHookEvent(raw);
  if (!event) throw invalidClaudePayload();
  if (event === 'UserPromptSubmit' && typeof raw.prompt !== 'string') throw invalidClaudePayload();
  if (event === 'UserPromptExpansion'
      && (typeof raw.expansion_type !== 'string' || typeof raw.command_name !== 'string')) throw invalidClaudePayload();
  if (event === 'PreToolUse' || event === 'PostToolUse' || event === 'PostToolUseFailure') {
    if (typeof raw.tool_name !== 'string' || !raw.tool_name || !isPlainRecord(raw.tool_input)) throw invalidClaudePayload();
    if (event === 'PostToolUse' && !Object.prototype.hasOwnProperty.call(raw, 'tool_response')) throw invalidClaudePayload();
  }
  if (event === 'PostToolBatch' && (!Array.isArray(raw.tool_calls)
      || !raw.tool_calls.every((call) => isPlainRecord(call)
        && Object.prototype.hasOwnProperty.call(call, 'tool_response')))) {
    throw invalidClaudePayload();
  }
  if (event === 'ConfigChange' && (typeof raw.source !== 'string'
      || !(raw.file_path === undefined || typeof raw.file_path === 'string'))) {
    throw invalidClaudePayload();
  }
  if (event === 'MessageDisplay' && typeof raw.delta !== 'string') throw invalidClaudePayload();
  if ((event === 'PreModelSwitch' || event === 'PostModelSwitch')
      && (typeof raw.from_model !== 'string' || typeof raw.to_model !== 'string' || typeof raw.source !== 'string')) {
    throw invalidClaudePayload();
  }
}

function invalidClaudePayload(): Error {
  return new Error('Invalid Claude Code hook payload.');
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function pickCodexHookEvent(raw: Record<string, unknown> | null): CodexHookEvent | undefined {
  const value = raw?.hook_event_name;
  return value === 'UserPromptSubmit' || value === 'PreToolUse' || value === 'PermissionRequest'
    || value === 'PostToolUse' || value === 'PreCompact' || value === 'PostCompact'
    ? value
    : undefined;
}

function pickClaudeHookEvent(raw: Record<string, unknown> | null): ClaudeHookEvent | undefined {
  const value = raw?.hook_event_name;
  return value === 'UserPromptSubmit' || value === 'UserPromptExpansion' || value === 'PreToolUse'
    || value === 'PostToolUse' || value === 'PostToolUseFailure' || value === 'PostToolBatch'
    || value === 'ConfigChange' || value === 'PreModelSwitch' || value === 'PostModelSwitch'
    || value === 'MessageDisplay' || value === 'Stop' || value === 'InstructionsLoaded'
    || value === 'PreCompact' || value === 'PostCompact'
    ? value
    : undefined;
}

function pickCodexHookEventFromAction(action: Pick<RuntimeAction, 'metadata'>): CodexHookEvent | undefined {
  const value = action.metadata?.codexHookEvent;
  return typeof value === 'string' ? pickCodexHookEvent({ hook_event_name: value }) : undefined;
}

function pickClaudeHookEventFromAction(action: Pick<RuntimeAction, 'metadata'>): ClaudeHookEvent | undefined {
  const value = action.metadata?.claudeHookEvent;
  return typeof value === 'string' ? pickClaudeHookEvent({ hook_event_name: value }) : undefined;
}

function codexActionType(
  event: CodexHookEvent | undefined,
  toolName: string,
  raw: Record<string, unknown> | null,
): RuntimeActionType {
  if (event === 'UserPromptSubmit') return 'other';
  if (event === 'PostToolUse' || event === 'PreCompact' || event === 'PostCompact') return 'other';
  return mapToolToRuntimeAction(toolName, raw);
}

function claudeActionType(
  event: ClaudeHookEvent,
  toolName: string,
  raw: Record<string, unknown> | null,
): RuntimeActionType {
  if (event === 'PostToolBatch') return 'llm_request';
  if (event === 'ConfigChange') return 'file_write';
  if (event === 'PreToolUse') return mapToolToRuntimeAction(toolName, raw);
  return 'other';
}

function codexLifecycleFields(event: CodexHookEvent | undefined): Pick<
  RuntimeAction,
  'lifecycleStage' | 'canBlockCurrentAction' | 'coverageLevel' | 'enforcementStatus' | 'missingFacts'
> {
  if (event === 'UserPromptSubmit') {
    return {
      lifecycleStage: 'user_prompt',
      canBlockCurrentAction: true,
      coverageLevel: 'partial',
      missingFacts: [
        'complete_payload', 'final_destination', 'credential_kind', 'credential_presence',
        'exact_payload_bytes', 'attachment_bytes', 'file_path_count', 'retry_and_fallback',
        'auxiliary_model_calls',
      ],
    };
  }
  if (event === 'PreToolUse' || event === 'PermissionRequest') {
    return { lifecycleStage: 'pre_tool', canBlockCurrentAction: true, coverageLevel: 'partial' };
  }
  if (event === 'PostToolUse') {
    return { lifecycleStage: 'post_tool', canBlockCurrentAction: true, coverageLevel: 'partial' };
  }
  if (event === 'PreCompact' || event === 'PostCompact') {
    return {
      lifecycleStage: 'stop',
      canBlockCurrentAction: false,
      coverageLevel: 'observe_only',
      enforcementStatus: 'observed',
    };
  }
  return {};
}

function claudeLifecycleFields(event: ClaudeHookEvent | undefined): Pick<
  RuntimeAction,
  'lifecycleStage' | 'canBlockCurrentAction' | 'coverageLevel' | 'enforcementStatus' | 'missingFacts'
> {
  const requestMissing: MissingLlmFact[] = [
    'complete_payload', 'final_destination', 'credential_kind', 'credential_presence',
    'attachment_bytes', 'retry_and_fallback', 'auxiliary_model_calls',
  ];
  if (event === 'UserPromptSubmit') {
    return {
      lifecycleStage: 'user_prompt', canBlockCurrentAction: true, coverageLevel: 'partial',
      missingFacts: [...requestMissing, 'exact_payload_bytes', 'file_path_count'],
    };
  }
  if (event === 'UserPromptExpansion') {
    return {
      lifecycleStage: 'prompt_expansion', canBlockCurrentAction: true, coverageLevel: 'partial',
      missingFacts: [...requestMissing, 'exact_payload_bytes', 'file_path_count'],
    };
  }
  if (event === 'PreToolUse') {
    return { lifecycleStage: 'pre_tool', canBlockCurrentAction: true, coverageLevel: 'partial' };
  }
  if (event === 'PostToolUse') {
    return { lifecycleStage: 'post_tool', canBlockCurrentAction: true, coverageLevel: 'partial' };
  }
  if (event === 'PostToolUseFailure') {
    return {
      lifecycleStage: 'post_tool', canBlockCurrentAction: false, coverageLevel: 'partial',
      enforcementStatus: 'observed', missingFacts: ['complete_response'],
    };
  }
  if (event === 'PostToolBatch') {
    return {
      lifecycleStage: 'post_tool_batch', canBlockCurrentAction: true, coverageLevel: 'partial',
      missingFacts: requestMissing,
    };
  }
  if (event === 'ConfigChange') {
    return { lifecycleStage: 'config_change', canBlockCurrentAction: true, coverageLevel: 'partial' };
  }
  if (event === 'PreModelSwitch') {
    return {
      lifecycleStage: 'model_switch', canBlockCurrentAction: true, coverageLevel: 'partial',
      missingFacts: [...requestMissing, 'exact_payload_bytes', 'file_path_count'],
    };
  }
  if (event === 'PostModelSwitch') {
    return {
      lifecycleStage: 'model_switch', canBlockCurrentAction: false, coverageLevel: 'observe_only',
      enforcementStatus: 'observed', missingFacts: ['final_destination', 'retry_and_fallback'],
    };
  }
  if (event === 'MessageDisplay') {
    return {
      lifecycleStage: 'assistant_display', canBlockCurrentAction: false, coverageLevel: 'partial',
      enforcementStatus: 'display_only', missingFacts: ['complete_response', 'response_source'],
    };
  }
  if (event === 'Stop') {
    return {
      lifecycleStage: 'stop', canBlockCurrentAction: false, coverageLevel: 'observe_only',
      enforcementStatus: 'observed', missingFacts: ['complete_response', 'response_source'],
    };
  }
  if (event === 'InstructionsLoaded' || event === 'PreCompact' || event === 'PostCompact') {
    return {
      lifecycleStage: 'stop', canBlockCurrentAction: false, coverageLevel: 'observe_only',
      enforcementStatus: 'observed', missingFacts: ['complete_payload'],
    };
  }
  return {};
}

const LIFECYCLE_STAGES: RuntimeLifecycleStage[] = [
  'user_prompt', 'prompt_expansion', 'run_start', 'model_request', 'model_response', 'pre_tool',
  'post_tool', 'post_tool_batch', 'config_change', 'model_switch', 'assistant_display', 'stop',
];
const COVERAGE_LEVELS: CoverageLevel[] = ['full', 'partial', 'observe_only', 'unsupported'];
const ENFORCEMENT_STATUSES: EnforcementStatus[] = ['enforced', 'would_block', 'observed', 'display_only', 'unsupported'];
const MISSING_LLM_FACTS: MissingLlmFact[] = [
  'complete_payload', 'complete_response', 'final_destination', 'credential_kind', 'credential_presence',
  'exact_payload_bytes', 'attachment_bytes', 'file_path_count', 'retry_and_fallback',
  'auxiliary_model_calls', 'response_source',
];
const LLM_PURPOSES: LlmRequestPurpose[] = [
  'unknown', 'conversation', 'compaction', 'title', 'vision', 'embedding', 'file_upload', 'plugin', 'other',
];
const CREDENTIAL_KINDS: CredentialKind[] = ['api_key', 'oauth', 'aws', 'ambient', 'none', 'unknown'];
const ENDPOINT_TIERS: LlmEndpointTier[] = ['T0', 'T1', 'T2', 'T3', 'T4', 'unknown'];

function pickLlmMetadata(raw: Record<string, unknown> | null): LlmEgressRequestMetadata | undefined {
  const value = firstRecord(raw?.llm, raw?.llm_metadata, raw?.llmMetadata);
  if (!value) return undefined;
  const requestId = firstString(value.requestId, value.request_id);
  const sessionId = firstString(value.sessionId, value.session_id, raw?.sessionId, raw?.session_id);
  const lifecycleStage = pickEnum(value.lifecycleStage ?? value.lifecycle_stage, LIFECYCLE_STAGES);
  if (!requestId || !sessionId || !lifecycleStage) return undefined;
  const destinationValue = firstRecord(value.destination);
  const destination = destinationValue ? {
    scheme: optionalString(destinationValue.scheme),
    host: optionalString(destinationValue.host),
    port: nonNegativeInteger(destinationValue.port),
    path: optionalString(destinationValue.path),
    service: optionalString(destinationValue.service),
    region: optionalString(destinationValue.region),
    tier: pickEnum(destinationValue.tier, ENDPOINT_TIERS),
  } : undefined;
  const rawCredentialPresent = value.credentialPresent ?? value.credential_present;
  const credentialPresent = typeof rawCredentialPresent === 'boolean'
    ? rawCredentialPresent
    : 'unknown';
  return {
    schemaVersion: 1,
    requestId,
    parentRequestId: firstString(value.parentRequestId, value.parent_request_id) || undefined,
    sessionId,
    purpose: pickEnum(value.purpose, LLM_PURPOSES) ?? 'unknown',
    lifecycleStage,
    canBlockCurrentAction: pickBoolean(value.canBlockCurrentAction ?? value.can_block_current_action) ?? false,
    provider: optionalString(value.provider),
    model: optionalString(value.model),
    apiMode: optionalString(value.apiMode ?? value.api_mode),
    attempt: nonNegativeInteger(value.attempt),
    isRetry: pickBoolean(value.isRetry ?? value.is_retry),
    isFallback: pickBoolean(value.isFallback ?? value.is_fallback),
    destination,
    credentialKind: pickEnum(value.credentialKind ?? value.credential_kind, CREDENTIAL_KINDS) ?? 'unknown',
    credentialPresent,
    payloadBytes: nonNegativeInteger(value.payloadBytes ?? value.payload_bytes),
    attachmentBytes: nonNegativeInteger(value.attachmentBytes ?? value.attachment_bytes),
    messageCount: nonNegativeInteger(value.messageCount ?? value.message_count),
    filePathCount: nonNegativeInteger(value.filePathCount ?? value.file_path_count),
  };
}

function pickFilePathMetadata(raw: Record<string, unknown> | null): Record<string, unknown> {
  const metadata = firstRecord(raw?.metadata);
  const paths = metadata?.filePaths ?? metadata?.file_paths;
  if (!Array.isArray(paths)) return {};
  return { filePaths: paths.filter((item): item is string => typeof item === 'string').slice(0, 10_000) };
}

function claudeEventMetadata(
  event: ClaudeHookEvent | undefined,
  raw: Record<string, unknown> | null,
): Record<string, unknown> {
  if (!event || !raw) return {};
  if (event === 'UserPromptExpansion') {
    return {
      expansionType: firstString(raw.expansion_type) || 'unknown',
      commandName: firstString(raw.command_name) || 'unknown',
      commandSource: firstString(raw.command_source) || 'unknown',
    };
  }
  if (event === 'ConfigChange') {
    return { configSource: firstString(raw.source) || 'unknown', configDiskRollback: false };
  }
  if (event === 'PreModelSwitch' || event === 'PostModelSwitch') {
    return {
      fromModel: firstString(raw.from_model) || 'unknown',
      toModel: firstString(raw.to_model) || 'unknown',
      modelSwitchSource: firstString(raw.source) || 'unknown',
      contextTokens: nonNegativeInteger(raw.context_tokens),
      modelIdIsEndpoint: false,
    };
  }
  if (event === 'PostToolUseFailure') {
    return { failureType: firstString(raw.error_type, raw.failure_type) || 'unknown', outputReplaceable: false };
  }
  if (event === 'MessageDisplay') return { displayOnly: true, transcriptModified: false };
  if (event === 'PostToolBatch') return { continuationBlockedOnly: true, resumeRetransmissionGuaranteed: false };
  return {};
}

function claudeBatchFacts(
  raw: Record<string, unknown> | null,
  sessionId: string,
): { llm: LlmEgressRequestMetadata; metadata: Record<string, unknown> } {
  const responses = raw?.tool_calls ?? [];
  const serialized = JSON.stringify(responses);
  const filePaths = collectClaudeBatchFilePaths(responses);
  return {
    llm: {
      schemaVersion: 1,
      requestId: `claude-code:${sessionId}:post-tool-batch`,
      sessionId,
      purpose: 'conversation',
      lifecycleStage: 'post_tool_batch',
      canBlockCurrentAction: true,
      credentialKind: 'unknown',
      credentialPresent: 'unknown',
      payloadBytes: Buffer.byteLength(serialized, 'utf8'),
      filePathCount: filePaths.length,
    },
    metadata: {
      filePathCount: filePaths.length,
      serializedResultBytes: Buffer.byteLength(serialized, 'utf8'),
      redactedBytes: Buffer.byteLength(serialized, 'utf8') - Buffer.byteLength(redactText(serialized), 'utf8'),
      filePaths,
    },
  };
}

function collectClaudeBatchFilePaths(value: unknown): string[] {
  const paths = new Set<string>();
  const visit = (candidate: unknown): void => {
    if (Array.isArray(candidate)) {
      for (const item of candidate) visit(item);
      return;
    }
    if (!candidate || typeof candidate !== 'object') return;
    for (const [key, item] of Object.entries(candidate as Record<string, unknown>)) {
      if ((key === 'file_path' || key === 'filePath' || key === 'path') && typeof item === 'string') {
        paths.add(item);
      } else {
        visit(item);
      }
    }
  };
  visit(value);
  return [...paths].slice(0, 10_000);
}

function redactVerifiedClaudeToolOutput(toolName: string, output: unknown): unknown | undefined {
  const lower = toolName.toLowerCase();
  const verifiedTool = toolName === 'Read' || toolName === 'Bash' || toolName === 'PowerShell'
    || toolName === 'WebFetch' || toolName === 'WebSearch' || lower.startsWith('mcp__');
  if (!verifiedTool) return undefined;
  if (typeof output === 'string') return redactText(output);
  if (!isPlainRecord(output)) return undefined;
  const hasVerifiedShape = toolName === 'Read'
    ? typeof output.content === 'string'
    : toolName === 'Bash' || toolName === 'PowerShell'
      ? ['stdout', 'stderr', 'output'].some((key) => typeof output[key] === 'string')
      : lower.startsWith('mcp__')
        ? Array.isArray(output.content)
        : typeof output.content === 'string' || Array.isArray(output.content);
  return hasVerifiedShape ? redactStructuredClaudeOutput(output) : undefined;
}

function redactStructuredClaudeOutput(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactStructuredClaudeOutput);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => [key, redactStructuredClaudeOutput(item)]));
}

function pickEnum<T extends string>(value: unknown, allowed: readonly T[]): T | undefined {
  return typeof value === 'string' && allowed.includes(value as T) ? value as T : undefined;
}

function pickEnumArray<T extends string>(value: unknown, allowed: readonly T[]): T[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is T => typeof item === 'string' && allowed.includes(item as T));
}

function pickBoolean(value: unknown): boolean | undefined {
  return typeof value === 'boolean' ? value : undefined;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function nonNegativeInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function parseRawInput(rawInput: unknown, stdinText?: string, strictJson = false): Record<string, unknown> | null {
  if (rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput)) return rawInput as Record<string, unknown>;
  if (strictJson && rawInput !== undefined) throw new Error('Codex hook input must be a JSON object.');
  const text = stdinText?.trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    if (strictJson) throw new Error('Codex hook input must be a JSON object.');
    return null;
  } catch {
    if (strictJson) throw new Error('Codex hook input must be a JSON object.');
    return { content: text };
  }
}

function pickToolName(raw: Record<string, unknown> | null): string {
  if (!raw) return 'Tool';
  return String(raw.tool_name || raw.toolName || raw.name || 'Tool');
}

function mapToolToRuntimeAction(toolName: string, raw: Record<string, unknown> | null): RuntimeActionType {
  const lower = toolName.toLowerCase();
  const toolInput = pickToolInput(raw);
  if (lower.startsWith('mcp__')) return 'mcp_tool';
  if (toolName === 'Bash' || toolName === 'PowerShell' || lower.includes('shell') || lower.includes('exec')) return 'shell';
  if (toolName === 'Read' || lower.includes('read') || lower === 'view_image') return 'file_read';
  if (['Write', 'Edit', 'MultiEdit', 'apply_patch'].includes(toolName)
      || lower.includes('write') || lower.includes('edit') || lower.includes('patch')) return 'file_write';
  if (lower.includes('websearch') || lower.includes('web_search') || lower.includes('search_query')) return 'web_search';
  if (lower.includes('web') || lower.includes('browser')) return 'network';
  if (typeof toolInput?.command === 'string' || typeof toolInput?.cmd === 'string') return 'shell';
  if (typeof toolInput?.query === 'string') return 'web_search';
  if (typeof toolInput?.url === 'string' || typeof toolInput?.uri === 'string'
      || typeof toolInput?.href === 'string') return 'network';
  const hasPath = typeof toolInput?.file_path === 'string' || typeof toolInput?.filePath === 'string'
    || typeof toolInput?.path === 'string' || typeof toolInput?.target === 'string';
  const hasWriteContent = ['content', 'new_string', 'old_string', 'patch'].some((key) =>
    typeof toolInput?.[key] === 'string');
  if (hasPath) return hasWriteContent ? 'file_write' : 'file_read';
  if (raw?.actionType && typeof raw.actionType === 'string') return raw.actionType as RuntimeActionType;
  if (raw?.action_type && typeof raw.action_type === 'string') return raw.action_type as RuntimeActionType;
  return 'other';
}

function pickInput(
  raw: Record<string, unknown> | null,
  actionType: RuntimeActionType,
  toolInput = pickToolInput(raw),
  codexHookEvent?: CodexHookEvent,
  claudeHookEvent?: ClaudeHookEvent,
  claudeConfigInput?: string,
): string {
  if (!raw) return '';
  if (codexHookEvent === 'UserPromptSubmit') return firstString(raw.prompt);
  if (codexHookEvent === 'PostToolUse') {
    const response = raw.tool_response ?? raw.toolResponse;
    return typeof response === 'string' ? response : response === undefined ? '' : JSON.stringify(response);
  }
  if (codexHookEvent === 'PreCompact' || codexHookEvent === 'PostCompact') {
    return `compact trigger=${firstString(raw.trigger) || 'unknown'}`;
  }
  if (claudeHookEvent === 'UserPromptSubmit') return firstString(raw.prompt);
  if (claudeHookEvent === 'UserPromptExpansion') {
    return JSON.stringify({
      expansion_type: raw.expansion_type,
      command_name: raw.command_name,
      command_args: raw.command_args,
      command_source: raw.command_source,
    });
  }
  if (claudeHookEvent === 'PostToolUse') {
    const response = raw.tool_response ?? raw.toolResponse;
    return typeof response === 'string' ? response : response === undefined ? '' : JSON.stringify(response);
  }
  if (claudeHookEvent === 'PostToolUseFailure') {
    const failure = raw.error ?? raw.error_message ?? raw.stderr ?? raw.tool_response;
    return typeof failure === 'string' ? failure : failure === undefined ? 'tool failure' : JSON.stringify(failure);
  }
  if (claudeHookEvent === 'PostToolBatch') {
    return JSON.stringify(raw.tool_calls ?? []);
  }
  if (claudeHookEvent === 'ConfigChange') return claudeConfigInput ?? 'config change';
  if (claudeHookEvent === 'PreModelSwitch' || claudeHookEvent === 'PostModelSwitch') {
    return `model switch source=${firstString(raw.source) || 'unknown'} context_tokens=${nonNegativeInteger(raw.context_tokens) ?? 'unknown'}`;
  }
  if (claudeHookEvent === 'MessageDisplay') return firstString(raw.delta);
  if (claudeHookEvent === 'Stop') {
    return firstString(raw.last_assistant_message, raw.lastAssistantMessage, raw.stop_reason, raw.reason, raw.message, raw.content, 'stop');
  }
  if (claudeHookEvent === 'InstructionsLoaded') {
    const count = Array.isArray(raw.instructions) ? raw.instructions.length : nonNegativeInteger(raw.instruction_count) ?? 0;
    return `instructions loaded count=${count}`;
  }
  if (claudeHookEvent === 'PreCompact' || claudeHookEvent === 'PostCompact') {
    return `compact trigger=${firstString(raw.trigger) || 'unknown'}`;
  }
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
    if (actionType === 'file_read' && typeof filePath === 'string') return filePath;
    if (actionType === 'file_write') {
      const content = firstString(toolInput.content, toolInput.new_string, toolInput.old_string, toolInput.patch);
      return `${JSON.stringify(toolInput)}${content ? `\n${content}` : ''}`;
    }
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

function readClaudeConfigChange(raw: Record<string, unknown> | null): {
  input: string;
  bytesRead: number;
  dangerous: boolean;
  sensitive: boolean;
} {
  const path = firstString(raw?.file_path);
  if (!path) return { input: 'config change', bytesRead: 0, dangerous: false, sensitive: false };
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, 'r');
    const buffer = Buffer.alloc(CLAUDE_CONFIG_READ_LIMIT);
    const bytesRead = readSync(descriptor, buffer, 0, buffer.length, 0);
    const content = buffer.subarray(0, bytesRead).toString('utf8');
    return {
      input: path,
      bytesRead,
      dangerous: isDangerousClaudeConfig(content),
      sensitive: redactText(content) !== content,
    };
  } catch {
    return { input: path, bytesRead: 0, dangerous: false, sensitive: false };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
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
