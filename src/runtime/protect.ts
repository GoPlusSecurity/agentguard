import { cwd } from 'node:process';
import { dirname, join } from 'node:path';
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

export async function protectAction(options: ProtectOptions): Promise<ProtectResult | null> {
  const action = buildRuntimeAction(options);
  const codexHookEvent = pickCodexHookEventFromAction(action);
  const selfApprovalAttempt = codexHookEvent === 'PreToolUse' && isAgentGuardApprovalCommand(action);
  if (!action.input) return null;
  if (isAgentGuardRuntimeAction(action) && !selfApprovalAttempt) return null;
  const approvalStorePath = resolveApprovalStorePath(options.config);

  const client = new AgentGuardCloudClient(options.config);
  if (client.connected) {
    await flushEventSpool(options.config.eventSpoolPath, (events) => client.ingestEvents(events)).catch(() => undefined);
  }

  let decision: RuntimeDecision;
  let policySource: ProtectResult['policySource'];
  const postToolCall = options.phase === 'post' || codexHookEvent === 'PostToolUse';
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
  decision = enforceCodexHookDecision(action, decision, selfApprovalAttempt);
  const approvedGrant = canEnforce && !postToolCall && decision.decision === 'require_approval'
    ? consumeApprovedApproval(approvalStorePath, action)
    : null;
  if (approvedGrant) {
    decision = { ...decision, decision: 'allow' };
  }
  const auditSafe = options.auditSafe || codexHookEvent === 'PermissionRequest'
    || codexHookEvent === 'PreCompact' || codexHookEvent === 'PostCompact';
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
    coverageLevel: mergeCoverage(action.coverageLevel, decision.coverageLevel),
    enforcementStatus: action.enforcementStatus ?? enforcementStatusFor(action, decision),
    missingFacts: uniqueMissingFacts([...(action.missingFacts ?? []), ...(decision.missingFacts ?? [])]),
    metadata: {
      ...(action.metadata || {}),
      evaluation: policySource === 'cloud-decision' ? 'cloud' : 'local-oss',
      policySource,
      ...(decision.ruleEvaluations?.length ? { privacyRules: decision.ruleEvaluations } : {}),
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
  if (client.connected && policySource !== 'cloud-decision' && !isCodexCompactEvent(codexHookEvent)) {
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

function enforceCodexHookDecision(
  action: RuntimeAction,
  decision: RuntimeDecision,
  selfApprovalAttempt: boolean,
): RuntimeDecision {
  const event = pickCodexHookEventFromAction(action);
  const scansVisibleContent = event === 'UserPromptSubmit' || event === 'PostToolUse';
  const containsSensitiveContent = scansVisibleContent && redactText(action.input) !== action.input;
  if (!selfApprovalAttempt && !containsSensitiveContent) return decision;

  return {
    ...decision,
    decision: 'block',
    policyDecision: 'block',
    riskScore: 100,
    riskLevel: 'critical',
    coverageLevel: 'partial',
    reasons: [{
      code: selfApprovalAttempt ? 'AGENT_SELF_APPROVAL' : 'PII_EGRESS',
      severity: 'critical',
      title: selfApprovalAttempt ? 'Agent approval command denied' : 'Sensitive content blocked',
      description: selfApprovalAttempt
        ? 'Approval must be performed explicitly by the user outside the agent tool path.'
        : 'The locally visible hook content contains sensitive data and was blocked.',
      evidence: '[REDACTED]',
    }],
  };
}

function isCodexCompactEvent(event: CodexHookEvent | undefined): boolean {
  return event === 'PreCompact' || event === 'PostCompact';
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
  if (
    decision.decision === 'require_approval' &&
    result?.approvalChannel === 'agent' &&
    result.event.agentHost === 'claude-code'
  ) return 0;
  return decision.decision === 'block' || decision.decision === 'require_approval' ? 2 : 0;
}

function enforcementStatusFor(action: RuntimeAction, decision: RuntimeDecision) {
  if (mergeCoverage(action.coverageLevel, decision.coverageLevel) === 'unsupported') return 'unsupported' as const;
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
  const nativeCodexHook = (options.agentHost || process.env.AGENTGUARD_AGENT_HOST) === 'codex' && Boolean(wrapper);
  const raw = parseRawInput(options.rawInput, options.stdinText, nativeCodexHook);
  if (nativeCodexHook) validateNativeCodexHook(raw, wrapper);
  const codexHookEvent = pickCodexHookEvent(raw);
  const envActionType = process.env.AGENTGUARD_ACTION_TYPE as RuntimeActionType | undefined;
  const envAgentHost = process.env.AGENTGUARD_AGENT_HOST as RuntimeAgentHost | undefined;
  const toolName = options.toolName || process.env.AGENTGUARD_TOOL_NAME || pickToolName(raw);
  const actionType = options.actionType || envActionType || codexActionType(codexHookEvent, toolName, raw);
  const toolInput = pickToolInput(raw);
  const codexLifecycle = codexLifecycleFields(codexHookEvent);

  return {
    sessionId: options.sessionId || process.env.AGENTGUARD_SESSION_ID || pickSessionId(raw),
    agentHost: options.agentHost || envAgentHost || 'claude-code',
    actionType,
    toolName,
    input: process.env.TOOL_INPUT || pickInput(raw, actionType, toolInput, codexHookEvent),
    cwd: pickCwd(raw),
    sourceSkill: pickSourceSkill(raw),
    lifecycleStage: codexLifecycle.lifecycleStage
      ?? pickEnum(raw?.lifecycleStage ?? raw?.lifecycle_stage, LIFECYCLE_STAGES),
    canBlockCurrentAction: codexLifecycle.canBlockCurrentAction
      ?? pickBoolean(raw?.canBlockCurrentAction ?? raw?.can_block_current_action),
    coverageLevel: codexLifecycle.coverageLevel
      ?? pickEnum(raw?.coverageLevel ?? raw?.coverage_level, COVERAGE_LEVELS),
    enforcementStatus: codexLifecycle.enforcementStatus
      ?? pickEnum(raw?.enforcementStatus ?? raw?.enforcement_status, ENFORCEMENT_STATUSES),
    missingFacts: codexLifecycle.missingFacts
      ?? pickEnumArray(raw?.missingFacts ?? raw?.missing_facts, MISSING_LLM_FACTS),
    llm: pickLlmMetadata(raw),
    metadata: {
      rawProtocol: raw ? 'stdin-json' : 'env',
      ...(codexHookEvent ? { codexHookEvent } : {}),
      ...(options.phase === 'post' ? { hookPhase: 'post' } : {}),
      ...pickNetworkMetadata(raw, toolInput),
      ...pickFilePathMetadata(raw),
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

function pickCodexHookEventFromAction(action: Pick<RuntimeAction, 'metadata'>): CodexHookEvent | undefined {
  const value = action.metadata?.codexHookEvent;
  return typeof value === 'string' ? pickCodexHookEvent({ hook_event_name: value }) : undefined;
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

const LIFECYCLE_STAGES: RuntimeLifecycleStage[] = [
  'user_prompt', 'prompt_expansion', 'run_start', 'model_request', 'model_response', 'pre_tool',
  'post_tool', 'post_tool_batch', 'config_change', 'model_switch', 'assistant_display', 'stop',
];
const COVERAGE_LEVELS: CoverageLevel[] = ['full', 'partial', 'observe_only', 'unsupported'];
const ENFORCEMENT_STATUSES: EnforcementStatus[] = ['enforced', 'would_block', 'observed', 'unsupported'];
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
  if (lower.startsWith('mcp__')) return 'mcp_tool';
  if (toolName === 'Bash' || lower.includes('shell') || lower.includes('exec')) return 'shell';
  if (toolName === 'Read' || lower.includes('read') || lower === 'view_image') return 'file_read';
  if (['Write', 'Edit', 'MultiEdit', 'apply_patch'].includes(toolName) || lower.includes('write') || lower.includes('patch')) return 'file_write';
  if (lower.includes('websearch') || lower.includes('web_search') || lower.includes('search_query')) return 'web_search';
  if (lower.includes('web') || lower.includes('browser')) return 'network';
  if (raw?.actionType && typeof raw.actionType === 'string') return raw.actionType as RuntimeActionType;
  if (raw?.action_type && typeof raw.action_type === 'string') return raw.action_type as RuntimeActionType;
  return 'other';
}

function pickInput(
  raw: Record<string, unknown> | null,
  actionType: RuntimeActionType,
  toolInput = pickToolInput(raw),
  codexHookEvent?: CodexHookEvent,
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
