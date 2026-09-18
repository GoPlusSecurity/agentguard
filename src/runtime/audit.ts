import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PolicyReason, RuntimeAction, RuntimeAuditEvent, RuntimePrivacyRuleEvaluation, RuntimeSeverity } from './types.js';
import { redactLlmMetadata, redactMetadata, redactPreview, redactReasons } from './redaction.js';

export function buildAuditEvent(event: RuntimeAuditEvent): RuntimeAuditEvent {
  const nativeHook = isCodexNativeHookAction(event) || isClaudeNativeHookAction(event);
  return {
    actionId: redactPreview(event.actionId, 160),
    sessionId: redactPreview(event.sessionId, 160),
    agentHost: event.agentHost,
    actionType: event.actionType,
    toolName: redactPreview(event.toolName, 160),
    input: isLlmTrafficEvent(event) || nativeHook ? '[LOCAL_ONLY_LLM_CONTENT]' : redactPreview(event.input),
    decision: event.decision,
    policyDecision: event.policyDecision,
    riskScore: clampRiskScore(event.riskScore),
    riskLevel: event.riskLevel,
    reasons: nativeHook ? codexSafeReasons(event.reasons) : redactReasons(event.reasons),
    policyVersion: redactPreview(event.policyVersion, 160),
    cwd: nativeHook ? undefined : event.cwd ? redactPreview(event.cwd, 500) : event.cwd,
    sourceSkill: event.sourceSkill ? redactPreview(event.sourceSkill, 240) : event.sourceSkill,
    lifecycleStage: event.lifecycleStage,
    canBlockCurrentAction: event.canBlockCurrentAction,
    coverageLevel: event.coverageLevel,
    enforcementStatus: event.enforcementStatus,
    missingFacts: event.missingFacts ? [...event.missingFacts] : undefined,
    llm: event.llm ? redactLlmMetadata(event.llm) : undefined,
    metadata: nativeHook
      ? nativeHookSafeMetadata(event.metadata)
      : {
          ...redactMetadata(event.metadata),
          evaluation: redactPreview(event.metadata?.evaluation || 'local-oss', 120),
        },
  };
}

export function isCodexNativeHookAction(action: Pick<RuntimeAction, 'agentHost' | 'metadata'>): boolean {
  return action.agentHost === 'codex' && CODEX_HOOK_EVENTS.has(action.metadata?.codexHookEvent);
}

export function isClaudeNativeHookAction(action: Pick<RuntimeAction, 'agentHost' | 'metadata'>): boolean {
  return action.agentHost === 'claude-code' && CLAUDE_HOOK_EVENTS.has(action.metadata?.claudeHookEvent);
}

export function codexSafeMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> {
  return nativeHookSafeMetadata(metadata);
}

export function nativeHookSafeMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!metadata) return {};
  const result: Record<string, unknown> = {};
  if (CODEX_HOOK_EVENTS.has(metadata.codexHookEvent)) result.codexHookEvent = metadata.codexHookEvent;
  if (CLAUDE_HOOK_EVENTS.has(metadata.claudeHookEvent)) result.claudeHookEvent = metadata.claudeHookEvent;
  if (metadata.evaluation === 'local-oss' || metadata.evaluation === 'cloud') result.evaluation = metadata.evaluation;
  if (metadata.policySource === 'cloud' || metadata.policySource === 'cache'
      || metadata.policySource === 'default' || metadata.policySource === 'cloud-decision') {
    result.policySource = metadata.policySource;
  }
  if (Array.isArray(metadata.privacyRules)) {
    result.privacyRules = metadata.privacyRules.slice(0, 20).map(codexSafePrivacyRule).filter(Boolean);
  }
  for (const key of [
    'responseStatusCode', 'statusCode', 'responseBodyBytes', 'responseBytes', 'contentLength',
    'filePathCount', 'serializedResultBytes', 'redactedBytes', 'contextTokens',
  ]) {
    const value = metadata[key];
    if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) result[key] = value;
  }
  if (metadata.approvedByLocalGrant === true) result.approvedByLocalGrant = true;
  if (typeof metadata.approvalActionId === 'string' && SAFE_ID.test(metadata.approvalActionId)) {
    result.approvalActionId = metadata.approvalActionId;
  }
  if (metadata.approvalOnce === true) result.approvalOnce = true;
  for (const key of [
    'configDiskRollback', 'modelIdIsEndpoint', 'outputReplaceable', 'displayOnly', 'transcriptModified',
    'continuationBlockedOnly', 'resumeRetransmissionGuaranteed',
  ]) {
    if (typeof metadata[key] === 'boolean') result[key] = metadata[key];
  }
  return result;
}

function codexSafeReasons(reasons: PolicyReason[]): PolicyReason[] {
  return reasons.slice(0, 20).map((reason) => ({
    code: SAFE_RULE_ID.test(reason.code) ? reason.code : 'POLICY',
    severity: CODEX_SEVERITIES.has(reason.severity) ? reason.severity as RuntimeSeverity : 'info',
    title: 'Policy rule matched',
    description: '[REDACTED]',
    evidence: reason.evidence === undefined ? undefined : '[REDACTED]',
    remediation: reason.remediation === undefined ? undefined : '[REDACTED]',
  }));
}

function codexSafePrivacyRule(value: unknown): RuntimePrivacyRuleEvaluation | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const rule = value as Record<string, unknown>;
  if (!CODEX_PRIVACY_RULES.has(rule.ruleId) || !COVERAGE_LEVELS.has(rule.coverageLevel)
      || typeof rule.detected !== 'boolean') return null;
  const missingFacts = Array.isArray(rule.missingFacts)
    ? rule.missingFacts.filter((fact): fact is RuntimePrivacyRuleEvaluation['missingFacts'][number] => MISSING_FACTS.has(fact))
    : [];
  const decision = CODEX_DECISIONS.has(rule.decision) ? rule.decision as RuntimePrivacyRuleEvaluation['decision'] : undefined;
  return {
    ruleId: rule.ruleId as RuntimePrivacyRuleEvaluation['ruleId'],
    coverageLevel: rule.coverageLevel as RuntimePrivacyRuleEvaluation['coverageLevel'],
    missingFacts,
    detected: rule.detected,
    ...(decision ? { decision } : {}),
  };
}

const CODEX_HOOK_EVENTS = new Set<unknown>([
  'UserPromptSubmit', 'PreToolUse', 'PermissionRequest', 'PostToolUse', 'PreCompact', 'PostCompact',
]);
const CLAUDE_HOOK_EVENTS = new Set<unknown>([
  'UserPromptSubmit', 'UserPromptExpansion', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
  'PostToolBatch', 'ConfigChange', 'PreModelSwitch', 'PostModelSwitch', 'MessageDisplay', 'Stop',
  'InstructionsLoaded', 'PreCompact', 'PostCompact',
]);
const CODEX_PRIVACY_RULES = new Set<unknown>([
  'UNTRUSTED_LLM_ENDPOINT', 'PII_EGRESS', 'LLM_ENDPOINT_HIJACK', 'RELAY_RESPONSE_TAMPERING',
  'LLM_KEY_TO_UNKNOWN_HOST', 'WORKSPACE_BULK_EGRESS',
]);
const COVERAGE_LEVELS = new Set<unknown>(['full', 'partial', 'observe_only', 'unsupported']);
const MISSING_FACTS = new Set<unknown>([
  'complete_payload', 'complete_response', 'final_destination', 'credential_kind', 'credential_presence',
  'exact_payload_bytes', 'attachment_bytes', 'file_path_count', 'retry_and_fallback',
  'auxiliary_model_calls', 'response_source',
]);
const CODEX_DECISIONS = new Set<unknown>(['allow', 'warn', 'require_approval', 'block']);
const CODEX_SEVERITIES = new Set<unknown>(['info', 'low', 'medium', 'high', 'critical']);
const SAFE_RULE_ID = /^[A-Z][A-Z0-9_]{0,63}$/;
const SAFE_ID = /^[A-Za-z0-9_-]{1,160}$/;

function isLlmTrafficEvent(event: RuntimeAuditEvent): boolean {
  return event.actionType === 'llm_request'
    || event.actionType === 'llm_response'
    || event.metadata?.codexHookEvent === 'UserPromptSubmit'
    || event.metadata?.codexHookEvent === 'PostToolUse';
}

export function writeAuditLog(auditPath: string, event: RuntimeAuditEvent): void {
  ensurePrivateDir(dirname(auditPath));
  appendFileSync(auditPath, `${JSON.stringify(buildAuditEvent(event))}\n`, { mode: 0o600 });
  chmodBestEffort(auditPath, 0o600);
}

export function spoolEvent(spoolPath: string, event: RuntimeAuditEvent): void {
  ensurePrivateDir(dirname(spoolPath));
  appendFileSync(spoolPath, `${JSON.stringify(buildAuditEvent(event))}\n`, { mode: 0o600 });
  chmodBestEffort(spoolPath, 0o600);
}

export function readSpooledEvents(spoolPath: string): RuntimeAuditEvent[] {
  if (!existsSync(spoolPath)) return [];
  return readFileSync(spoolPath, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as RuntimeAuditEvent);
}

export async function flushEventSpool(
  spoolPath: string,
  sendBatch: (events: RuntimeAuditEvent[]) => Promise<void>,
  batchSize = 100
): Promise<{ flushed: number; remaining: number }> {
  const events = readSpooledEvents(spoolPath);
  if (events.length === 0) return { flushed: 0, remaining: 0 };

  let flushed = 0;
  const remaining: RuntimeAuditEvent[] = [];
  for (let index = 0; index < events.length; index += batchSize) {
    const batch = events.slice(index, index + batchSize);
    try {
      await sendBatch(batch);
      flushed += batch.length;
    } catch {
      remaining.push(...batch, ...events.slice(index + batch.length));
      break;
    }
  }

  if (remaining.length === 0) {
    rmSync(spoolPath, { force: true });
  } else {
    writeFileSync(spoolPath, `${remaining.map((event) => JSON.stringify(buildAuditEvent(event))).join('\n')}\n`, { mode: 0o600 });
    chmodBestEffort(spoolPath, 0o600);
  }

  return { flushed, remaining: remaining.length };
}

function clampRiskScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function ensurePrivateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodBestEffort(path, 0o700);
}

function chmodBestEffort(path: string, mode: number): void {
  try {
    chmodSync(path, mode);
  } catch {
    // Best-effort hardening for platforms/filesystems that support chmod.
  }
}
