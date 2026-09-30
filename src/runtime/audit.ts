import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PolicyReason, RuntimeAction, RuntimeAuditEvent, RuntimePiiSummary, RuntimePrivacyRuleEvaluation, RuntimeSeverity } from './types.js';
import { redactLlmMetadata, redactMetadata, redactPreview, redactReasons, redactText } from './redaction.js';

export function buildAuditEvent(event: RuntimeAuditEvent): RuntimeAuditEvent {
  const nativeHook = isCodexNativeHookAction(event) || isClaudeNativeHookAction(event);
  return {
    actionId: redactPreview(event.actionId, 160),
    sessionId: redactPreview(event.sessionId, 160),
    agentHost: event.agentHost,
    actionType: event.actionType,
    toolName: redactPreview(event.toolName, 160),
    input: isLlmTrafficEvent(event)
      ? '[LOCAL_ONLY_LLM_CONTENT]'
      : nativeHook
        ? nativeHookAuditInput(event)
        : redactPreview(event.input),
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
    privacySummary: event.privacySummary ? sanitizePiiSummary(event.privacySummary) : undefined,
    llm: event.llm ? redactLlmMetadata(event.llm) : undefined,
    metadata: nativeHook
      ? nativeHookSafeMetadata(event.metadata)
      : {
          ...redactMetadata(event.metadata),
          evaluation: redactPreview(event.metadata?.evaluation || 'local-oss', 120),
        },
  };
}

/**
 * Keep model traffic private while still reporting confirmed PII egress.
 *
 * Model responses never leave the machine. Routine model requests also stay
 * local; a request is Cloud-reportable only when local evaluation found PII
 * and the request was not stopped at a blocking gate.
 */
export function shouldReportAuditEventToCloud(event: RuntimeAuditEvent): boolean {
  if (isNativePostToolEvent(event)) return shouldReportNativePostToolEvent(event);
  if (event.actionType === 'llm_response') return false;
  if (event.actionType !== 'llm_request') return true;

  const piiDetected = hasPiiSummary(event.privacySummary);
  if (!piiDetected) return false;

  const stoppedBeforeEgress = event.canBlockCurrentAction !== false
    && (event.decision === 'block' || event.decision === 'require_approval');
  return !stoppedBeforeEgress;
}

/**
 * Routine post-tool observations duplicate the already reported pre-tool
 * action and stay in the local audit. Upload a separate post-tool event only
 * when the result adds a material security or execution signal.
 */
function shouldReportNativePostToolEvent(event: RuntimeAuditEvent): boolean {
  if (event.metadata?.claudeHookEvent === 'PostToolUseFailure') return true;
  if (event.metadata?.toolFailed === true) return true;

  const responseStatus = firstSafeInteger(
    event.metadata?.responseStatusCode,
    event.metadata?.statusCode,
  );
  if (responseStatus !== undefined && responseStatus >= 400) return true;

  if (event.decision !== 'allow' || (event.policyDecision && event.policyDecision !== 'allow')) return true;
  if (event.riskScore >= 20 || MATERIAL_POST_RISK_LEVELS.has(event.riskLevel)) return true;
  if (event.enforcementStatus === 'would_block' || event.enforcementStatus === 'unsupported') return true;
  if (hasPiiSummary(event.privacySummary)) return true;

  return event.reasons.some((reason) => (
    reason.code !== 'SHELL_INJECTION_RISK' || MATERIAL_POST_SEVERITIES.has(reason.severity)
  ));
}

function isNativePostToolEvent(event: RuntimeAuditEvent): boolean {
  return event.metadata?.codexHookEvent === 'PostToolUse'
    || event.metadata?.claudeHookEvent === 'PostToolUse'
    || event.metadata?.claudeHookEvent === 'PostToolUseFailure';
}

function hasPiiSummary(summary: RuntimePiiSummary | undefined): boolean {
  return Boolean(summary
    && Number.isSafeInteger(summary.valueCount)
    && summary.valueCount > 0
    && summary.categories.some((item) => (
      PII_CATEGORIES.has(item.category)
      && Number.isSafeInteger(item.count)
      && item.count > 0
    )));
}

function firstSafeInteger(...values: unknown[]): number | undefined {
  return values.find((value): value is number => Number.isSafeInteger(value));
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
    'filePathCount', 'serializedResultBytes', 'redactedBytes', 'contextTokens', 'exitCode',
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
    'continuationBlockedOnly', 'resumeRetransmissionGuaranteed', 'toolFailed',
  ]) {
    if (typeof metadata[key] === 'boolean') result[key] = metadata[key];
  }
  return result;
}

function codexSafeReasons(reasons: PolicyReason[]): PolicyReason[] {
  return reasons.slice(0, 20).map((reason) => ({
    code: SAFE_RULE_ID.test(reason.code) ? reason.code : 'POLICY',
    severity: CODEX_SEVERITIES.has(reason.severity) ? reason.severity as RuntimeSeverity : 'info',
    title: reason.code === 'SECRET_ACCESS' ? 'Protected path access' : 'Policy rule matched',
    description: '[REDACTED]',
    evidence: reason.evidence === undefined ? undefined : '[REDACTED]',
    remediation: reason.remediation === undefined ? undefined : '[REDACTED]',
  }));
}

/**
 * Preserve a minimal explanation for protected-file access
 * without exporting the raw native-hook command, absolute path, or arguments.
 */
function nativeHookAuditInput(event: RuntimeAuditEvent): string {
  const protectedAccess = event.reasons.some((reason) => reason.code === 'SECRET_ACCESS');
  if (event.actionType === 'shell' && !protectedAccess) return nativeHookShellPreview(event);
  if (!protectedAccess) return '[LOCAL_ONLY_LLM_CONTENT]';

  const protectedFile = safeProtectedFileReference(event);
  if (!protectedFile) return '[LOCAL_ONLY_LLM_CONTENT]';

  if (event.actionType === 'shell') {
    const command = safeShellCommandName(event.input);
    return `${command ?? 'access'} ${protectedFile}`;
  }
  if (event.actionType === 'file_read') return `read ${protectedFile}`;
  if (event.actionType === 'file_write') return `write ${protectedFile}`;
  return `access ${protectedFile}`;
}

function nativeHookShellPreview(event: RuntimeAuditEvent): string {
  const redacted = redactText(event.input);
  const hasUnmaskedSensitiveFinding = event.reasons.some((reason) => (
    NATIVE_SENSITIVE_CONTENT_RULES.has(reason.code)
  )) && redacted === event.input;
  if (hasUnmaskedSensitiveFinding) return '[LOCAL_ONLY_LLM_CONTENT]';
  const preview = redacted.slice(0, 2000);
  return preview.trim() ? preview : '[LOCAL_ONLY_LLM_CONTENT]';
}

function safeProtectedFileReference(event: RuntimeAuditEvent): string | undefined {
  const input = event.input;
  const ssh = input.match(/\.ssh[\\/]([A-Za-z0-9._-]{1,128})(?=$|[\s"';&|)\]},:])/i)?.[1];
  if (ssh && isSafeProtectedFileName(ssh)) return `.ssh/${ssh}`;

  const aws = input.match(/\.aws[\\/]([A-Za-z0-9._-]{1,128})(?=$|[\s"';&|)\]},:])/i)?.[1];
  if (aws && isSafeProtectedFileName(aws)) return `.aws/${aws}`;

  const environment = input.match(
    /(?:^|[\s"'=([{,:])(?:[A-Za-z]:[\\/])?[\\/]?(?:[A-Za-z0-9_~.-]+[\\/])*(\.env(?:\.[A-Za-z0-9_-]{1,64})?)(?=$|[\s"';&|)\]},:])/i
  )?.[1];
  if (environment && isSafeProtectedFileName(environment)) return environment;

  const genericTarget = safeGenericProtectedTarget(event);
  if (genericTarget) return genericTarget;

  const credentials = input.match(
    /(?:^|[\\/\s"'=([{,:])(credentials[A-Za-z0-9._-]{0,96})(?=$|[\s"';&|)\]},:])/i
  )?.[1];
  if (credentials && isSafeProtectedFileName(credentials)) return credentials;

  const namedSecret = input.match(
    /(?:^|[\\/\s"'=([{,:])([A-Za-z0-9._-]{0,96}(?:private-key|seed)[A-Za-z0-9._-]{0,96})(?=$|[\s"';&|)\]},:])/i
  )?.[1];
  if (namedSecret && isSafeProtectedFileName(namedSecret)) return namedSecret;

  for (const reason of event.reasons) {
    if (reason.code !== 'SECRET_ACCESS' || !reason.evidence || /[*?\[\]]/.test(reason.evidence)) continue;
    const exactName = reason.evidence.split(/[\\/]/).at(-1);
    if (event.input.includes(reason.evidence) && exactName && isSafeProtectedFileName(exactName)) return exactName;
  }
  return undefined;
}

function safeGenericProtectedTarget(event: RuntimeAuditEvent): string | undefined {
  if (event.actionType === 'file_read') return safePathBasename(event.input);

  if (event.actionType === 'file_write') {
    const path = event.input.match(
      /["'](?:file_path|filePath|path|target)["']\s*:\s*["']([^"']+)["']/
    )?.[1];
    return path ? safePathBasename(path) : undefined;
  }

  if (event.actionType !== 'shell') return undefined;
  const command = safeShellCommandName(event.input);
  if (!command || !SINGLE_TARGET_FILE_COMMANDS.has(command)) return undefined;
  const firstCommand = event.input.split(/[;&|<>\r\n]/, 1)[0] ?? '';
  if (/\$\(|`|[()]/.test(firstCommand)) return undefined;
  const tokens = firstCommand.match(/"[^"]*"|'[^']*'|[^\s]+/g) ?? [];
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    const token = tokens[index]!.replace(/^["']|["']$/g, '');
    if (token.startsWith('-') || /^\d+$/.test(token)) continue;
    const name = safePathBasename(token);
    if (name && name.toLowerCase() !== command) return name;
  }
  return undefined;
}

function safePathBasename(value: string): string | undefined {
  const normalized = value.trim().replace(/^["']|["']$/g, '').replace(/[\\/]+$/, '');
  const name = normalized.split(/[\\/]/).at(-1);
  return name && isSafeProtectedFileName(name) ? name : undefined;
}

function isSafeProtectedFileName(value: string): boolean {
  return value !== '.'
    && value !== '..'
    && value.length <= 128
    && /^[A-Za-z0-9._-]+$/.test(value)
    && redactPreview(value, 128) === value;
}

function safeShellCommandName(input: string): string | undefined {
  const match = input.match(
    /^\s*(?:(?:sudo|env)\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*(?:\/[^\s/]+\/)*([A-Za-z][A-Za-z0-9_-]*)\b/
  );
  const command = match?.[1]?.toLowerCase();
  return command && SAFE_FILE_COMMANDS.has(command) ? command : undefined;
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

function sanitizePiiSummary(value: RuntimePiiSummary): RuntimePiiSummary {
  return {
    categories: value.categories.slice(0, 20).filter((item) =>
      PII_CATEGORIES.has(item.category)
      && Number.isSafeInteger(item.count)
      && item.count >= 0
    ).map((item) => ({ category: item.category, count: Math.min(item.count, 1_000_000) })),
    valueCount: Number.isSafeInteger(value.valueCount) && value.valueCount >= 0
      ? Math.min(value.valueCount, 1_000_000)
      : 0,
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
const PII_CATEGORIES = new Set<unknown>([
  'national_id', 'bank_account', 'biometric', 'minor_data', 'health_record',
  'location_trace', 'contact_dump', 'phone_number', 'email_address', 'hardcoded_dataset',
]);
const COVERAGE_LEVELS = new Set<unknown>(['full', 'partial', 'observe_only', 'unsupported']);
const MISSING_FACTS = new Set<unknown>([
  'complete_payload', 'complete_response', 'final_destination', 'credential_kind', 'credential_presence',
  'exact_payload_bytes', 'attachment_bytes', 'file_path_count', 'retry_and_fallback',
  'auxiliary_model_calls', 'response_source',
]);
const CODEX_DECISIONS = new Set<unknown>(['allow', 'warn', 'require_approval', 'block']);
const CODEX_SEVERITIES = new Set<unknown>(['info', 'low', 'medium', 'high', 'critical']);
const MATERIAL_POST_RISK_LEVELS = new Set<unknown>(['medium', 'high', 'critical']);
const MATERIAL_POST_SEVERITIES = new Set<unknown>(['medium', 'high', 'critical']);
const SAFE_RULE_ID = /^[A-Z][A-Z0-9_]{0,63}$/;
const SAFE_ID = /^[A-Za-z0-9_-]{1,160}$/;
const NATIVE_SENSITIVE_CONTENT_RULES = new Set([
  'PII_EGRESS', 'DATA_EXFILTRATION', 'LLM_KEY_TO_UNKNOWN_HOST',
  'WORKSPACE_BULK_EGRESS', 'DANGEROUS_CONFIG_CHANGE',
]);
const SAFE_FILE_COMMANDS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'grep', 'sed', 'awk',
  'cp', 'mv', 'rm', 'touch', 'chmod', 'chown', 'tee',
]);
const SINGLE_TARGET_FILE_COMMANDS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'rm', 'touch', 'chmod', 'chown',
]);

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
