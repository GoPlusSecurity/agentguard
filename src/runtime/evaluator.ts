import { ActionScanner } from '../action/index.js';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { DEFAULT_CAPABILITY } from '../types/skill.js';
import { domainMatchesPattern, extractDomain } from '../utils/patterns.js';
import { classifySystemPathOperation } from '../utils/system-paths.js';
import { getAgentGuardPaths } from '../config.js';
import type { ActionData, ActionEvidence, ActionType } from '../types/action.js';
import type {
  CloudPolicyDecision,
  EffectiveRuntimePolicy,
  PolicyReason,
  RuntimeAction,
  RuntimeDecision,
  RuntimeRiskLevel,
  RuntimeSeverity,
} from './types.js';
import { redactPreview, redactReasons } from './redaction.js';

const ONE_MINUTE_MS = 60_000;
const TEN_MINUTES_MS = 10 * ONE_MINUTE_MS;
const HIGH_FREQUENCY_THRESHOLD = 100;
const ODD_HOUR_FREQUENCY_THRESHOLD = 20;
const TOKEN_DOMAIN_THRESHOLD = 10;
const REPLAY_THRESHOLD = 5;
const DOS_STATUS_THRESHOLD = 5;
const SINGLE_RESPONSE_BYTES_THRESHOLD = 10 * 1024 * 1024;
const WINDOW_RESPONSE_BYTES_THRESHOLD = 100 * 1024 * 1024;
const MAX_PERSISTED_BEHAVIOR_EVENTS = 1_000;

interface NetworkTarget {
  hostname: string;
  pathname: string;
}

interface NetworkBehaviorEvent {
  timestamp: number;
  sessionId: string;
  hostname: string;
  method: string;
  fingerprint?: string;
  tokenHashes: string[];
  responseBytes?: number;
  responseStatus?: number;
}

export interface LocalActionEvaluationOptions {
  filesystemAllowlist?: string[];
}

const networkBehaviorEvents: NetworkBehaviorEvent[] = [];
let networkBehaviorStateLoaded = false;

export function __resetNetworkBehaviorForTests(): void {
  networkBehaviorEvents.length = 0;
  networkBehaviorStateLoaded = true;
  const statePath = process.env.AGENTGUARD_BEHAVIOR_STATE_PATH;
  if (statePath) {
    try {
      rmSync(statePath, { force: true });
    } catch {
      // Test cleanup only.
    }
  }
}

function reason(
  code: string,
  severity: RuntimeSeverity,
  title: string,
  description: string,
  evidence?: unknown
): PolicyReason {
  return {
    code,
    severity,
    title,
    description,
    evidence: evidence === undefined ? undefined : redactPreview(evidence, 240),
  };
}

export async function evaluateLocalAction(
  policy: EffectiveRuntimePolicy,
  action: RuntimeAction,
  options: LocalActionEvaluationOptions = {}
): Promise<RuntimeDecision> {
  if (isAllowedByCommandPolicy(policy, action)) {
    return {
      actionId: `act_local_${Date.now()}_${process.pid}`,
      decision: 'allow',
      riskScore: 0,
      riskLevel: 'safe',
      reasons: [],
      policyVersion: policy.policyVersion || 'runtime-local-v0.1',
    };
  }

  const customReasons = customPolicyReasons(policy, action);
  const ossDecision = await evaluateWithOssActionScanner(policy, action, options);
  const ossReasons = (ossDecision?.risk_tags || []).map((tag, index) =>
    normalizeOssReason(tag, ossDecision?.evidence?.[index], action)
  );
  const reasons = redactReasons([...customReasons, ...ossReasons]);
  const riskScore = riskScoreFor(reasons, ossDecision?.risk_level || 'safe');
  const riskLevel = riskLevelFor(riskScore);
  const decision = shouldAutoAllowRuntimeDecision(riskScore, riskLevel)
    ? 'allow'
    : decisionFor(policy, reasons, riskLevel, ossDecision?.decision);

  return {
    actionId: `act_local_${Date.now()}_${process.pid}`,
    decision: policy.mode === 'observe' && decision === 'block' ? 'warn' : decision,
    riskScore,
    riskLevel,
    reasons,
    policyVersion: policy.policyVersion || 'runtime-local-v0.1',
  };
}

function isAllowedByCommandPolicy(policy: EffectiveRuntimePolicy, action: RuntimeAction): boolean {
  if (action.actionType !== 'shell') return false;
  return policy.allowedCommandPatterns.some((pattern) => matchesAllowedCommand(action.input, pattern));
}

function customPolicyReasons(policy: EffectiveRuntimePolicy, action: RuntimeAction): PolicyReason[] {
  const reasons: PolicyReason[] = [];
  const input = action.input || '';
  const lower = input.toLowerCase();

  if (action.actionType === 'shell') {
    for (const pattern of policy.blockedCommandPatterns) {
      if (matchesPattern(lower, pattern.toLowerCase())) {
        reasons.push(reason(
          'CUSTOM_BLOCKED_COMMAND',
          'critical',
          'Custom blocked command',
          'The action matched a command pattern configured in runtime policy.',
          pattern
        ));
      }
    }
    for (const pathPattern of policy.protectedPaths) {
      if (matchesPath(input, pathPattern)) {
        reasons.push(reason(
          'SECRET_ACCESS',
          'high',
          'Protected path access',
          'The agent attempted to access a path protected by runtime policy.',
          pathPattern
        ));
      }
    }
    for (const domain of policy.network.blockedDomains) {
      if (domain && matchesNetworkReference(input, domain)) {
        reasons.push(reason(
          'CUSTOM_BLOCKED_DOMAIN',
          'high',
          'Custom blocked domain',
          'The action references a domain blocked by runtime policy.',
          domain
        ));
      }
    }
  }

  if (action.actionType === 'network' || action.actionType === 'browser') {
    for (const domain of policy.network.blockedDomains) {
      if (matchesNetworkTarget(input, domain)) {
        reasons.push(reason(
          'CUSTOM_BLOCKED_DOMAIN',
          'high',
          'Custom blocked domain',
          'The action references a domain blocked by runtime policy.',
          domain
        ));
      }
    }

    if (policy.network.defaultOutbound !== 'allow') {
      reasons.push(reason(
        'NETWORK_OUTBOUND',
        'medium',
        'Network outbound policy',
        'The action makes an outbound network request covered by runtime policy.',
        input
      ));
    }
  }

  const networkTargets = networkTargetsFromAction(action);
  if (networkTargets.length > 0) {
    reasons.push(...networkBehaviorReasons(action, networkTargets));
    reasons.push(...networkResponseReasons(action, networkTargets[0]));
  }

  if (action.actionType === 'file_read' || action.actionType === 'file_write') {
    const systemPathReason = systemPathReasonForFileAction(action);
    if (systemPathReason) reasons.push(systemPathReason);

    for (const pathPattern of policy.protectedPaths) {
      if (matchesPath(input, pathPattern)) {
        reasons.push(reason(
          'SECRET_ACCESS',
          action.actionType === 'file_write' ? 'critical' : 'high',
          'Protected path access',
          'The agent attempted to access a path protected by runtime policy.',
          pathPattern
        ));
      }
    }
  }

  if (action.actionType === 'deploy') {
    reasons.push(reason(
      'DEPLOYMENT_ACTION',
      'high',
      'Deployment action requires approval',
      'Deployment actions can affect production systems and should be approved in cloud policy.',
      input
    ));
  }

  return reasons;
}

function systemPathReasonForFileAction(action: RuntimeAction): PolicyReason | null {
  const operation = action.actionType === 'file_read' ? 'read' : 'write';
  const classification = classifySystemPathOperation(action.input, operation);
  if (!classification) return null;

  return reason(
    classification.decision === 'block' ? 'SYSTEM_PATH_MUTATION' : 'SYSTEM_PATH_ACCESS',
    classification.severity,
    classification.decision === 'block' ? 'System path mutation blocked' : 'System path access requires approval',
    `${operation} operation targets ${classification.description}.`,
    classification.path
  );
}

async function evaluateWithOssActionScanner(
  policy: EffectiveRuntimePolicy,
  action: RuntimeAction,
  options: LocalActionEvaluationOptions
) {
  const mapped = mapRuntimeAction(action);
  if (!mapped) return null;

  const runtimeCapabilities = {
    ...DEFAULT_CAPABILITY,
    exec: 'allow' as const,
    network_allowlist: policy.network.approvalDomains,
    filesystem_allowlist: runtimeFilesystemAllowlist(policy, options),
  };
  const registry = {
    async lookup() {
      return {
        record: null,
        effective_trust_level: 'trusted',
        effective_capabilities: runtimeCapabilities,
      };
    },
  };

  const scanner = new ActionScanner({
    registry: registry as never,
    defaultCapabilities: runtimeCapabilities,
  });
  return scanner.decide({
    actor: {
      skill: {
        id: action.sourceSkill || 'local-agent',
        source: action.agentHost,
        version_ref: 'runtime',
        artifact_hash: '',
      },
    },
    action: mapped,
    context: {
      session_id: action.sessionId,
      user_present: true,
      env: 'dev',
      time: new Date().toISOString(),
      initiating_skill: action.sourceSkill,
    },
  });
}

function runtimeFilesystemAllowlist(
  policy: EffectiveRuntimePolicy,
  options: LocalActionEvaluationOptions
): string[] {
  return options.filesystemAllowlist ?? policy.filesystemAllowlist ?? ['*'];
}

function mapRuntimeAction(action: RuntimeAction): { type: ActionType; data: ActionData } | null {
  if (action.actionType === 'shell') {
    return { type: 'exec_command', data: { command: action.input, cwd: action.cwd } };
  }
  if (action.actionType === 'file_read') {
    return { type: 'read_file', data: { path: action.input } };
  }
  if (action.actionType === 'file_write') {
    return { type: 'write_file', data: { path: action.input } };
  }
  if (action.actionType === 'web_search') {
    return { type: 'web_search', data: { query: action.input } };
  }
  if (action.actionType === 'network' || action.actionType === 'browser') {
    return {
      type: 'network_request',
      data: {
        method: methodFromMetadata(action.metadata?.method),
        url: action.input,
        body_preview: stringFromMetadata(action.metadata?.bodyPreview),
      },
    };
  }
  return null;
}

function methodFromMetadata(value: unknown): 'GET' | 'HEAD' | 'OPTIONS' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' {
  const method = typeof value === 'string' ? value.toUpperCase() : '';
  if (
    method === 'GET' ||
    method === 'HEAD' ||
    method === 'OPTIONS' ||
    method === 'POST' ||
    method === 'PUT' ||
    method === 'DELETE' ||
    method === 'PATCH'
  ) {
    return method;
  }
  return 'GET';
}

function stringFromMetadata(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function firstStringFromMetadata(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

function numberFromMetadata(...values: unknown[]): number | undefined {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim()) {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return undefined;
}

function timeFromMetadata(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function recordFromMetadata(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function normalizeOssReason(tag: string, evidence: ActionEvidence | undefined, action: RuntimeAction): PolicyReason {
  const evidenceText = evidence?.match || evidence?.description || action.input;
  if (tag === 'DANGEROUS_COMMAND') {
    return reason('DESTRUCTIVE_COMMAND', 'critical', 'Dangerous command', 'The local OSS runtime detected a dangerous command.', evidenceText);
  }
  if (tag === 'DESTRUCTIVE_FILE_OPERATION') {
    return reason('DESTRUCTIVE_FILE_OPERATION', 'high', 'Destructive file operation', 'The local OSS runtime detected a destructive file operation.', evidenceText);
  }
  if (tag === 'SYSTEM_PATH_MUTATION') {
    return reason('SYSTEM_PATH_MUTATION', 'critical', 'System path mutation', 'The local OSS runtime detected a mutation of a protected system path.', evidenceText);
  }
  if (tag === 'SYSTEM_PATH_ACCESS') {
    return reason('SYSTEM_PATH_ACCESS', 'high', 'System path access', 'The local OSS runtime detected access to a protected system path.', evidenceText);
  }
  if (tag === 'HIDDEN_NETWORK_COMMAND') {
    return reason('HIDDEN_NETWORK_COMMAND', 'high', 'Hidden network command', 'The local OSS runtime detected a network command hidden inside a wrapper.', evidenceText);
  }
  if (tag === 'REMOTE_SCRIPT_EXECUTION') {
    return reason('REMOTE_CODE_EXECUTION', 'high', 'Remote script execution', 'The local OSS runtime detected a remote script executed by a shell.', evidenceText);
  }
  if (tag === 'SUSPICIOUS_REMOTE_SCRIPT_EXECUTION') {
    return reason('REMOTE_CODE_EXECUTION', 'high', 'Suspicious remote script execution', 'The local OSS runtime detected a remote script executed by a shell with suspicious indicators.', evidenceText);
  }
  if (tag === 'MALICIOUS_REMOTE_SCRIPT_EXECUTION') {
    return reason('REMOTE_CODE_EXECUTION', 'critical', 'Malicious remote script execution', 'The local OSS runtime detected a remote script execution pattern with high-risk indicators.', evidenceText);
  }
  if (tag === 'SENSITIVE_DATA_ACCESS' || tag === 'SENSITIVE_ENV_VAR') {
    return reason('SECRET_ACCESS', 'high', 'Sensitive data access', 'The local OSS runtime detected access to sensitive data.', evidenceText);
  }
  if (tag === 'WEBHOOK_EXFIL' || tag === 'CRITICAL_SECRET_EXFIL' || tag === 'POTENTIAL_SECRET_EXFIL') {
    return reason('DATA_EXFILTRATION', tag === 'CRITICAL_SECRET_EXFIL' ? 'critical' : 'high', 'Potential data exfiltration', 'The local OSS runtime detected exfiltration risk.', evidenceText);
  }
  if (tag === 'NETWORK_COMMAND' || tag === 'UNTRUSTED_DOMAIN') {
    return reason('NETWORK_RISK', 'medium', 'Network action', 'The local OSS runtime detected network activity.', evidenceText);
  }
  if (tag === 'SHELL_INJECTION_RISK') {
    return reason('SHELL_INJECTION_RISK', 'low', 'Shell metacharacters', 'The local OSS runtime detected shell metacharacters.', evidenceText);
  }
  return reason(tag, 'medium', tag.replace(/_/g, ' ').toLowerCase(), 'The local OSS runtime detected a risky action.', evidenceText);
}

const BEHAVIOR_ANOMALY_CODES = new Set([
  'NETWORK_RATE_LIMIT',
  'NETWORK_TOKEN_DOMAIN_SWEEP',
  'NETWORK_ODD_HOUR_ACTIVITY',
  'NETWORK_REPLAY',
  'NETWORK_LARGE_RESPONSE',
  'NETWORK_DOS_RESPONSE',
]);

const RESPONSE_ANOMALY_CODES = new Set([
  'RESPONSE_XSS_ECHO',
  'RESPONSE_ERROR_DISCLOSURE',
  'RESPONSE_MALICIOUS_SCRIPT',
  'RESPONSE_PATH_TRAVERSAL',
  'RESPONSE_CONTENT_TYPE_MISMATCH',
  'RESPONSE_CREDENTIAL_ECHO',
]);

function networkTargetsFromAction(action: RuntimeAction): NetworkTarget[] {
  if (action.actionType === 'network' || action.actionType === 'browser') {
    const target = parseNetworkTarget(action.input);
    return target ? [target] : [];
  }
  if (action.actionType !== 'shell') return [];

  const targets = new Map<string, NetworkTarget>();
  for (const reference of extractNetworkReferences(action.input)) {
    const target = parseNetworkTarget(reference);
    if (target) targets.set(`${target.hostname}${target.pathname}`, target);
  }
  return [...targets.values()];
}

function networkBehaviorReasons(action: RuntimeAction, targets: NetworkTarget[]): PolicyReason[] {
  const timestamp = timeFromMetadata(action.metadata?.timestamp) ?? Date.now();
  loadNetworkBehaviorState(timestamp);
  pruneNetworkBehaviorEvents(timestamp);

  const method = methodFromMetadata(action.metadata?.method);
  const headers = recordFromMetadata(action.metadata?.headers) ?? recordFromMetadata(action.metadata?.requestHeaders);
  const bodyPreview = stringFromMetadata(action.metadata?.bodyPreview);
  const responseBytes = numberFromMetadata(
    action.metadata?.responseBodyBytes,
    action.metadata?.responseBytes,
    action.metadata?.contentLength
  );
  const responseStatus = numberFromMetadata(
    action.metadata?.responseStatusCode,
    action.metadata?.statusCode,
    action.metadata?.status
  );
  const tokenHashes = extractCredentialValues(action.input, headers, bodyPreview).map(hashValue);
  const fingerprint = requestFingerprint(action.input, targets[0], method, headers, bodyPreview);

  for (const target of targets) {
    networkBehaviorEvents.push({
      timestamp,
      sessionId: action.sessionId,
      hostname: target.hostname,
      method,
      fingerprint,
      tokenHashes,
      responseBytes,
      responseStatus,
    });
  }

  const reasons: PolicyReason[] = [];
  const sessionRecent = networkBehaviorEvents.filter((event) =>
    event.sessionId === action.sessionId &&
    timestamp - event.timestamp <= ONE_MINUTE_MS
  );

  if (sessionRecent.length > HIGH_FREQUENCY_THRESHOLD) {
    reasons.push(reason(
      'NETWORK_RATE_LIMIT',
      'high',
      'High-frequency network activity',
      'The agent made more than 100 outbound requests in one minute.',
      `${sessionRecent.length} requests in 60s`
    ));
  }

  if (isOddHour(timestamp) && sessionRecent.length > ODD_HOUR_FREQUENCY_THRESHOLD) {
    reasons.push(reason(
      'NETWORK_ODD_HOUR_ACTIVITY',
      'high',
      'Odd-hour network burst',
      'The agent made a high-frequency network burst during the 02:00-06:00 local risk window.',
      `${sessionRecent.length} requests in 60s`
    ));
  }

  if (fingerprint) {
    const repeats = sessionRecent.filter((event) => event.fingerprint === fingerprint).length;
    if (repeats >= REPLAY_THRESHOLD) {
      reasons.push(reason(
        'NETWORK_REPLAY',
        'high',
        'Repeated identical request',
        'The same request body and headers appeared repeatedly in a short window.',
        `${repeats} repeats in 60s`
      ));
    }
  }

  for (const tokenHash of tokenHashes) {
    const domains = new Set(
      networkBehaviorEvents
        .filter((event) =>
          event.sessionId === action.sessionId &&
          timestamp - event.timestamp <= TEN_MINUTES_MS &&
          event.tokenHashes.includes(tokenHash)
        )
        .map((event) => event.hostname)
    );
    if (domains.size > TOKEN_DOMAIN_THRESHOLD) {
      reasons.push(reason(
        'NETWORK_TOKEN_DOMAIN_SWEEP',
        'high',
        'Credential used across many domains',
        'The same credential-like value was used against more than 10 distinct domains.',
        `${domains.size} domains in 10m`
      ));
      break;
    }
  }

  const responseBytesTotal = sessionRecent.reduce((total, event) => total + (event.responseBytes ?? 0), 0);
  if (
    (responseBytes !== undefined && responseBytes > SINGLE_RESPONSE_BYTES_THRESHOLD) ||
    responseBytesTotal > WINDOW_RESPONSE_BYTES_THRESHOLD
  ) {
    reasons.push(reason(
      'NETWORK_LARGE_RESPONSE',
      'high',
      'Large network response volume',
      'The network response volume crossed the runtime anomaly threshold.',
      responseBytes !== undefined ? `${responseBytes} bytes` : `${responseBytesTotal} bytes in 60s`
    ));
  }

  if (responseStatus === 429 || responseStatus === 503) {
    const statusRepeats = sessionRecent.filter((event) => event.responseStatus === responseStatus).length;
    if (statusRepeats >= DOS_STATUS_THRESHOLD) {
      reasons.push(reason(
        'NETWORK_DOS_RESPONSE',
        'high',
        'Repeated throttling or service unavailable responses',
        'The agent received repeated 429/503 responses in a short window.',
        `${statusRepeats} responses with status ${responseStatus} in 60s`
      ));
    }
  }

  saveNetworkBehaviorState();
  return dedupeReasons(reasons);
}

function networkResponseReasons(action: RuntimeAction, target: NetworkTarget): PolicyReason[] {
  const responseBody = firstStringFromMetadata(
    action.metadata?.responseBodyPreview,
    action.metadata?.responsePreview,
    action.metadata?.responseBody
  );
  const responseHeaders = recordFromMetadata(action.metadata?.responseHeaders);
  const contentType = (firstStringFromMetadata(
    action.metadata?.responseContentType,
    contentTypeFromHeaders(responseHeaders)
  ) ?? '').toLowerCase();

  if (!responseBody) return [];

  const reasons: PolicyReason[] = [];
  if (hasSuspiciousXssResponse(responseBody)) {
    reasons.push(reason(
      'RESPONSE_XSS_ECHO',
      'high',
      'Executable markup in response',
      'The network response contains script-like markup or JavaScript URL content.',
      target.hostname
    ));
  }

  if (/sql syntax|mysql_fetch|postgresql|ora-\d+|traceback|stack trace|exception|at .+:\d+:\d+/i.test(responseBody)) {
    reasons.push(reason(
      'RESPONSE_ERROR_DISCLOSURE',
      'high',
      'Server error disclosure in response',
      'The network response contains SQL, command, or stack-trace style error output.',
      target.hostname
    ));
  }

  if (/eval\s*\(\s*(?:atob|unescape)|fromcharcode|document\.write\s*\(/i.test(responseBody)) {
    reasons.push(reason(
      'RESPONSE_MALICIOUS_SCRIPT',
      'critical',
      'Obfuscated script in response',
      'The network response contains script patterns commonly used for payload staging.',
      target.hostname
    ));
  }

  if (/root:.*:0:0:|\/etc\/passwd|c:\\windows\\|windows\\system32/i.test(responseBody)) {
    reasons.push(reason(
      'RESPONSE_PATH_TRAVERSAL',
      'critical',
      'Path traversal content in response',
      'The network response contains filesystem markers associated with traversal or local file disclosure.',
      target.hostname
    ));
  }

  if (contentType && isBinaryOrMediaContentType(contentType) && looksLikeHtmlOrScript(responseBody)) {
    reasons.push(reason(
      'RESPONSE_CONTENT_TYPE_MISMATCH',
      'critical',
      'Response content type mismatch',
      'The response body looks executable or HTML-like while the Content-Type claims binary/media content.',
      target.hostname
    ));
  }

  const requestSecrets = extractCredentialValues(
    action.input,
    recordFromMetadata(action.metadata?.headers) ?? recordFromMetadata(action.metadata?.requestHeaders),
    stringFromMetadata(action.metadata?.bodyPreview)
  );
  if (requestSecrets.some((secret) => secret.length >= 8 && responseBody.includes(secret))) {
    reasons.push(reason(
      'RESPONSE_CREDENTIAL_ECHO',
      'critical',
      'Credential echoed in response',
      'The response appears to echo a credential-like value from the request.',
      target.hostname
    ));
  }

  return dedupeReasons(reasons);
}

function decisionFor(
  policy: EffectiveRuntimePolicy,
  reasons: PolicyReason[],
  riskLevel: RuntimeRiskLevel,
  ossDecision?: string
): CloudPolicyDecision {
  const policyDecisions: CloudPolicyDecision[] = [];
  for (const item of reasons) {
    const decision = policyDecisionFor(item, policy);
    if (decision) policyDecisions.push(decision);
  }
  const strongestPolicyDecision = strongestDecision(policyDecisions);
  const scannerDecision = scannerPolicyDecision(ossDecision, riskLevel);
  if (strongestPolicyDecision) {
    if (
      scannerDecision &&
      DECISION_ORDER[strongestPolicyDecision] <= DECISION_ORDER.warn &&
      DECISION_ORDER[scannerDecision] > DECISION_ORDER[strongestPolicyDecision]
    ) {
      return scannerDecision;
    }
    return strongestPolicyDecision;
  }
  if (scannerDecision) return scannerDecision;
  if (reasons.length > 0) return 'warn';
  return 'allow';
}

function policyDecisionFor(reasonItem: PolicyReason, policy: EffectiveRuntimePolicy): CloudPolicyDecision | null {
  const code = reasonItem.code;
  if (code === 'CUSTOM_BLOCKED_COMMAND' || code === 'DESTRUCTIVE_COMMAND') return policy.decisions.destructiveCommand;
  if (code === 'DESTRUCTIVE_FILE_OPERATION') return 'require_approval';
  if (code === 'SYSTEM_PATH_MUTATION') return 'block';
  if (code === 'SYSTEM_PATH_ACCESS') return 'require_approval';
  if (code === 'HIDDEN_NETWORK_COMMAND') return 'require_approval';
  if (code === 'REMOTE_CODE_EXECUTION') return reasonItem.severity === 'critical' ? 'block' : policy.decisions.remoteCodeExecution;
  if (code === 'CUSTOM_BLOCKED_DOMAIN' || code === 'DATA_EXFILTRATION') return policy.decisions.dataExfiltration;
  if (code === 'NETWORK_OUTBOUND') return policy.network.defaultOutbound;
  if (BEHAVIOR_ANOMALY_CODES.has(code)) return policy.network.behaviorAnomaly ?? 'require_approval';
  if (RESPONSE_ANOMALY_CODES.has(code)) {
    return policy.network.responseAnomaly ?? (reasonItem.severity === 'critical' ? 'block' : 'require_approval');
  }
  if (code === 'SECRET_ACCESS') return policy.decisions.secretAccess;
  if (code === 'DEPLOYMENT_ACTION') return policy.decisions.deployAction;
  return null;
}

const DECISION_ORDER: Record<CloudPolicyDecision, number> = {
  allow: 0,
  warn: 1,
  require_approval: 2,
  block: 3,
};

function strongestDecision(decisions: CloudPolicyDecision[]): CloudPolicyDecision | null {
  let strongest: CloudPolicyDecision | null = null;
  for (const decision of decisions) {
    if (!strongest || DECISION_ORDER[decision] > DECISION_ORDER[strongest]) strongest = decision;
  }
  return strongest;
}

function scannerPolicyDecision(ossDecision: string | undefined, riskLevel: RuntimeRiskLevel): CloudPolicyDecision | null {
  if (ossDecision === 'deny') return riskLevel === 'critical' ? 'block' : 'require_approval';
  if (ossDecision === 'confirm') return 'require_approval';
  return null;
}

function riskScoreFor(reasons: PolicyReason[], ossRiskLevel: RuntimeRiskLevel): number {
  if (reasons.some((item) => item.severity === 'critical') || ossRiskLevel === 'critical') return 95;
  if (reasons.some((item) => item.severity === 'high') || ossRiskLevel === 'high') return 55;
  if (reasons.some((item) => item.severity === 'medium') || ossRiskLevel === 'medium') return 20;
  if (reasons.length > 0 || ossRiskLevel === 'low') return reasons.length > 0 ? 10 : 0;
  return 0;
}

function riskLevelFor(score: number): RuntimeRiskLevel {
  if (score >= 90) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 20) return 'medium';
  if (score > 0) return 'low';
  return 'safe';
}

function shouldAutoAllowRuntimeDecision(riskScore: number, riskLevel: RuntimeRiskLevel): boolean {
  return riskScore < 20 || riskLevel === 'safe';
}

function matchesPattern(input: string, pattern: string): boolean {
  if (!pattern) return false;
  if (isRootRmRfPattern(pattern)) return isRootRmRfCommand(input);
  if (input.includes(pattern)) return true;
  const compact = pattern.replace(/\s*\.\.\.\s*/g, ' ');
  return compact !== pattern && input.includes(compact);
}

function isRootRmRfPattern(pattern: string): boolean {
  return /^rm\s+-[^\s]*r[^\s]*f[^\s]*\s+\/$/.test(pattern) ||
    /^rm\s+-[^\s]*f[^\s]*r[^\s]*\s+\/$/.test(pattern);
}

function isRootRmRfCommand(input: string): boolean {
  const normalized = normalizeCommand(input);
  return /^rm\s+-[^\s]*r[^\s]*f[^\s]*\s+\/\s*$/.test(normalized) ||
    /^rm\s+-[^\s]*f[^\s]*r[^\s]*\s+\/\s*$/.test(normalized);
}

function matchesAllowedCommand(input: string, pattern: string): boolean {
  const trimmedInput = input.trim();
  const trimmedPattern = pattern.trim();
  if (!trimmedInput || !trimmedPattern) return false;

  const inputHasControl = hasShellControl(trimmedInput);
  const patternHasControl = hasShellControl(trimmedPattern);
  if (inputHasControl && !patternHasControl) return false;

  const normalizedInput = normalizeCommand(trimmedInput);
  const normalizedPattern = normalizeCommand(trimmedPattern);
  if (normalizedPattern === '*') return true;
  if (/[?*]/.test(normalizedPattern) || normalizedPattern.includes('...')) {
    const regex = new RegExp(`^${globCommandToRegexSource(normalizedPattern)}$`);
    return regex.test(normalizedInput);
  }

  return normalizedInput === normalizedPattern ||
    (!inputHasControl && normalizedInput.startsWith(`${normalizedPattern} `));
}

function matchesNetworkTarget(input: string, pattern: string): boolean {
  const target = parseNetworkTarget(input);
  const matcher = parseNetworkPattern(pattern);
  if (!target || !matcher) return false;

  if (!domainMatchesPattern(target.hostname, matcher.hostname)) return false;
  if (!matcher.pathname) return true;

  return target.pathname === matcher.pathname ||
    target.pathname.startsWith(`${matcher.pathname.replace(/\/+$/, '')}/`);
}

function matchesNetworkReference(input: string, pattern: string): boolean {
  if (matchesNetworkTarget(input, pattern)) return true;
  return extractNetworkReferences(input).some((reference) => matchesNetworkTarget(reference, pattern));
}

function parseNetworkTarget(value: string): NetworkTarget | null {
  const trimmed = trimNetworkToken(value);
  if (!trimmed) return null;
  const urlLike = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(urlLike);
    return {
      hostname: parsed.hostname.toLowerCase(),
      pathname: normalizeNetworkPath(parsed.pathname),
    };
  } catch {
    return null;
  }
}

function parseNetworkPattern(value: string): { hostname: string; pathname: string | null } | null {
  const trimmed = trimNetworkToken(value).toLowerCase();
  if (!trimmed) return null;
  const urlLike = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  try {
    const parsed = new URL(urlLike);
    return {
      hostname: parsed.hostname.toLowerCase(),
      pathname: parsed.pathname && parsed.pathname !== '/' ? normalizeNetworkPath(parsed.pathname) : null,
    };
  } catch {
    return null;
  }
}

function extractNetworkReferences(input: string): string[] {
  const references = new Set<string>();
  for (const match of input.matchAll(/https?:\/\/[^\s'"<>`]+/gi)) {
    references.add(trimNetworkToken(match[0]));
  }
  for (const match of input.matchAll(/\b[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}(?:\/[^\s'"<>`]*)?/gi)) {
    references.add(trimNetworkToken(match[0]));
  }
  return [...references].filter(Boolean);
}

function trimNetworkToken(value: string): string {
  return value.trim().replace(/[),.;\]]+$/g, '');
}

function normalizeNetworkPath(pathname: string): string {
  if (!pathname || pathname === '/') return '/';
  return pathname.replace(/\/+$/g, '') || '/';
}

function behaviorStatePath(): string {
  return process.env.AGENTGUARD_BEHAVIOR_STATE_PATH ||
    join(getAgentGuardPaths().home, 'network-behavior.json');
}

function loadNetworkBehaviorState(now: number): void {
  if (networkBehaviorStateLoaded) return;
  networkBehaviorStateLoaded = true;
  const statePath = behaviorStatePath();
  try {
    if (!existsSync(statePath)) return;
    const parsed = JSON.parse(readFileSync(statePath, 'utf8')) as unknown;
    if (!Array.isArray(parsed)) return;
    const events: NetworkBehaviorEvent[] = [];
    for (const item of parsed) {
      const event = parseNetworkBehaviorEvent(item);
      if (event && now - event.timestamp <= TEN_MINUTES_MS) events.push(event);
    }
    networkBehaviorEvents.push(...events);
  } catch {
    networkBehaviorEvents.length = 0;
  }
}

function saveNetworkBehaviorState(): void {
  const statePath = behaviorStatePath();
  try {
    mkdirSync(dirname(statePath), { recursive: true, mode: 0o700 });
    const events = networkBehaviorEvents.slice(-MAX_PERSISTED_BEHAVIOR_EVENTS);
    writeFileSync(statePath, `${JSON.stringify(events)}\n`, { mode: 0o600 });
    chmodSync(statePath, 0o600);
  } catch {
    // Behavior state is best-effort; runtime protection still works without it.
  }
}

function parseNetworkBehaviorEvent(value: unknown): NetworkBehaviorEvent | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (
    typeof record.timestamp !== 'number' ||
    typeof record.sessionId !== 'string' ||
    typeof record.hostname !== 'string' ||
    typeof record.method !== 'string'
  ) {
    return null;
  }
  return {
    timestamp: record.timestamp,
    sessionId: record.sessionId,
    hostname: record.hostname,
    method: record.method,
    fingerprint: typeof record.fingerprint === 'string' ? record.fingerprint : undefined,
    tokenHashes: Array.isArray(record.tokenHashes)
      ? record.tokenHashes.filter((item): item is string => typeof item === 'string')
      : [],
    responseBytes: typeof record.responseBytes === 'number' ? record.responseBytes : undefined,
    responseStatus: typeof record.responseStatus === 'number' ? record.responseStatus : undefined,
  };
}

function pruneNetworkBehaviorEvents(now: number): void {
  const cutoff = now - TEN_MINUTES_MS;
  while (networkBehaviorEvents.length > 0 && networkBehaviorEvents[0].timestamp < cutoff) {
    networkBehaviorEvents.shift();
  }
}

function isOddHour(timestamp: number): boolean {
  const hour = new Date(timestamp).getHours();
  return hour >= 2 && hour < 6;
}

function requestFingerprint(
  input: string,
  target: NetworkTarget,
  method: string,
  headers: Record<string, unknown> | undefined,
  bodyPreview: string | undefined
): string | undefined {
  if (!headers && !bodyPreview) return undefined;
  return hashValue(JSON.stringify({
    method,
    host: target.hostname,
    path: target.pathname,
    input,
    headers: stableRecordString(headers),
    bodyPreview,
  }));
}

function extractCredentialValues(
  input: string,
  headers: Record<string, unknown> | undefined,
  bodyPreview: string | undefined
): string[] {
  const values = new Set<string>();
  collectUrlCredentialValues(input, values);

  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      if (!/(authorization|api[-_]?key|access[-_]?token|token|secret)/i.test(key)) continue;
      const text = Array.isArray(value) ? value.join(',') : String(value ?? '');
      for (const item of text.matchAll(/[A-Za-z0-9._~+/=-]{8,}/g)) {
        values.add(item[0]);
      }
    }
  }

  if (bodyPreview) {
    for (const match of bodyPreview.matchAll(/(?:api[-_]?key|access[-_]?token|token|authorization|secret)["':=\s]+([A-Za-z0-9._~+/=-]{8,})/gi)) {
      values.add(match[1]);
    }
  }

  return [...values];
}

function collectUrlCredentialValues(input: string, values: Set<string>): void {
  for (const reference of extractNetworkReferences(input).length > 0 ? extractNetworkReferences(input) : [input]) {
    const token = trimNetworkToken(reference);
    if (!token) continue;
    const urlLike = /^[a-z][a-z0-9+.-]*:\/\//i.test(token) ? token : `https://${token}`;
    try {
      const parsed = new URL(urlLike);
      for (const [key, value] of parsed.searchParams.entries()) {
        if (/(api[-_]?key|access[-_]?token|token|authorization|secret|auth|key)/i.test(key) && value.length >= 8) {
          values.add(value);
        }
      }
    } catch {
      // Ignore malformed references.
    }
  }
}

function stableRecordString(record: Record<string, unknown> | undefined): string | undefined {
  if (!record) return undefined;
  return Object.keys(record)
    .sort((a, b) => a.localeCompare(b))
    .map((key) => `${key.toLowerCase()}:${String(record[key])}`)
    .join('\n');
}

function hashValue(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function contentTypeFromHeaders(headers: Record<string, unknown> | undefined): string | undefined {
  if (!headers) return undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === 'content-type' && typeof value === 'string') return value;
  }
  return undefined;
}

function isBinaryOrMediaContentType(contentType: string): boolean {
  return /^(image|audio|video)\//i.test(contentType) ||
    /application\/(?:octet-stream|pdf|zip|gzip|x-tar)/i.test(contentType);
}

function hasSuspiciousXssResponse(body: string): boolean {
  return /javascript:\s*(?:alert|confirm|prompt|eval|fetch|\w+\()/i.test(body) ||
    /on(?:error|load|click|mouseover|focus)\s*=\s*["']?(?:alert|confirm|prompt|eval|fetch|javascript:)/i.test(body) ||
    /<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]{0,500}?(?:alert|confirm|prompt|document\.cookie|localStorage|eval|fetch\s*\()/i.test(body);
}

function looksLikeHtmlOrScript(body: string): boolean {
  return /^\s*(?:<!doctype\s+html|<html\b|<script\b)/i.test(body) ||
    /javascript:|<script\b/i.test(body);
}

function dedupeReasons(items: PolicyReason[]): PolicyReason[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.code)) return false;
    seen.add(item.code);
    return true;
  });
}

function normalizeCommand(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase();
}

function hasShellControl(command: string): boolean {
  return /[;&|<>`\n\r\t]|\$\(/.test(command);
}

function globCommandToRegexSource(pattern: string): string {
  const normalized = pattern.replace(/\s*\.\.\.\s*/g, ' * ');
  let source = '';
  for (const char of normalized) {
    if (char === '*') source += '.*';
    else if (char === '?') source += '.';
    else source += escapeRegex(char);
  }
  return source;
}

function matchesPath(input: string, pattern: string): boolean {
  if (!pattern) return false;
  const normalizedInput = normalizePathLike(input);
  return expandHomePattern(pattern).map(normalizePathLike).some((candidate) => {
    if (!candidate) return false;
    if (!candidate.includes('*')) {
      return normalizedInput.includes(candidate);
    }
    return new RegExp(globToRegexSource(candidate)).test(normalizedInput);
  });
}

function normalizePathLike(value: string): string {
  return value.replace(/\\/g, '/');
}

function expandHomePattern(pattern: string): string[] {
  if (!pattern.startsWith('~/')) {
    return [pattern];
  }
  return [pattern, `${homedir().replace(/\\/g, '/')}/${pattern.slice(2)}`];
}

function globToRegexSource(pattern: string): string {
  let source = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === '*') {
      if (pattern[index + 1] === '*') {
        source += '.*';
        index += 1;
      } else {
        source += '[^/\\s\'"]*';
      }
      continue;
    }
    source += escapeRegex(char);
  }
  return source;
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}
