import { ActionScanner } from '../action/index.js';
import { homedir } from 'node:os';
import { DEFAULT_CAPABILITY } from '../types/skill.js';
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
  action: RuntimeAction
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
  const ossDecision = await evaluateWithOssActionScanner(policy, action);
  const ossReasons = (ossDecision?.risk_tags || []).map((tag, index) =>
    normalizeOssReason(tag, ossDecision?.evidence?.[index], action)
  );
  const reasons = redactReasons([...customReasons, ...ossReasons]);
  const riskScore = riskScoreFor(reasons, ossDecision?.risk_level || 'safe');
  const riskLevel = riskLevelFor(riskScore);
  const decision = decisionFor(policy, reasons, riskLevel, ossDecision?.decision);

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
      if (domain && lower.includes(domain.toLowerCase())) {
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

  if (action.actionType === 'file_read' || action.actionType === 'file_write') {
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

async function evaluateWithOssActionScanner(
  policy: EffectiveRuntimePolicy,
  action: RuntimeAction
) {
  const mapped = mapRuntimeAction(action);
  if (!mapped) return null;

  const registry = {
    async lookup() {
      return {
        record: null,
        effective_trust_level: 'trusted',
        effective_capabilities: {
          ...DEFAULT_CAPABILITY,
          exec: 'allow' as const,
          network_allowlist: policy.network.approvalDomains,
          filesystem_allowlist: policy.protectedPaths,
        },
      };
    },
  };

  const scanner = new ActionScanner({ registry: registry as never });
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
  if (action.actionType === 'network' || action.actionType === 'browser') {
    return { type: 'network_request', data: { method: 'GET', url: action.input } };
  }
  return null;
}

function normalizeOssReason(tag: string, evidence: ActionEvidence | undefined, action: RuntimeAction): PolicyReason {
  const evidenceText = evidence?.match || evidence?.description || action.input;
  if (tag === 'DANGEROUS_COMMAND') {
    return reason('DESTRUCTIVE_COMMAND', 'critical', 'Dangerous command', 'The local OSS runtime detected a dangerous command.', evidenceText);
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
    return reason('SHELL_INJECTION_RISK', 'medium', 'Shell metacharacters', 'The local OSS runtime detected shell metacharacters.', evidenceText);
  }
  return reason(tag, 'medium', tag.replace(/_/g, ' ').toLowerCase(), 'The local OSS runtime detected a risky action.', evidenceText);
}

function decisionFor(
  policy: EffectiveRuntimePolicy,
  reasons: PolicyReason[],
  riskLevel: RuntimeRiskLevel,
  ossDecision?: string
): CloudPolicyDecision {
  for (const item of reasons) {
    const decision = policyDecisionFor(item.code, policy);
    if (decision) return decision;
  }
  if (ossDecision === 'deny') return riskLevel === 'critical' ? 'block' : 'require_approval';
  if (ossDecision === 'confirm') return 'require_approval';
  if (reasons.length > 0) return 'warn';
  return 'allow';
}

function policyDecisionFor(code: string, policy: EffectiveRuntimePolicy): CloudPolicyDecision | null {
  if (code === 'CUSTOM_BLOCKED_COMMAND' || code === 'DESTRUCTIVE_COMMAND') return policy.decisions.destructiveCommand;
  if (code === 'REMOTE_CODE_EXECUTION') return policy.decisions.remoteCodeExecution;
  if (code === 'CUSTOM_BLOCKED_DOMAIN' || code === 'DATA_EXFILTRATION') return policy.decisions.dataExfiltration;
  if (code === 'SECRET_ACCESS') return policy.decisions.secretAccess;
  if (code === 'DEPLOYMENT_ACTION') return policy.decisions.deployAction;
  return null;
}

function riskScoreFor(reasons: PolicyReason[], ossRiskLevel: RuntimeRiskLevel): number {
  if (reasons.some((item) => item.severity === 'critical') || ossRiskLevel === 'critical') return 95;
  if (reasons.some((item) => item.severity === 'high') || ossRiskLevel === 'high') return 55;
  if (reasons.some((item) => item.severity === 'medium') || ossRiskLevel === 'medium') return 20;
  if (reasons.length > 0 || ossRiskLevel === 'low') return reasons.length > 0 ? 5 : 0;
  return 0;
}

function riskLevelFor(score: number): RuntimeRiskLevel {
  if (score >= 90) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 20) return 'medium';
  if (score > 0) return 'low';
  return 'safe';
}

function matchesPattern(input: string, pattern: string): boolean {
  if (!pattern) return false;
  if (input.includes(pattern)) return true;
  const compact = pattern.replace(/\s*\.\.\.\s*/g, ' ');
  return compact !== pattern && input.includes(compact);
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
