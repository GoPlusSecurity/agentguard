import type { RuntimeDecision } from '../runtime/types.js';
import type {
  DshPostToolDecision,
  DshPreToolDecision,
} from './runtime.js';

const MAX_REASON_CODES = 5;
const MAX_REASON_LENGTH = 500;

/**
 * Translate a shared AgentGuard decision into DSH's native pre-execute
 * vocabulary. Returning `ask` delegates approval and its audit pair to DSH.
 * This function does not register a listener or apply the decision.
 */
export function translateDshPreDecision(decision: RuntimeDecision): DshPreToolDecision {
  if (decision.decision === 'allow' || decision.decision === 'warn') {
    return { kind: 'allow' };
  }
  const reason = formatDshPolicyReason(decision);
  return decision.decision === 'require_approval'
    ? { kind: 'ask', reason }
    : { kind: 'deny', reason };
}

/**
 * Translate post-response policy into DSH result containment. The live
 * protector invokes this only for block-class results. Direct approval-class
 * translation remains available to model the future held-result contract.
 */
export function translateDshPostDecision(decision: RuntimeDecision): DshPostToolDecision {
  if (decision.decision === 'allow' || decision.decision === 'warn') {
    return { kind: 'accept' };
  }
  return {
    kind: 'block',
    feedback: [{ type: 'text', text: formatDshPolicyReason(decision) }],
  };
}

/** Preserve the strongest result when AgentGuard composes with other policies. */
export function mergeDshPreDecisions(
  agentguard: DshPreToolDecision,
  downstream: DshPreToolDecision
): DshPreToolDecision {
  const rank = { allow: 0, ask: 1, deny: 2 } as const;
  return rank[downstream.kind] >= rank[agentguard.kind] ? downstream : agentguard;
}

/** A downstream block is never weakened by an AgentGuard accept. */
export function mergeDshPostDecisions(
  agentguard: DshPostToolDecision,
  downstream: DshPostToolDecision
): DshPostToolDecision {
  if (downstream.kind === 'block') return downstream;
  return agentguard.kind === 'block' ? agentguard : downstream;
}

/** Render only bounded policy metadata; raw input and reason evidence stay out. */
export function formatDshPolicyReason(decision: RuntimeDecision): string {
  const codes = [...new Set(
    decision.reasons
      .map(item => safePolicyToken(item.code, 64))
      .filter(code => code.length > 0)
  )].slice(0, MAX_REASON_CODES);
  const action = decision.decision === 'block' ? 'blocked' : 'requires approval';
  const suffix = codes.length > 0 ? ` Reasons: ${codes.join(', ')}.` : '';
  const riskScore = Number.isFinite(decision.riskScore)
    ? Math.max(0, Math.min(100, Math.round(decision.riskScore)))
    : 100;
  const riskLevel = safePolicyToken(decision.riskLevel, 16) || 'unknown';
  const policyVersion = safePolicyToken(decision.policyVersion, 64) || 'unknown';
  return `AgentGuard ${action} this tool call (risk ${riskScore}/100, ${riskLevel}; policy ${policyVersion}).${suffix}`
    .slice(0, MAX_REASON_LENGTH);
}

function safePolicyToken(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') return '';
  return value.replace(/[^A-Za-z0-9._:-]+/g, '_').slice(0, maxLength);
}
