import type { RuntimeEvaluation } from '../runtime/decision.js';
import type {
  CloudPolicyDecision,
  PolicyReason,
  RuntimeAction,
  RuntimeRiskLevel,
} from '../runtime/types.js';

export interface DshOwnerPolicy {
  /** A monotonic floor: owner policy may strengthen, never weaken, shared policy. */
  readonly minimumDecision: CloudPolicyDecision;
}

export type DshOwnerPolicies = Readonly<Record<string, DshOwnerPolicy>>;

const RANK: Record<CloudPolicyDecision, number> = {
  allow: 0,
  warn: 1,
  require_approval: 2,
  block: 3,
};

const RISK_FLOOR: Record<CloudPolicyDecision, { score: number; level: RuntimeRiskLevel }> = {
  allow: { score: 0, level: 'safe' },
  warn: { score: 20, level: 'medium' },
  require_approval: { score: 55, level: 'high' },
  block: { score: 95, level: 'critical' },
};

const OWNER_ID_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9@._/:-]{0,159}$/;
const MAX_OWNER_POLICIES = 500;

/** Validate and snapshot monotonic owner policy configuration. */
export function normalizeDshOwnerPolicies(value: unknown): DshOwnerPolicies {
  if (value === undefined) return {};
  if (!isRecord(value)) throw new Error('AgentGuard DSH runtime ownerPolicies must be an object');
  const entries = Object.entries(value);
  if (entries.length > MAX_OWNER_POLICIES) {
    throw new Error(`AgentGuard DSH runtime ownerPolicies supports at most ${MAX_OWNER_POLICIES} entries`);
  }
  const normalized: Record<string, DshOwnerPolicy> = Object.create(null) as Record<string, DshOwnerPolicy>;
  for (const [owner, rawPolicy] of entries) {
    if (!OWNER_ID_PATTERN.test(owner)) {
      throw new Error(`invalid AgentGuard DSH owner policy id ${JSON.stringify(owner)}`);
    }
    if (!isRecord(rawPolicy) || !isDecision(rawPolicy.minimumDecision)) {
      throw new Error(`AgentGuard DSH owner policy ${JSON.stringify(owner)} requires minimumDecision`);
    }
    normalized[owner] = { minimumDecision: rawPolicy.minimumDecision };
  }
  return normalized;
}

/** Apply an attributed owner's decision floor without weakening shared policy. */
export function applyDshOwnerPolicy(
  evaluation: RuntimeEvaluation,
  action: RuntimeAction,
  policies: DshOwnerPolicies = {}
): RuntimeEvaluation {
  if (action.metadata?.sourceAttribution !== 'configured-tool-owner') return evaluation;
  const owner = action.metadata?.sourceOwner;
  if (typeof owner !== 'string' || !Object.hasOwn(policies, owner)) return evaluation;
  const minimumDecision = policies[owner]?.minimumDecision;
  if (!minimumDecision || RANK[minimumDecision] <= RANK[evaluation.decision.decision]) return evaluation;

  const floor = RISK_FLOOR[minimumDecision];
  const reason: PolicyReason = {
    code: 'DSH_OWNER_POLICY',
    severity: minimumDecision === 'block' ? 'critical'
      : minimumDecision === 'require_approval' ? 'high'
        : 'medium',
    title: 'DSH plugin owner policy',
    description: `Operator policy requires at least ${minimumDecision} for attributed owner ${owner}.`,
  };
  return {
    ...evaluation,
    decision: {
      ...evaluation.decision,
      decision: minimumDecision,
      riskScore: Math.max(evaluation.decision.riskScore, floor.score),
      riskLevel: strongerRiskLevel(evaluation.decision.riskLevel, floor.level),
      reasons: [...evaluation.decision.reasons, reason],
    },
  };
}

function strongerRiskLevel(left: RuntimeRiskLevel, right: RuntimeRiskLevel): RuntimeRiskLevel {
  const rank: Record<RuntimeRiskLevel, number> = {
    safe: 0, low: 1, medium: 2, high: 3, critical: 4,
  };
  return rank[left] >= rank[right] ? left : right;
}

function isDecision(value: unknown): value is CloudPolicyDecision {
  return value === 'allow' || value === 'warn' || value === 'require_approval' || value === 'block';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
