import type { CloudPolicyDecision } from '../runtime/types.js';

export type DshRuntimePhase = 'pre' | 'post';
export type DshShadowHookDecision = 'allow' | 'ask' | 'deny' | 'accept' | 'block';
export type DshShadowDisposition =
  | 'proceed'
  | 'proceed-with-warning'
  | 'request-approval'
  | 'deny-execution'
  | 'accept-result'
  | 'accept-result-with-warning'
  | 'hold-result-for-approval'
  | 'block-result';

export interface DshEnforcementPlan {
  phase: DshRuntimePhase;
  policyDecision: CloudPolicyDecision;
  hookDecision: DshShadowHookDecision;
  disposition: DshShadowDisposition;
  enforcementGates: string[];
}

/**
 * Describe the deterministic DSH-native decision that an enforcing integration
 * would make. The plan is audit metadata only; callers must not apply it.
 */
export function planDshEnforcement(
  decision: CloudPolicyDecision,
  phase: DshRuntimePhase
): DshEnforcementPlan {
  if (phase === 'pre') {
    if (decision === 'allow') return plan(phase, decision, 'allow', 'proceed');
    if (decision === 'warn') return plan(phase, decision, 'allow', 'proceed-with-warning');
    if (decision === 'require_approval') {
      return plan(phase, decision, 'ask', 'request-approval', [
        'native-approval-service',
        'headless-approval-policy',
      ]);
    }
    return plan(phase, decision, 'deny', 'deny-execution');
  }

  if (decision === 'allow') return plan(phase, decision, 'accept', 'accept-result');
  if (decision === 'warn') return plan(phase, decision, 'accept', 'accept-result-with-warning');
  if (decision === 'require_approval') {
    return plan(phase, decision, 'block', 'hold-result-for-approval', [
      'native-post-result-approval',
      'approved-result-resume',
    ]);
  }
  return plan(phase, decision, 'block', 'block-result', [
    'post-result-suppression-validation',
  ]);
}

function plan(
  phase: DshRuntimePhase,
  policyDecision: CloudPolicyDecision,
  hookDecision: DshShadowHookDecision,
  disposition: DshShadowDisposition,
  enforcementGates: string[] = []
): DshEnforcementPlan {
  return { phase, policyDecision, hookDecision, disposition, enforcementGates };
}
