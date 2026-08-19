import type { EffectiveRuntimePolicy, RuntimeAction, RuntimeDecision } from './types.js';
import { evaluateLocalAction, type LocalActionEvaluationOptions } from './evaluator.js';
import { resolveRuntimePolicy } from './policy.js';

export interface EvaluateRuntimeActionOptions extends LocalActionEvaluationOptions {
  action: RuntimeAction;
  policyCachePath: string;
  fetchPolicy?: () => Promise<EffectiveRuntimePolicy | null>;
}

export interface RuntimeEvaluation {
  decision: RuntimeDecision;
  policySource: 'cloud' | 'cache' | 'default';
}

/**
 * Resolve the effective policy and evaluate one normalized runtime action.
 *
 * This boundary deliberately has no approval-store, audit-log, event-spool, or
 * host-protocol side effects. Host adapters can therefore share the exact same
 * policy decision while translating approval and enforcement through their own
 * native lifecycle.
 */
export async function evaluateRuntimeAction(
  options: EvaluateRuntimeActionOptions
): Promise<RuntimeEvaluation> {
  const { policy, source } = await resolveRuntimePolicy({
    cachePath: options.policyCachePath,
    fetchPolicy: options.fetchPolicy,
  });
  const decision = await evaluateLocalAction(policy, options.action, {
    filesystemAllowlist: options.filesystemAllowlist,
  });
  return { decision, policySource: source };
}
