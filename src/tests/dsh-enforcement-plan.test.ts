import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { planDshEnforcement } from '../dsh/enforcement-plan.js';
import type { CloudPolicyDecision } from '../runtime/types.js';

describe('DSH shadow enforcement plan', () => {
  it('maps every runtime decision deterministically at pre-execute', () => {
    const expected: Record<CloudPolicyDecision, [string, string]> = {
      allow: ['allow', 'proceed'],
      warn: ['allow', 'proceed-with-warning'],
      require_approval: ['ask', 'request-approval'],
      block: ['deny', 'deny-execution'],
    };
    for (const [decision, [hookDecision, disposition]] of Object.entries(expected)) {
      const result = planDshEnforcement(decision as CloudPolicyDecision, 'pre');
      assert.equal(result.hookDecision, hookDecision);
      assert.equal(result.disposition, disposition);
    }
    assert.deepEqual(planDshEnforcement('require_approval', 'pre').enforcementGates, [
      'native-approval-service',
      'headless-approval-policy',
    ]);
  });

  it('contains risky post-execute results without claiming approval is wired', () => {
    assert.deepEqual(planDshEnforcement('allow', 'post'), {
      phase: 'post', policyDecision: 'allow', hookDecision: 'accept',
      disposition: 'accept-result', enforcementGates: [],
    });
    assert.deepEqual(planDshEnforcement('require_approval', 'post'), {
      phase: 'post', policyDecision: 'require_approval', hookDecision: 'block',
      disposition: 'hold-result-for-approval',
      enforcementGates: ['native-post-result-approval', 'approved-result-resume'],
    });
    assert.deepEqual(planDshEnforcement('block', 'post'), {
      phase: 'post', policyDecision: 'block', hookDecision: 'block',
      disposition: 'block-result', enforcementGates: ['post-result-suppression-validation'],
    });
  });
});
