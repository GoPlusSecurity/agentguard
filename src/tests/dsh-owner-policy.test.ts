import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyDshOwnerPolicy,
  normalizeDshOwnerPolicies,
} from '../dsh/owner-policy.js';
import type { RuntimeEvaluation } from '../runtime/decision.js';
import type { CloudPolicyDecision, RuntimeAction, RuntimeRiskLevel } from '../runtime/types.js';

function evaluation(
  decision: CloudPolicyDecision,
  riskScore = 0,
  riskLevel: RuntimeRiskLevel = 'safe'
): RuntimeEvaluation {
  return {
    policySource: 'default',
    decision: {
      actionId: 'owner-policy-test',
      decision,
      riskScore,
      riskLevel,
      reasons: [],
      policyVersion: 'test-policy',
    },
  };
}

function action(owner = 'example-plugin'): RuntimeAction {
  return {
    sessionId: 'session-1',
    agentHost: 'dsh',
    actionType: 'other',
    toolName: 'example_tool',
    input: '{}',
    metadata: {
      sourceAttribution: 'configured-tool-owner',
      sourceOwner: owner,
    },
  };
}

describe('DSH attributed owner policy', () => {
  it('raises a shared decision to the configured minimum', () => {
    const policies = normalizeDshOwnerPolicies({
      'example-plugin': { minimumDecision: 'require_approval' },
    });
    const result = applyDshOwnerPolicy(evaluation('allow'), action(), policies);
    assert.equal(result.decision.decision, 'require_approval');
    assert.equal(result.decision.riskScore, 55);
    assert.equal(result.decision.riskLevel, 'high');
    assert.deepEqual(result.decision.reasons.map(reason => reason.code), ['DSH_OWNER_POLICY']);
  });

  it('never weakens a stronger shared decision', () => {
    const policies = normalizeDshOwnerPolicies({
      'example-plugin': { minimumDecision: 'allow' },
    });
    const original = evaluation('block', 95, 'critical');
    assert.equal(applyDshOwnerPolicy(original, action(), policies), original);
  });

  it('does not apply owner policy to unknown or differently attributed tools', () => {
    const policies = normalizeDshOwnerPolicies({
      'example-plugin': { minimumDecision: 'block' },
    });
    const original = evaluation('allow');
    assert.equal(applyDshOwnerPolicy(original, action('other-plugin'), policies), original);
    assert.equal(applyDshOwnerPolicy(original, {
      ...action(), metadata: { sourceAttribution: 'unknown' },
    }, policies), original);
  });

  it('rejects malformed owner policies', () => {
    assert.throws(() => normalizeDshOwnerPolicies([]), /must be an object/);
    assert.throws(
      () => normalizeDshOwnerPolicies({ 'bad owner': { minimumDecision: 'block' } }),
      /invalid AgentGuard DSH owner policy id/
    );
    assert.throws(
      () => normalizeDshOwnerPolicies({ plugin: { minimumDecision: 'deny' } }),
      /requires minimumDecision/
    );
  });
});
