import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatDshPolicyReason,
  mergeDshPostDecisions,
  mergeDshPreDecisions,
  translateDshPostDecision,
  translateDshPreDecision,
} from '../dsh/enforcement-adapter.js';
import type { RuntimeDecision } from '../runtime/types.js';

function runtimeDecision(
  decision: RuntimeDecision['decision'],
  overrides: Partial<RuntimeDecision> = {}
): RuntimeDecision {
  return {
    actionId: 'action-test',
    decision,
    riskScore: decision === 'block' ? 95 : decision === 'require_approval' ? 55 : 20,
    riskLevel: decision === 'block' ? 'critical' : decision === 'require_approval' ? 'high' : 'medium',
    reasons: [{
      code: 'REMOTE_CODE_EXECUTION', severity: 'high', title: 'remote execution',
      description: 'description must not be included', evidence: 'TOP_SECRET_EVIDENCE',
    }],
    policyVersion: 'runtime-test',
    ...overrides,
  };
}

describe('DSH enforcement protocol adapter', () => {
  it('delegates approval-class decisions to the native ask protocol', () => {
    const translated = translateDshPreDecision(runtimeDecision('require_approval'));
    assert.equal(translated.kind, 'ask');
    assert.match(translated.kind === 'ask' ? translated.reason ?? '' : '', /requires approval/);
    assert.doesNotMatch(JSON.stringify(translated), /TOP_SECRET_EVIDENCE|description must not/);
  });

  it('maps allow, warn, and block without inventing a second approval queue', () => {
    assert.deepEqual(translateDshPreDecision(runtimeDecision('allow')), { kind: 'allow' });
    assert.deepEqual(translateDshPreDecision(runtimeDecision('warn')), { kind: 'allow' });
    assert.equal(translateDshPreDecision(runtimeDecision('block')).kind, 'deny');
  });

  it('contains approval and block decisions discovered after execution', () => {
    assert.deepEqual(translateDshPostDecision(runtimeDecision('allow')), { kind: 'accept' });
    assert.deepEqual(translateDshPostDecision(runtimeDecision('warn')), { kind: 'accept' });
    for (const value of ['require_approval', 'block'] as const) {
      const translated = translateDshPostDecision(runtimeDecision(value));
      assert.equal(translated.kind, 'block');
      assert.match(translated.kind === 'block' ? String(translated.feedback[0].text ?? '') : '', /AgentGuard/);
    }
  });

  it('never weakens decisions returned by another DSH policy listener', () => {
    const deny = { kind: 'deny' as const, reason: 'downstream deny' };
    const ask = { kind: 'ask' as const, reason: 'AgentGuard asks' };
    assert.equal(mergeDshPreDecisions(ask, deny), deny);
    assert.equal(mergeDshPreDecisions({ kind: 'deny', reason: 'AgentGuard deny' }, { kind: 'allow' }).kind, 'deny');

    const downstreamBlock = {
      kind: 'block' as const,
      feedback: [{ type: 'text' as const, text: 'downstream block' }],
    };
    assert.equal(mergeDshPostDecisions({ kind: 'accept' }, downstreamBlock), downstreamBlock);
    assert.equal(mergeDshPostDecisions(downstreamBlock, { kind: 'accept' }), downstreamBlock);
  });

  it('bounds reason-code output and excludes evidence on failure paths', () => {
    const reasons = Array.from({ length: 12 }, (_, index) => ({
      code: `CODE_${index}_${'x'.repeat(100)}`,
      severity: 'high' as const,
      title: 'title',
      description: 'description',
      evidence: `secret-${index}`,
    }));
    const text = formatDshPolicyReason(runtimeDecision('block', { reasons }));
    assert.ok(text.length <= 500);
    assert.match(text, /CODE_0_/);
    assert.doesNotMatch(text, /CODE_6_|secret-/);
  });
});
