import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { evaluateLocalAction } from '../runtime/evaluator.js';
import { evaluateRuntimeAction } from '../runtime/decision.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { ClaudeCodeAdapter } from '../adapters/claude-code.js';
import { HermesAdapter } from '../adapters/hermes.js';
import { OpenClawAdapter } from '../adapters/openclaw.js';
import {
  CONFORMANCE_ACTION_FIXTURES,
  LIFECYCLE_CONFORMANCE_FIXTURES,
  buildConformanceAction,
  type ConformanceHost,
} from './fixtures/runtime-conformance.js';

describe('runtime evaluator conformance', () => {
  it('returns the same decision, reasons, and risk for identical facts across hosts', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    for (const fixture of CONFORMANCE_ACTION_FIXTURES) {
      const snapshots = await Promise.all((['dsh', 'hermes', 'openclaw', 'codex', 'claude-code'] as ConformanceHost[]).map(async agentHost => {
        const result = await evaluateLocalAction(policy, buildConformanceAction(fixture, agentHost));
        return {
          decision: result.decision,
          riskScore: result.riskScore,
          riskLevel: result.riskLevel,
          reasonCodes: result.reasons.map(reason => reason.code),
        };
      }));
      for (const snapshot of snapshots.slice(1)) assert.deepEqual(snapshot, snapshots[0], fixture.name);
    }
  });

  it('classifies endpoint and credential fixtures without treating missing facts as allow', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const completeUnknown = await evaluateLocalAction(policy, buildConformanceAction(
      CONFORMANCE_ACTION_FIXTURES.find(fixture => fixture.name === 'unknown-relay-with-key')!, 'codex'));
    assert.equal(completeUnknown.decision, 'block');
    assert.ok(completeUnknown.reasons.some(reason => reason.code === 'LLM_KEY_TO_UNKNOWN_HOST'));

    const missingFacts = await evaluateLocalAction(policy, buildConformanceAction(
      CONFORMANCE_ACTION_FIXTURES.find(fixture => fixture.name === 'unknown-relay-missing-transport-facts')!, 'codex'));
    assert.equal(missingFacts.ruleEvaluations?.find(rule => rule.ruleId === 'UNTRUSTED_LLM_ENDPOINT')?.coverageLevel, 'unsupported');
    assert.equal(missingFacts.ruleEvaluations?.find(rule => rule.ruleId === 'LLM_KEY_TO_UNKNOWN_HOST')?.coverageLevel, 'unsupported');
    assert.notEqual(missingFacts.decision, 'allow');
    assert.ok(missingFacts.missingFacts?.includes('final_destination'));
  });

  it('keeps local blocking decisions when the Cloud evaluator is unavailable', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const action = buildConformanceAction(
      CONFORMANCE_ACTION_FIXTURES.find(fixture => fixture.name === 'unknown-relay-with-key')!, 'claude-code');
    const cachePath = join(mkdtempSync(join(tmpdir(), 'agentguard-conformance-')), 'policy.json');
    const result = await evaluateRuntimeAction({
      action,
      policyCachePath: cachePath,
      fetchPolicy: async () => { throw new Error('cloud offline'); },
    });
    assert.equal(result.policySource, 'default');
    assert.equal(result.decision.decision, 'block');
  });

  it('preserves bounded PII summaries while applying the same block decision', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const fixture = CONFORMANCE_ACTION_FIXTURES.find(item => item.name === 'unknown-relay-with-key')!;
    const action = buildConformanceAction({
      ...fixture,
      input: 'email_address=private.person@corp.invalid phone_number=13812345678',
    }, 'dsh');
    const result = await evaluateLocalAction(policy, action);
    assert.equal(result.decision, 'block');
    assert.deepEqual(result.piiSummary?.categories.map(item => item.category), ['email_address', 'phone_number']);
    assert.ok(result.reasons.every(reason => !reason.evidence?.includes('private.person@invalid.test')));
  });
});

describe('adapter lifecycle conformance', () => {
  it('declares the five host capability and lifecycle fixtures explicitly', () => {
    const adapters = {
      hermes: new HermesAdapter(),
      openclaw: new OpenClawAdapter(),
      'claude-code': new ClaudeCodeAdapter(),
    } as const;
    for (const fixture of LIFECYCLE_CONFORMANCE_FIXTURES) {
      if (fixture.adapter in adapters) {
        assert.deepEqual(adapters[fixture.adapter as keyof typeof adapters].capabilities, fixture.capabilities);
      }
      assert.ok(fixture.events.length > 0, fixture.adapter);
      for (const event of fixture.events) {
        assert.ok(event.lifecycleStage);
        assert.ok(event.coverageLevel);
        assert.equal(typeof event.canBlockCurrentAction, 'boolean');
        assert.ok(Array.isArray(event.missingFacts));
      }
    }
  });

  it('marks uncovered retry, fallback, auxiliary, embedding, and file-upload paths explicitly', () => {
    const requiredScenarios = new Set([
      'ordinary', 'tool_loop_second', 'retry', 'fallback', 'auxiliary', 'streaming', 'embedding', 'file_upload',
    ]);
    for (const fixture of LIFECYCLE_CONFORMANCE_FIXTURES) {
      const scenarios = new Set(fixture.events.map(event => event.scenario));
      for (const scenario of requiredScenarios) assert.ok(scenarios.has(scenario as never), `${fixture.adapter}:${scenario}`);
      for (const event of fixture.events) {
        assert.ok(['full', 'partial', 'observe_only', 'unsupported'].includes(event.coverageLevel));
        if (['embedding', 'file_upload'].includes(event.scenario)) {
          assert.equal(event.coverageLevel, 'unsupported');
        }
      }
    }
  });
});
