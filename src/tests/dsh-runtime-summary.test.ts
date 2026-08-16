import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { summarizeDshRuntimeAudit } from '../dsh/runtime-summary.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

function event(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    actionId: 'action-1',
    sessionId: 'dsh:root-1',
    agentHost: 'dsh',
    actionType: 'shell',
    toolName: 'bash',
    input: 'sensitive raw command',
    decision: 'require_approval',
    riskScore: 55,
    riskLevel: 'high',
    reasons: [{ code: 'REMOTE_CODE_EXECUTION' }],
    policyVersion: 'test-policy',
    metadata: { runtimeMode: 'observe', nested: false },
    ...overrides,
  };
}

describe('DSH runtime audit summary', () => {
  it('aggregates only observed DSH events and omits raw inputs', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentguard-dsh-summary-'));
    roots.push(root);
    const auditPath = join(root, 'audit.jsonl');
    const lines = [
      event(),
      event({
        actionId: 'action-2',
        actionType: 'file_read',
        decision: 'allow',
        riskLevel: 'safe',
        reasons: [],
        metadata: { runtimeMode: 'observe', nested: true },
      }),
      event({ actionId: 'other-host', agentHost: 'codex' }),
      event({ actionId: 'not-observe', metadata: { runtimeMode: 'enforce' } }),
    ];
    await writeFile(auditPath, `${lines.map(value => JSON.stringify(value)).join('\n')}\nnot-json\n`, 'utf8');

    const summary = summarizeDshRuntimeAudit(auditPath);
    assert.equal(summary.total, 2);
    assert.equal(summary.inspected, 2);
    assert.equal(summary.malformedLines, 1);
    assert.equal(summary.nestedCalls, 1);
    assert.deepEqual(summary.decisions, { require_approval: 1, allow: 1 });
    assert.deepEqual(summary.actionTypes, { shell: 1, file_read: 1 });
    assert.deepEqual(summary.riskLevels, { high: 1, safe: 1 });
    assert.deepEqual(summary.topReasons, [{ code: 'REMOTE_CODE_EXECUTION', count: 1 }]);
    assert.equal(summary.latestActionId, 'action-2');
    assert.doesNotMatch(JSON.stringify(summary), /sensitive raw command/);
  });

  it('supports exact session filtering and bounded recent results', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentguard-dsh-summary-filter-'));
    roots.push(root);
    const auditPath = join(root, 'audit.jsonl');
    await writeFile(auditPath, [
      event({ actionId: 'old', sessionId: 'target' }),
      event({ actionId: 'other', sessionId: 'other' }),
      event({ actionId: 'new', sessionId: 'target', decision: 'block' }),
    ].map(value => JSON.stringify(value)).join('\n'), 'utf8');

    const summary = summarizeDshRuntimeAudit(auditPath, { sessionId: 'target', limit: 1 });
    assert.equal(summary.total, 1);
    assert.equal(summary.inspected, 2);
    assert.equal(summary.truncated, true);
    assert.equal(summary.latestActionId, 'new');
    assert.deepEqual(summary.decisions, { block: 1 });
    assert.equal(summarizeDshRuntimeAudit(join(root, 'missing.jsonl')).total, 0);
    assert.throws(() => summarizeDshRuntimeAudit(auditPath, { sessionId: ' ' }), /non-empty/);
  });
});
