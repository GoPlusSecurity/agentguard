import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { maskValue, scanSurfaces } from '../privacy/surfaces.js';
import { DEFAULT_ADJUDICATE_OPTIONS, TokenBudget, type AdjudicationRequest, type AdjudicationResult, type PrivacyAdjudicator } from '../privacy/types.js';

class AlwaysPositive implements PrivacyAdjudicator {
  readonly name = 'always';
  readonly available = true;
  calls = 0;
  async adjudicate(request: AdjudicationRequest): Promise<AdjudicationResult> {
    this.calls += 1;
    return {
      candidateVerdicts: request.candidates.map((c) => ({ id: c.id, isPii: true, probability: 0.9 })),
      chunkVerdicts: request.chunks.map((c) => ({ id: `s${c.index}`, isPii: true, probability: 0.9 })),
      coverage: 'full',
      provider: this.name,
      usage: { inputTokens: 100, outputTokens: 10, requests: 1 },
    };
  }
}

let dir = '';

describe('Privacy surface scanning', () => {
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'ag-surface-'));
    writeFileSync(join(dir, 'a.md'), '收件人是陈立群，电话 13701234567。');
    writeFileSync(join(dir, 'b.md'), '这位客户上周刚做完手术。');
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  const base = { adjudicator: new AlwaysPositive(), settings: DEFAULT_ADJUDICATE_OPTIONS };

  /**
   * Reporting a leak must not be one. Findings travel to the console, the audit
   * log and, when Cloud is connected, off the machine.
   */
  it('never puts a raw value in a finding', async () => {
    const scan = await scanSurfaces([join(dir, 'a.md')], { ...base, scope: 'candidates' });
    assert.ok(scan.findings.length > 0);
    for (const finding of scan.findings) {
      assert.ok(!finding.evidence.includes('13701234567'), 'raw phone number leaked into a finding');
      assert.ok(!finding.evidence.includes('陈立群'), 'raw name leaked into a finding');
    }
  });

  it('reports chunk findings by position, never by quoting the sentence', async () => {
    const scan = await scanSurfaces([join(dir, 'b.md')], { ...base, scope: 'filtered' });
    const chunkFinding = scan.findings.find((f) => f.localization === 'chunk');
    assert.ok(chunkFinding, 'the disclosure sentence should be flagged');
    assert.ok(!chunkFinding.evidence.includes('手术'), 'the sentence must not be republished');
    assert.match(chunkFinding.evidence, /sentence \d+/);
  });

  it('shares one budget across files so a directory scan cannot multiply it', async () => {
    const adjudicator = new AlwaysPositive();
    const budget = new TokenBudget(60);
    const scan = await scanSurfaces([join(dir, 'a.md'), join(dir, 'b.md')], {
      adjudicator,
      settings: DEFAULT_ADJUDICATE_OPTIONS,
      scope: 'filtered',
      budget,
    });
    assert.equal(scan.budgetExhausted, true);
    assert.ok(scan.coverage !== 'full', 'an unexamined scan must not read as complete');
  });

  it('counts unreadable and oversized files as skipped rather than clean', async () => {
    const scan = await scanSurfaces([join(dir, 'missing.md')], { ...base, scope: 'candidates' });
    assert.equal(scan.filesSkipped, 1);
    assert.equal(scan.filesExamined, 0);
  });

  it('masks values without revealing length-revealing extremes', () => {
    assert.equal(maskValue('ab'), '**');
    assert.ok(!maskValue('13701234567').includes('0123'));
    assert.match(maskValue('13701234567'), /^13\*+67$/);
  });
});
