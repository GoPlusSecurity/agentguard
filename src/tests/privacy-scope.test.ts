import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { analyzePrivacy, MemoryVerdictCache } from '../privacy/adjudicator.js';
import { hasSoftSignal, isStructuredNoise, softSignalGroups, SOFT_SIGNAL_GROUPS } from '../privacy/soft-signals.js';
import { TokenBudget, type AdjudicationRequest, type AdjudicationResult, type PrivacyAdjudicator } from '../privacy/types.js';

/** Records what each scope actually put on the wire. */
class RecordingAdjudicator implements PrivacyAdjudicator {
  readonly name = 'recording';
  readonly available = true;
  candidateIds: string[] = [];
  chunkIndexes: number[] = [];
  calls = 0;
  async adjudicate(request: AdjudicationRequest): Promise<AdjudicationResult> {
    this.calls += 1;
    this.candidateIds = request.candidates.map((c) => c.id);
    this.chunkIndexes = request.chunks.map((c) => c.index);
    return {
      candidateVerdicts: request.candidates.map((c) => ({ id: c.id, isPii: false, probability: 0.1 })),
      chunkVerdicts: request.chunks.map((c) => ({ id: `s${c.index}`, isPii: false, probability: 0.1 })),
      coverage: 'full',
      provider: this.name,
    };
  }
}

const MIXED = [
  '帮我看下这个订单服务的 bug，生产环境从昨天开始间歇性 500。',
  '出问题的订单收件人是陈立群，电话 13701234567。',
  '这位客户上周刚做完手术，急着要收康复器械。',
  'const config = { retries: 3, timeout: [1000, 2000] };',
].join('');

describe('Soft signal net', () => {
  it('fires on disclosures that carry no extractable span', () => {
    assert.ok(hasSoftSignal('这位客户上周刚做完手术'));
    assert.ok(hasSoftSignal('我月薪两万八，房贷还剩一百八十万'));
    assert.ok(hasSoftSignal('我女儿今年上三年级'));
    assert.ok(hasSoftSignal('I was diagnosed with type 2 diabetes'));
  });

  it('stays quiet on ordinary engineering prose', () => {
    assert.ok(!hasSoftSignal('生产环境从昨天下午开始间歇性 500'));
    assert.ok(!hasSoftSignal('报错栈指向 OrderService 第 142 行'));
  });

  it('reports which categories fired so the table can be tuned', () => {
    assert.deepEqual(softSignalGroups('医生说下个月还要复查'), ['health']);
    assert.ok(softSignalGroups('我住在望京，孩子上小学').includes('minor'));
  });

  it('covers the PIPL Article 28 categories', () => {
    for (const group of ['health', 'finance', 'residence', 'identity', 'minor', 'belief', 'biometric', 'whereabouts']) {
      assert.ok(group in SOFT_SIGNAL_GROUPS, `missing sensitive-information group: ${group}`);
    }
  });

  it('treats JSON, code and log lines as structured noise', () => {
    assert.ok(isStructuredNoise('const config = { retries: 3, timeout: [1000, 2000] };'));
    assert.ok(isStructuredNoise('{"level":"warn","msg":"pool exhausted"}'));
    assert.ok(!isStructuredNoise('这位客户上周刚做完手术，急着要收康复器械。'));
  });
});

describe('Privacy scope', () => {
  it('candidates scope sends spans only', async () => {
    const adjudicator = new RecordingAdjudicator();
    const report = await analyzePrivacy(MIXED, { adjudicator, scope: 'candidates' });
    assert.ok(adjudicator.candidateIds.length > 0);
    assert.equal(adjudicator.chunkIndexes.length, 0, 'code scans must not ship prose');
    assert.equal(report.scope, 'candidates');
    assert.ok(report.chunksSkipped > 0);
  });

  it('filtered scope keeps the semantic sentence and drops the rest', async () => {
    const adjudicator = new RecordingAdjudicator();
    await analyzePrivacy(MIXED, { adjudicator, scope: 'filtered' });
    assert.equal(adjudicator.chunkIndexes.length, 1, 'only the disclosure sentence should survive the net');
  });

  it('full scope ships every sentence', async () => {
    const adjudicator = new RecordingAdjudicator();
    const report = await analyzePrivacy(MIXED, { adjudicator, scope: 'full' });
    assert.ok(adjudicator.chunkIndexes.length > 1);
    assert.equal(report.chunksSkipped, 0);
  });

  it('defaults to filtered so the cheaper, lower-egress path is the default', async () => {
    const adjudicator = new RecordingAdjudicator();
    const report = await analyzePrivacy(MIXED, { adjudicator });
    assert.equal(report.scope, 'filtered');
  });

  it('never ships a sentence whose span was already extracted', async () => {
    const adjudicator = new RecordingAdjudicator();
    await analyzePrivacy('收件人是陈立群，电话 13701234567。', { adjudicator, scope: 'filtered' });
    assert.equal(adjudicator.chunkIndexes.length, 0, 'the span is the stronger finding; the sentence is redundant');
  });

  it('keys the cache on scope so a narrower run cannot clear a wider one', async () => {
    const cache = new MemoryVerdictCache();
    const adjudicator = new RecordingAdjudicator();
    await analyzePrivacy(MIXED, { adjudicator, cache, scope: 'candidates' });
    await analyzePrivacy(MIXED, { adjudicator, cache, scope: 'full' });
    assert.equal(adjudicator.calls, 2, 'a wider scope must re-examine, not reuse narrower verdicts');
  });
});

describe('Shared token budget', () => {
  it('degrades to partial coverage instead of sending when exhausted', async () => {
    const adjudicator = new RecordingAdjudicator();
    const report = await analyzePrivacy(MIXED, { adjudicator, budget: new TokenBudget(10) });
    assert.equal(adjudicator.calls, 0, 'nothing may be sent once the ceiling is reached');
    assert.equal(report.budgetExhausted, true);
    assert.equal(report.coverage, 'partial');
    assert.notEqual(report.coverage, 'full', 'an unexamined scan must never read as complete');
  });

  it('is shared across calls so a directory scan cannot multiply the ceiling', async () => {
    const budget = new TokenBudget(400);
    const adjudicator = new RecordingAdjudicator();
    let exhaustedAt = -1;
    for (let i = 0; i < 12; i++) {
      const report = await analyzePrivacy(`${MIXED}${i}`, { adjudicator, budget });
      if (report.budgetExhausted && exhaustedAt < 0) exhaustedAt = i;
    }
    assert.ok(exhaustedAt >= 0, 'a shared budget must eventually stop a repeated scan');
    assert.equal(budget.exhausted || budget.remaining < 400, true);
  });

  it('reports remaining budget so callers can pace a large scan', () => {
    const budget = new TokenBudget(1000);
    assert.equal(budget.tryConsume(600), true);
    assert.equal(budget.remaining, 400);
    assert.equal(budget.tryConsume(600), false, 'over-spending must be refused, not clamped');
    assert.equal(budget.remaining, 400, 'a refused reservation must not be charged');
  });
});
