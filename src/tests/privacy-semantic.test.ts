import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractCandidates } from '../privacy/candidates.js';
import { chunkLocator, splitChunks } from '../privacy/chunks.js';
import { analyzePrivacy, maskFindings, MemoryVerdictCache } from '../privacy/adjudicator.js';
import { estimateTokens, splitByTokenBudget } from '../privacy/providers/jev.js';
import { OfflineAdjudicator } from '../privacy/providers/offline.js';
import type { AdjudicationRequest, AdjudicationResult, PrivacyAdjudicator } from '../privacy/types.js';

const candidatesOf = (text: string) => {
  const chunks = splitChunks(text);
  return extractCandidates(text, chunkLocator(chunks));
};

/** Judges by a caller-supplied predicate so pipeline tests need no network. */
class StubAdjudicator implements PrivacyAdjudicator {
  readonly name = 'stub';
  readonly available = true;
  constructor(private readonly isPii: (value: string) => boolean) {}
  async adjudicate(request: AdjudicationRequest): Promise<AdjudicationResult> {
    return {
      candidateVerdicts: request.candidates.map((c) => ({
        id: c.id,
        isPii: this.isPii(c.value),
        probability: this.isPii(c.value) ? 0.9 : 0.05,
      })),
      chunkVerdicts: request.chunks.map((c) => ({
        id: `s${c.index}`,
        isPii: this.isPii(c.text),
        probability: this.isPii(c.text) ? 0.85 : 0.04,
      })),
      coverage: 'full',
      provider: this.name,
    };
  }
}

describe('Privacy candidate extraction', () => {
  it('extracts value spans from prose that the field-anchored rules cannot see', () => {
    const kinds = candidatesOf('我的身份证是 110101199003071233，手机 13812345678').map((c) => c.kind);
    assert.ok(kinds.includes('national_id_cn'), 'national id span missing');
    assert.ok(kinds.includes('mobile_cn'), 'mobile span missing');
  });

  it('captures only the name, not the introducing phrase', () => {
    // Regression: matching the whole phrase produced the fragment "同事是我们组的".
    const people = candidatesOf('负责跟进的同事是小刘，收件人是陈立群').filter((c) => c.kind === 'person_cn');
    const values = people.map((c) => c.value);
    assert.deepEqual(values.sort(), ['小刘', '陈立群']);
    for (const person of people) {
      assert.ok(!person.value.includes('是'), `captured phrase instead of name: ${person.value}`);
    }
  });

  it('reports spans that index back into the source text', () => {
    const text = '客户实名认证信息是 110101199003071233，姓名张伟。';
    for (const candidate of candidatesOf(text)) {
      assert.equal(text.slice(candidate.start, candidate.end), candidate.value);
    }
  });

  it('drops spans already covered by a longer span', () => {
    // An 18-digit id also matches the 15-19 digit account extractor.
    const values = candidatesOf('证件号 110101199003071233').map((c) => c.value);
    assert.equal(new Set(values).size, values.length, 'overlapping duplicates survived');
  });

  it('keeps base64 that decodes to an identifier and drops base64 that does not', () => {
    const idPayload = Buffer.from('110101199003071233').toString('base64');
    assert.ok(candidatesOf(`payload = "${idPayload}"`).some((c) => c.kind === 'base64_id'));
    const prose = Buffer.from('the quick brown fox jumped').toString('base64');
    assert.ok(!candidatesOf(`payload = "${prose}"`).some((c) => c.kind === 'base64_id'));
  });

  it('finds addresses and coordinate pairs', () => {
    const kinds = candidatesOf('我住朝阳区酒仙桥路12号院3号楼502').map((c) => c.kind);
    assert.ok(kinds.includes('address_cn'));
    assert.ok(candidatesOf('轨迹点 31.230416, 121.473701').some((c) => c.kind === 'coordinate'));
  });
});

describe('Privacy chunking', () => {
  it('splits prose on sentence terminators and preserves offsets', () => {
    const text = '第一句话。第二句话！第三句话？';
    const chunks = splitChunks(text);
    assert.equal(chunks.length, 3);
    for (const chunk of chunks) assert.ok(text.slice(chunk.start, chunk.end).includes(chunk.text));
  });

  it('hard-splits a single oversized line so it cannot dominate the budget', () => {
    const chunks = splitChunks('x'.repeat(2500));
    assert.ok(chunks.length >= 3, `expected the long line to be split, got ${chunks.length}`);
  });

  it('locates the chunk containing an offset', () => {
    const text = '无关的一句。身份证 110101199003071233。';
    const chunks = splitChunks(text);
    const locate = chunkLocator(chunks);
    assert.equal(locate(text.indexOf('110101')).index, 1);
  });
});

describe('Jev batching', () => {
  it('estimates CJK as denser than Latin text', () => {
    assert.ok(estimateTokens('身份证号码'.repeat(10)) > estimateTokens('abcde'.repeat(10)));
  });

  it('splits by token budget rather than question count', () => {
    const items = Array.from({ length: 50 }, (_, i) => ({ id: `q${i}`, instructions: 'x', tokens: 100, bytes: 64 }));
    const batches = splitByTokenBudget(items, 1000);
    assert.ok(batches.length >= 5, `expected several batches, got ${batches.length}`);
    assert.equal(batches.flat().length, 50, 'no question may be dropped while batching');
    for (const batch of batches) {
      const total = batch.reduce((sum, item) => sum + item.tokens, 0);
      assert.ok(total <= 1000 || batch.length === 1, 'batch exceeded budget');
    }
  });

  /**
   * The byte cap must split batches, not merely reject them at dispatch: a
   * rejected batch loses coverage for every question it carried.
   */
  it('splits on serialized bytes even when the token budget is ample', () => {
    const items = Array.from({ length: 40 }, (_, i) => ({ id: `q${i}`, instructions: 'x', tokens: 10, bytes: 20 * 1024 }));
    const batches = splitByTokenBudget(items, 1_000_000);
    assert.ok(batches.length > 1, 'an ample token budget must not defeat the byte cap');
    assert.equal(batches.flat().length, 40, 'no question may be dropped while splitting');
    for (const batch of batches) {
      const bytes = batch.reduce((sum, item) => sum + item.bytes, 0);
      assert.ok(bytes <= 256 * 1024 || batch.length === 1, 'batch exceeded the byte cap');
    }
  });

  it('reserves budget for shared context', () => {
    const items = Array.from({ length: 10 }, (_, i) => ({ id: `q${i}`, instructions: 'x', tokens: 100, bytes: 64 }));
    const withContext = splitByTokenBudget(items, 600, '口径'.repeat(100));
    const without = splitByTokenBudget(items, 600);
    assert.ok(withContext.length > without.length, 'shared context must consume budget');
  });
});

describe('Privacy pipeline', () => {
  it('is disabled by default and reports unsupported rather than clean', async () => {
    const report = await analyzePrivacy('我的身份证是 110101199003071233');
    assert.equal(report.provider, 'offline');
    assert.equal(report.coverage, 'unsupported');
    assert.equal(report.findings.length, 0);
    assert.equal(report.localization, 'none');
  });

  it('produces maskable value spans for confirmed candidates', async () => {
    const text = '收件人是陈立群，电话 13701234567。';
    const report = await analyzePrivacy(text, {
      adjudicator: new StubAdjudicator((value) => value === '13701234567' || value === '陈立群'),
    });
    assert.equal(report.localization, 'value');
    assert.equal(report.valueCount, 2);
    const masked = maskFindings(text, report);
    assert.ok(!masked.includes('13701234567'), 'phone survived masking');
    assert.ok(!masked.includes('陈立群'), 'name survived masking');
  });

  it('falls back to chunk localization for PII with no extractable span', async () => {
    const text = '这位客户上周刚做完手术，急着要收康复器械。';
    const report = await analyzePrivacy(text, {
      adjudicator: new StubAdjudicator((value) => value.includes('手术')),
    });
    assert.equal(report.localization, 'chunk');
    assert.equal(report.valueCount, 0);
    assert.equal(report.flaggedChunks, 1);
    assert.ok(!maskFindings(text, report).includes('手术'));
  });

  it('does not double-count a chunk that already yielded a value span', async () => {
    const report = await analyzePrivacy('身份证 110101199003071233 请核对。', {
      adjudicator: new StubAdjudicator(() => true),
    });
    assert.equal(report.flaggedChunks, 0, 'chunk duplicated a confirmed span');
    assert.ok(report.valueCount > 0);
  });

  it('degrades coverage when the provider only answers part of the batch', async () => {
    const partial: PrivacyAdjudicator = {
      name: 'partial',
      available: true,
      async adjudicate() {
        return { candidateVerdicts: [], chunkVerdicts: [], coverage: 'partial', provider: 'partial' };
      },
    };
    const report = await analyzePrivacy('身份证 110101199003071233', { adjudicator: partial });
    assert.equal(report.coverage, 'partial');
    assert.notEqual(report.coverage, 'full');
  });

  it('reuses cached verdicts for identical text', async () => {
    const cache = new MemoryVerdictCache();
    let calls = 0;
    const counting: PrivacyAdjudicator = {
      name: 'counting',
      available: true,
      async adjudicate() {
        calls += 1;
        return { candidateVerdicts: [], chunkVerdicts: [], coverage: 'full', provider: 'counting' };
      },
    };
    const text = '手机 13812345678';
    const first = await analyzePrivacy(text, { adjudicator: counting, cache });
    const second = await analyzePrivacy(text, { adjudicator: counting, cache });
    assert.equal(calls, 1, 'cache did not prevent a second adjudication');
    assert.equal(first.fromCache, false);
    assert.equal(second.fromCache, true);
  });

  it('offline adjudicator never claims to have judged anything', async () => {
    const result = await new OfflineAdjudicator().adjudicate({ candidates: [], chunks: [] });
    assert.equal(result.coverage, 'unsupported');
  });
});
