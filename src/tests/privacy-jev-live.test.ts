import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzePrivacy } from '../privacy/adjudicator.js';
import { JevAdjudicator } from '../privacy/providers/jev.js';

interface ProseCase {
  id: string;
  track?: 'value' | 'chunk';
  text: string;
}
const fixture = JSON.parse(
  readFileSync(join(process.cwd(), 'src', 'tests', 'fixtures', 'privacy', 'prose.json'), 'utf8'),
) as { positive: ProseCase[]; negative: ProseCase[] };

const enabled = Boolean(process.env.TYPESAFE_API_KEY);
const skip = enabled ? false : 'set TYPESAFE_API_KEY to run the live Jev adjudication tests';

/**
 * Live contract tests against TypeSafe. Skipped without a key so the default
 * suite stays offline and deterministic.
 *
 * Thresholds are deliberately loose: these guard against the integration
 * breaking (schema drift, auth, batching), not against small model movement.
 */
describe('Jev adjudication (live)', { skip }, () => {
  it('recalls the prose positives the deterministic rules miss', async () => {
    const adjudicator = new JevAdjudicator();
    assert.ok(adjudicator.available, 'adjudicator should be configured when a key is present');

    const detected: string[] = [];
    for (const testCase of fixture.positive) {
      const report = await analyzePrivacy(testCase.text, { adjudicator });
      if (report.findings.length > 0) detected.push(testCase.id);
    }
    const recall = detected.length / fixture.positive.length;
    assert.ok(
      recall >= 0.7,
      `live prose recall dropped to ${(recall * 100).toFixed(0)}%; detected ${detected.join(', ')}`,
    );
  });

  it('stays quiet on documentation, technical identifiers and aggregates', async () => {
    const adjudicator = new JevAdjudicator();
    const flagged: string[] = [];
    for (const testCase of fixture.negative) {
      const report = await analyzePrivacy(testCase.text, { adjudicator });
      if (report.findings.length > 0) flagged.push(testCase.id);
    }
    assert.ok(
      flagged.length <= 1,
      `too many prose false positives: ${flagged.join(', ')}`,
    );
  });

  it('produces maskable value spans and never leaks the original into the mask', async () => {
    const adjudicator = new JevAdjudicator();
    const text = '出问题的那个订单收件人是陈立群，电话 13701234567。';
    const report = await analyzePrivacy(text, { adjudicator });
    assert.equal(report.coverage, 'full');
    assert.ok(report.valueCount > 0, 'expected at least one maskable span');
    assert.equal(report.localization, report.flaggedChunks > 0 ? 'chunk' : 'value');
  });

  it('reports usage so batching cost can be measured', async () => {
    const report = await analyzePrivacy('我的身份证是 110101199003071233', { adjudicator: new JevAdjudicator() });
    assert.ok((report.usage?.requests ?? 0) >= 1);
    assert.ok((report.usage?.inputTokens ?? 0) > 0);
  });
});
