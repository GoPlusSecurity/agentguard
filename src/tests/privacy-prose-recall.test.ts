import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectPiiCategories } from '../scanner/rules/privacy.js';
import { extractCandidates } from '../privacy/candidates.js';
import { chunkLocator, splitChunks } from '../privacy/chunks.js';

interface ProseCase {
  id: string;
  kind?: string;
  /** Which localization track can handle this case. */
  track?: 'value' | 'chunk';
  text: string;
}
interface ProseFixture {
  positive: ProseCase[];
  negative: ProseCase[];
}

const fixture = JSON.parse(
  readFileSync(join(process.cwd(), 'src', 'tests', 'fixtures', 'privacy', 'prose.json'), 'utf8'),
) as ProseFixture;

describe('Prose privacy recall', () => {
  /**
   * Locks in the measured gap the semantic layer exists to close.
   *
   * The deterministic rules require a `field: value` anchor, so they recall
   * almost nothing from prose — and prose is the shape an LLM prompt takes.
   * This asserts the limitation rather than hiding it: if someone later raises
   * prose recall in the deterministic rules, this test fails and the semantic
   * layer's justification should be re-examined.
   */
  it('deterministic rules recall almost nothing from prose', () => {
    const detected = fixture.positive.filter((c) => detectPiiCategories(c.text).length > 0);
    const recall = detected.length / fixture.positive.length;
    assert.ok(
      recall <= 0.25,
      `deterministic prose recall is now ${(recall * 100).toFixed(0)}% ` +
        `(${detected.map((c) => c.id).join(', ')}); re-evaluate whether the semantic layer is still needed`,
    );
  });

  it('deterministic rules stay quiet on prose negatives', () => {
    const flagged = fixture.negative.filter((c) => detectPiiCategories(c.text).length > 0);
    assert.deepEqual(flagged.map((c) => c.id), [], 'deterministic rules produced prose false positives');
  });

  /**
   * Candidate coverage bounds everything downstream: an adjudicator can only
   * rule on spans it is handed, so a value no extractor emits is unreachable
   * however good the judge is.
   */
  it('candidate extraction reaches every value-track case', () => {
    const valueTrack = fixture.positive.filter((c) => c.track === 'value');
    assert.ok(valueTrack.length > 0, 'fixture lost its value-track cases');
    for (const testCase of valueTrack) {
      const chunks = splitChunks(testCase.text);
      const candidates = extractCandidates(testCase.text, chunkLocator(chunks));
      assert.ok(candidates.length > 0, `${testCase.id} produced no candidates; recall ceiling reached`);
    }
  });

  /**
   * Obfuscation degrades localization, and that is a security property worth
   * asserting: Chinese-numeral or split identifiers leave no contiguous span,
   * so character-level masking becomes impossible even though the disclosure is
   * still detectable. An attacker cannot hide the leak, but can force the
   * coarser, more destructive redaction.
   */
  it('chunk-track cases yield no identifier span, so only whole-sentence handling is sound', () => {
    const chunkTrack = fixture.positive.filter((c) => c.track === 'chunk');
    for (const testCase of chunkTrack) {
      const chunks = splitChunks(testCase.text);
      const candidates = extractCandidates(testCase.text, chunkLocator(chunks));
      const identifiers = candidates.filter((c) =>
        ['national_id', 'bank_account', 'phone_number'].includes(c.category),
      );
      assert.equal(
        identifiers.length,
        0,
        `${testCase.id} produced an identifier span; reclassify it to the value track`,
      );
      assert.ok(chunks.length > 0, `${testCase.id} has no chunk to fall back to`);
    }
  });
});
