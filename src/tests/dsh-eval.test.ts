import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanDshPlugin } from '../dsh/scan.js';
import type { DshInstallRecommendation } from '../dsh/types.js';
import type { RiskLevel, RiskTag } from '../types/scanner.js';

type EvaluationCase = {
  name: string;
  expectedRisk: RiskLevel;
  expectedRecommendation: DshInstallRecommendation;
  mustContainTags?: RiskTag[];
  mustNotContainTags?: RiskTag[];
};

const corpusRoot = resolve('src/tests/fixtures/dsh-eval');
const cases = JSON.parse(readFileSync(resolve(corpusRoot, 'manifest.json'), 'utf8')) as EvaluationCase[];

describe('DSH labeled evaluation corpus', () => {
  for (const entry of cases) {
    it(`${entry.name}: matches the reviewed installation posture`, async () => {
      const report = await scanDshPlugin(resolve(corpusRoot, entry.name));
      assert.equal(report.riskLevel, entry.expectedRisk);
      assert.equal(report.installRecommendation, entry.expectedRecommendation);
      for (const tag of entry.mustContainTags ?? []) {
        assert.ok(report.riskTags.includes(tag), `expected ${entry.name} to include ${tag}`);
      }
      for (const tag of entry.mustNotContainTags ?? []) {
        assert.ok(!report.riskTags.includes(tag), `expected ${entry.name} not to include ${tag}`);
      }
    });
  }
});
