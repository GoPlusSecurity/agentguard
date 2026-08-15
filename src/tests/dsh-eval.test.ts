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
  expectedRuntimeRisk: RiskLevel;
  expectedReviewPriority: 'routine' | 'elevated' | 'high' | 'urgent';
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
      assert.equal(report.runtimeSurfaceRiskLevel, entry.expectedRuntimeRisk);
      assert.equal(report.reviewPriority, entry.expectedReviewPriority);
      for (const tag of entry.mustContainTags ?? []) {
        assert.ok(report.riskTags.includes(tag), `expected ${entry.name} to include ${tag}`);
      }
      for (const tag of entry.mustNotContainTags ?? []) {
        assert.ok(!report.riskTags.includes(tag), `expected ${entry.name} not to include ${tag}`);
      }
      if (entry.name === 'generated-runtime') {
        assert.ok(report.findings.some(finding => finding.likelyGenerated));
      }
      if (entry.name === 'test-only-shell') {
        assert.ok(report.findings.some(finding => finding.sourceCategory === 'test'));
      }
      if (entry.name === 'data-key-sample') {
        assert.ok(report.findings.some(finding => finding.sourceCategory === 'data'));
      }
      if (entry.name === 'active-skill-injection') {
        assert.ok(report.findings.some(finding =>
          finding.ruleId === 'PROMPT_INJECTION'
            && finding.sourceCategory === 'runtime'
            && finding.runtimeRelevance === 'indirect'));
      }
      if (entry.name === 'data-local-loader') {
        assert.ok(report.findings.some(finding =>
          finding.ruleId === 'DYNAMIC_MODULE_LOADING'
            && finding.sourceCategory === 'runtime'
            && finding.runtimeRelevance === 'direct'));
      }
    });
  }
});
