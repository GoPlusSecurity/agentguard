import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

type BenchmarkCase = {
  id: string;
  repository: string;
  revision: string;
  artifactHash?: string;
  riskLevel?: string;
  runtimeSurfaceRiskLevel?: string;
  reviewPriority?: string;
  findingCounts?: Record<string, number>;
};

type BenchmarkFile = {
  schemaVersion: number;
  baseline: string;
  rulesFrozenAt: string;
  cases: BenchmarkCase[];
};

function load(name: string): BenchmarkFile {
  return JSON.parse(readFileSync(resolve('benchmarks/dsh', name), 'utf8')) as BenchmarkFile;
}

describe('DSH real-world benchmark assets', () => {
  it('pins unique HTTPS repositories to full commits', () => {
    const manifest = load('real-world.manifest.json');
    assert.equal(manifest.schemaVersion, 1);
    assert.ok(manifest.cases.length >= 5);
    assert.equal(new Set(manifest.cases.map(entry => entry.id)).size, manifest.cases.length);
    for (const entry of manifest.cases) {
      assert.match(entry.id, /^[A-Za-z0-9][A-Za-z0-9._-]*$/);
      assert.match(entry.repository, /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/);
      assert.match(entry.revision, /^[0-9a-f]{40}$/);
    }
  });

  it('keeps a complete deterministic snapshot for every manifest case', () => {
    const manifest = load('real-world.manifest.json');
    const snapshot = load('real-world.snapshot.json');
    assert.equal(snapshot.schemaVersion, manifest.schemaVersion);
    assert.equal(snapshot.baseline, manifest.baseline);
    assert.equal(snapshot.rulesFrozenAt, manifest.rulesFrozenAt);
    assert.deepEqual(snapshot.cases.map(entry => entry.id), manifest.cases.map(entry => entry.id));
    for (let index = 0; index < snapshot.cases.length; index += 1) {
      const actual = snapshot.cases[index];
      const source = manifest.cases[index];
      assert.equal(actual.repository, source.repository);
      assert.equal(actual.revision, source.revision);
      assert.match(actual.artifactHash ?? '', /^sha256:[0-9a-f]{64}$/);
      assert.match(actual.riskLevel ?? '', /^(?:low|medium|high|critical)$/);
      assert.match(actual.runtimeSurfaceRiskLevel ?? '', /^(?:low|medium|high|critical)$/);
      assert.match(actual.reviewPriority ?? '', /^(?:routine|elevated|high|urgent)$/);
      assert.ok(actual.findingCounts && typeof actual.findingCounts === 'object');
      assert.equal('snippet' in actual, false, 'benchmark snapshots must not store matched source snippets');
    }
  });
});
