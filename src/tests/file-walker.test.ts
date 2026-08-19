import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { walkDirectoryWithCoverage } from '../scanner/file-walker.js';

const roots: string[] = [];

async function fixture(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agentguard-file-walker-'));
  roots.push(root);
  for (const [relativePath, content] of Object.entries(files)) {
    const filePath = join(root, relativePath);
    await mkdir(join(filePath, '..'), { recursive: true });
    await writeFile(filePath, content, 'utf8');
  }
  return root;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

describe('scanner file coverage', () => {
  it('reports complete coverage when every eligible file is read', async () => {
    const root = await fixture({ 'a.ts': 'export {}', 'nested/b.json': '{}' });
    const snapshot = await walkDirectoryWithCoverage(root);
    assert.equal(snapshot.files.length, 2);
    assert.deepEqual(snapshot.coverage, {
      discovered: 2,
      scanned: 2,
      skipped: 0,
      skippedByReason: { fileLimit: 0, oversized: 0, unreadable: 0 },
      complete: true,
    });
  });

  it('records files omitted by the deterministic file limit', async () => {
    const root = await fixture({ 'a.ts': 'a', 'b.ts': 'b', 'c.ts': 'c' });
    const snapshot = await walkDirectoryWithCoverage(root, { maxFiles: 2 });
    assert.deepEqual(snapshot.files.map(file => file.relativePath), ['a.ts', 'b.ts']);
    assert.deepEqual(snapshot.coverage, {
      discovered: 3,
      scanned: 2,
      skipped: 1,
      skippedByReason: { fileLimit: 1, oversized: 0, unreadable: 0 },
      complete: false,
    });
  });

  it('records oversized security-relevant files instead of silently skipping them', async () => {
    const root = await fixture({ 'large.ts': '0123456789' });
    const snapshot = await walkDirectoryWithCoverage(root, { maxFileBytes: 5 });
    assert.equal(snapshot.files.length, 0);
    assert.deepEqual(snapshot.coverage.skippedByReason, {
      fileLimit: 0, oversized: 1, unreadable: 0,
    });
    assert.equal(snapshot.coverage.complete, false);
  });

  it('records ordinary read failures while preserving unsafe-path fail-closed behavior', async () => {
    const root = await fixture({ 'unreadable.ts': 'export {}' });
    const snapshot = await walkDirectoryWithCoverage(root, {
      readFile: async () => { throw new Error('simulated read failure'); },
    });
    assert.equal(snapshot.files.length, 0);
    assert.deepEqual(snapshot.coverage.skippedByReason, {
      fileLimit: 0, oversized: 0, unreadable: 1,
    });
    assert.equal(snapshot.coverage.complete, false);
  });
});
