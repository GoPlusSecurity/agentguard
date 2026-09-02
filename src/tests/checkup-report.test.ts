import { execFile } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const execFileAsync = promisify(execFile);
const projectRoot = resolve(__dirname, '..', '..');
const reportScript = join(projectRoot, 'skills', 'agentguard', 'scripts', 'checkup-report.js');

describe('checkup HTML report', () => {
  it('includes DSH plugins in the scanned artifact total', async () => {
    const inputPath = join(tmpdir(), `agentguard-checkup-report-input-${process.pid}.json`);
    writeFileSync(inputPath, JSON.stringify({
      timestamp: '2026-09-02T00:00:00.000Z',
      composite_score: 90,
      tier: 'S',
      dimensions: {},
      recommendations: [],
      skills_scanned: 2,
      dsh_plugins_scanned: 3,
      protection_level: 'balanced',
    }));

    const { stdout, stderr } = await execFileAsync('node', [reportScript, '--file', inputPath], {
      env: { ...process.env, CI: '1' },
    });

    assert.equal(stderr, '');
    const html = readFileSync(stdout.trim(), 'utf8');
    assert.match(html, />5<\/span>\s*<span[^>]*data-i18n="artifacts_scanned">Scanned artifacts<\/span>/);
    assert.match(html, /2 skills and 3 DSH plugins/);
  });
});
