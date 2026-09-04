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
      dsh_plugins: [{
        name: 'nested-risky-plugin',
        path: '/tmp/nested-risky-plugin',
        risk_level: 'high',
        findings: [{ rule: 'SHELL_EXEC', severity: 'HIGH', file: 'index.js', line: 4 }],
      }, {
        name: '<script id="plugin-injection">boom</script>',
        path: '/tmp/<bundle>',
        risk_level: 'medium',
        findings: [{ rule: '<RULE>', severity: 'MEDIUM', file: '<entry>.js', line: 7 }],
      }],
      protection_level: 'balanced',
    }));

    const { stdout, stderr } = await execFileAsync('node', [reportScript, '--file', inputPath], {
      env: { ...process.env, CI: '1' },
    });

    assert.equal(stderr, '');
    const html = readFileSync(stdout.trim(), 'utf8');
    assert.match(html, />5<\/span>\s*<span[^>]*data-i18n="artifacts_scanned">Scanned artifacts<\/span>/);
    assert.match(html, /2 skills and 3 DSH plugins/);
    assert.match(html, /nested-risky-plugin/);
    assert.match(html, /SHELL_EXEC/);
    assert.match(html, /index\.js:4/);
    assert.match(html, /&lt;script id=&quot;plugin-injection&quot;&gt;boom&lt;\/script&gt;/);
    assert.match(html, /\/tmp\/&lt;bundle&gt;/);
    assert.match(html, /&lt;RULE&gt;/);
    assert.match(html, /&lt;entry&gt;\.js:7/);
    assert.doesNotMatch(html, /<script id="plugin-injection">/);
  });

  it('renders legacy report data without per-plugin DSH results', async () => {
    const inputPath = join(tmpdir(), `agentguard-checkup-report-legacy-${process.pid}.json`);
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
    assert.match(html, /2 skills and 3 DSH plugins/);
  assert.doesNotMatch(html, /data-i18n="dsh_scan_results"/);
  });
});
