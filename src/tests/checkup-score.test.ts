import { execFile } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

const execFileAsync = promisify(execFile);
const projectRoot = resolve(__dirname, '..', '..');
const scoreScript = join(projectRoot, 'skills', 'agentguard', 'scripts', 'checkup-score.js');

describe('checkup deterministic scoring', () => {
  it('scores DSH plugin findings as code safety findings when no skills are installed', async () => {
    const inputPath = join(tmpdir(), `agentguard-checkup-score-input-${process.pid}.json`);
    writeFileSync(inputPath, JSON.stringify({
      skills: [],
      dsh_plugins: [{
        name: 'risky-dsh-plugin',
        risk_level: 'critical',
        findings: [{
          rule: 'SHELL_EXEC',
          severity: 'CRITICAL',
          file: 'index.js',
          line: 4,
        }],
      }],
      credential_files: {},
      dlp: {},
      network: {},
      runtime: {},
      web3: {},
    }));

    const { stdout, stderr } = await execFileAsync('node', [scoreScript, '--file', inputPath]);

    assert.equal(stderr, '');
    const result = JSON.parse(stdout) as {
      dimensions: { code_safety: { score: number; findings: Array<{ severity: string; text: string }> } };
    };
    assert.equal(result.dimensions.code_safety.score, 85);
    assert.deepEqual(result.dimensions.code_safety.findings, [{
      severity: 'CRITICAL',
      text: 'SHELL_EXEC in risky-dsh-plugin:index.js:4',
    }]);
  });
});
