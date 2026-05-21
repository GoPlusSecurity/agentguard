import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

describe('postinstall', () => {
  it('prints the expected next steps after preparing local config', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-postinstall-home-'));
    const postinstallPath = resolve('dist', 'postinstall.js');

    const { stdout } = await execFileAsync(process.execPath, [postinstallPath], {
      env: { ...process.env, AGENTGUARD_HOME: home, AGENTGUARD_SKIP_PACKAGE_NEXT_STEPS: '1' },
    });

    assert.match(stdout, /AgentGuard local config ready:/);
    assert.match(stdout, /agentguard init --agent auto/);
    assert.doesNotMatch(stdout, /agentguard connect/);
    assert.doesNotMatch(stdout, /agentguard checkup/);

    const nextSteps = readFileSync(join(home, 'next-steps.txt'), 'utf8');
    assert.match(nextSteps, /agentguard init --agent auto/);
    assert.doesNotMatch(nextSteps, /agentguard connect/);
    assert.doesNotMatch(nextSteps, /agentguard checkup/);
  });
});
