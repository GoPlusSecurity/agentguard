import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

describe('postinstall', () => {
  it('prints the expected next steps after preparing local config', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-postinstall-home-'));
    const postinstallPath = resolve('dist', 'postinstall.js');

    const { stdout } = await execFileAsync(process.execPath, [postinstallPath], {
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    assert.match(stdout, /AgentGuard local config ready:/);
    assert.match(stdout, /agentguard init --agent <agent>/);
    assert.match(stdout, /agentguard connect/);
    assert.match(stdout, /agentguard checkup/);
  });
});
