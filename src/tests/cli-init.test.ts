import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

describe('init CLI', () => {
  it('persists the selected agent host in AgentGuard config', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-cwd-'));
    const cliPath = resolve('dist', 'cli.js');

    await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'codex', '--force'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as { agentHost?: string };
    assert.equal(config.agentHost, 'codex');
  });
});
