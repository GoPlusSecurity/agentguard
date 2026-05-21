import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

describe('init CLI', () => {
  it('prints required init guidance when run without a command', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-guidance-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-guidance-cwd-'));
    const cliPath = resolve('dist', 'cli.js');

    const { stdout } = await execFileAsync(process.execPath, [cliPath], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    assert.match(stdout, /Required next step:/);
    assert.match(stdout, /agentguard init --agent auto/);
    assert.doesNotMatch(stdout, /agentguard connect/);
    assert.doesNotMatch(stdout, /agentguard checkup/);
  });

  it('prints required init guidance from status when no agent host is saved', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-status-guidance-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-status-guidance-cwd-'));
    const cliPath = resolve('dist', 'cli.js');

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'status'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    assert.match(stdout, /Agent host: not configured/);
    assert.match(stdout, /agentguard init --agent auto/);
    assert.doesNotMatch(stdout, /agentguard connect/);
    assert.doesNotMatch(stdout, /agentguard checkup/);
  });

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

  it('accepts Hermes and QClaw agent installers', async () => {
    for (const agent of ['hermes', 'qclaw']) {
      const home = mkdtempSync(join(tmpdir(), `agentguard-init-${agent}-home-`));
      const cwd = mkdtempSync(join(tmpdir(), `agentguard-init-${agent}-cwd-`));
      const cliPath = resolve('dist', 'cli.js');

      await execFileAsync(process.execPath, [cliPath, 'init', '--agent', agent, '--force'], {
        cwd,
        env: { ...process.env, AGENTGUARD_HOME: home },
      });

      const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as { agentHost?: string };
      assert.equal(config.agentHost, agent);
    }
  });

  it('normalizes --agent values to lowercase', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-uppercase-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-uppercase-cwd-'));
    const cliPath = resolve('dist', 'cli.js');

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'Hermes', '--force'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as { agentHost?: string };
    assert.equal(config.agentHost, 'hermes');
    assert.match(stdout, /Installed hermes template:/);
  });

  it('auto-initializes detected agents in detection order', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-auto-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-auto-cwd-'));
    const cliPath = resolve('dist', 'cli.js');
    mkdirSync(join(cwd, '.codex'), { recursive: true });
    mkdirSync(join(cwd, '.openclaw'), { recursive: true });
    mkdirSync(join(cwd, '.hermes'), { recursive: true });

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'auto', '--force'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
      agentHost?: string;
      agentHosts?: string[];
    };
    assert.equal(config.agentHost, 'openclaw');
    assert.deepEqual(config.agentHosts, ['openclaw', 'hermes', 'codex']);
    assert.ok(existsSync(join(cwd, '.openclaw', 'plugins', 'agentguard', 'openclaw.plugin.json')));
    assert.ok(existsSync(join(cwd, '.hermes', 'skills', 'agentguard')));
    assert.ok(readFileSync(join(cwd, '.hermes', 'config.yaml'), 'utf8').includes('hermes-hook.js'));
    assert.ok(existsSync(join(cwd, '.codex', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(existsSync(join(cwd, '.codex', 'agentguard-hook.json')));
    assert.match(stdout, /Installed openclaw template:/);
    assert.match(stdout, /Installed hermes template:/);
    assert.match(stdout, /Installed codex template:/);
  });

  it('does not fail auto init when no supported agent directory exists', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-auto-empty-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-auto-empty-cwd-'));
    const cliPath = resolve('dist', 'cli.js');

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'auto'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
      agentHost?: string;
      agentHosts?: string[];
    };
    assert.equal(config.agentHost, undefined);
    assert.equal(config.agentHosts, undefined);
    assert.match(stdout, /No supported agent directories found/);
  });

  it('continues auto init after one detected agent fails', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-auto-failure-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-auto-failure-cwd-'));
    const cliPath = resolve('dist', 'cli.js');
    writeFileSync(join(cwd, '.openclaw'), 'not a directory');
    mkdirSync(join(cwd, '.hermes'), { recursive: true });

    const { stdout, stderr } = await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'auto', '--force'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
      agentHost?: string;
      agentHosts?: string[];
    };
    assert.equal(config.agentHost, 'hermes');
    assert.deepEqual(config.agentHosts, ['hermes']);
    assert.match(stdout, /Installed hermes template:/);
    assert.match(stderr, /Failed to initialize openclaw/);
  });
});
