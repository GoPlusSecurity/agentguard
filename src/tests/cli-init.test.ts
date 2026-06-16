import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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

  it('shows API-key Cloud auth without requiring Agent JWT fields', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-status-api-key-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-status-api-key-cwd-'));
    const cliPath = resolve('dist', 'cli.js');
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, 'config.json'), JSON.stringify({
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      apiKey: 'ag_live_status_key_123456',
      agentHost: 'codex',
      policyCachePath: join(home, 'policy-cache.json'),
      auditPath: join(home, 'audit.jsonl'),
      eventSpoolPath: join(home, 'events-spool.jsonl'),
    }, null, 2));

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'status'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    assert.match(stdout, /Cloud auth: connected via API key/);
    assert.match(stdout, /API key: ag_live_/);
    assert.match(stdout, /Agent JWT: not used for this connection/);
    assert.doesNotMatch(stdout, /Agent ID: not configured/);
  });

  it('shows Agent JWT Cloud auth without requiring API key fields', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-status-jwt-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-status-jwt-cwd-'));
    const cliPath = resolve('dist', 'cli.js');
    mkdirSync(home, { recursive: true });
    writeFileSync(join(home, 'config.json'), JSON.stringify({
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      agentId: 'agt_status_test',
      agentJwt: 'agent.jwt.status',
      agentHost: 'openclaw',
      policyCachePath: join(home, 'policy-cache.json'),
      auditPath: join(home, 'audit.jsonl'),
      eventSpoolPath: join(home, 'events-spool.jsonl'),
    }, null, 2));

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'status'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    assert.match(stdout, /Cloud auth: connected via Agent JWT/);
    assert.match(stdout, /API key: not used for this connection/);
    assert.match(stdout, /Agent ID: agt_status_test/);
    assert.match(stdout, /Agent JWT: configured/);
    assert.match(stdout, /Agent account: bound/);
    assert.doesNotMatch(stdout, /API key: not configured/);
  });

  it('disconnect removes the managed system subscribe cron job', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-disconnect-cron-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-disconnect-cron-cwd-'));
    const bin = join(cwd, 'bin');
    const crontabPath = join(cwd, 'crontab.txt');
    const cliPath = resolve('dist', 'cli.js');
    mkdirSync(home, { recursive: true });
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(home, 'config.json'), JSON.stringify({
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      apiKey: 'ag_live_status_key_123456',
      agentHost: 'codex',
      threatFeedCronName: 'agentguard-custom-feed',
      threatFeedCronInstalledAt: '2026-05-27T00:00:00.000Z',
      policyCachePath: join(home, 'policy-cache.json'),
      auditPath: join(home, 'audit.jsonl'),
      eventSpoolPath: join(home, 'events-spool.jsonl'),
    }, null, 2));
    writeFileSync(crontabPath, [
      '# AgentGuard begin agentguard-custom-feed',
      '0 * * * * /tmp/agentguard-custom-feed.sh',
      '# AgentGuard end agentguard-custom-feed',
      '15 * * * * /tmp/other-job.sh',
      '',
    ].join('\n'));
    const fakeCrontab = join(bin, 'crontab');
    writeFileSync(fakeCrontab, [
      '#!/usr/bin/env node',
      'const fs = require("node:fs");',
      'const path = process.env.FAKE_CRONTAB_PATH;',
      'if (process.argv[2] === "-l") {',
      '  if (fs.existsSync(path)) process.stdout.write(fs.readFileSync(path, "utf8"));',
      '  process.exit(0);',
      '}',
      'if (process.argv[2] === "-") {',
      '  let data = "";',
      '  process.stdin.on("data", (chunk) => data += chunk);',
      '  process.stdin.on("end", () => fs.writeFileSync(path, data));',
      '}',
      '',
    ].join('\n'));
    chmodSync(fakeCrontab, 0o755);

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'disconnect'], {
      cwd,
      env: {
        ...process.env,
        AGENTGUARD_HOME: home,
        FAKE_CRONTAB_PATH: crontabPath,
        PATH: `${bin}:${process.env.PATH || ''}`,
      },
    });

    const crontab = readFileSync(crontabPath, 'utf8');
    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
      apiKey?: string;
      threatFeedCronName?: string;
      threatFeedCronInstalledAt?: string;
    };
    assert.equal(config.apiKey, undefined);
    assert.equal(config.threatFeedCronName, undefined);
    assert.equal(config.threatFeedCronInstalledAt, undefined);
    assert.match(stdout, /Removed AgentGuard subscribe cron job "agentguard-custom-feed" from: system/);
    assert.doesNotMatch(crontab, /AgentGuard begin agentguard-custom-feed/);
    assert.match(crontab, /other-job/);
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

  it('overwrites existing agent templates by default', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-force-default-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-force-default-cwd-'));
    const cliPath = resolve('dist', 'cli.js');
    const pluginDir = join(cwd, '.openclaw', 'plugins', 'agentguard');
    const skillDir = join(cwd, '.openclaw', 'skills', 'agentguard');
    mkdirSync(pluginDir, { recursive: true });
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(join(pluginDir, 'index.js'), 'old plugin template');
    writeFileSync(join(skillDir, 'SKILL.md'), 'old skill template');

    await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'openclaw'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home, OPENCLAW_STATE_DIR: join(cwd, '.openclaw') },
    });

    const template = readFileSync(join(pluginDir, 'index.js'), 'utf8');
    assert.notEqual(template, 'old plugin template');
    assert.match(template, /loadAgentGuard/);
    const skill = readFileSync(join(skillDir, 'SKILL.md'), 'utf8');
    assert.notEqual(skill, 'old skill template');
    assert.match(skill, /agentguard approve --last --once/);
  });

  it('preserves existing agent templates with --no-force', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-no-force-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-no-force-cwd-'));
    const cliPath = resolve('dist', 'cli.js');
    const pluginDir = join(cwd, '.openclaw', 'plugins', 'agentguard');
    const skillDir = join(cwd, '.openclaw', 'skills', 'agentguard');
    mkdirSync(pluginDir, { recursive: true });
    mkdirSync(skillDir, { recursive: true });
    writeFileSync(join(pluginDir, 'index.js'), 'old plugin template');
    writeFileSync(join(skillDir, 'SKILL.md'), 'old skill template');

    await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'openclaw', '--no-force'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home, OPENCLAW_STATE_DIR: join(cwd, '.openclaw') },
    });

    assert.equal(readFileSync(join(pluginDir, 'index.js'), 'utf8'), 'old plugin template');
    assert.equal(readFileSync(join(skillDir, 'SKILL.md'), 'utf8'), 'old skill template');
  });

  it('accepts Hermes and QClaw agent installers', async () => {
    for (const agent of ['hermes', 'qclaw']) {
      const home = mkdtempSync(join(tmpdir(), `agentguard-init-${agent}-home-`));
      const cwd = mkdtempSync(join(tmpdir(), `agentguard-init-${agent}-cwd-`));
      const hermesHome = join(home, '.hermes');
      const cliPath = resolve('dist', 'cli.js');

      await execFileAsync(process.execPath, [cliPath, 'init', '--agent', agent, '--force'], {
        cwd,
        env: {
          ...process.env,
          AGENTGUARD_HOME: home,
          ...(agent === 'hermes' ? { HERMES_HOME: hermesHome } : {}),
        },
      });

      const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as { agentHost?: string };
      assert.equal(config.agentHost, agent);
      if (agent === 'hermes') {
        assert.ok(existsSync(join(hermesHome, 'plugins', 'agentguard', 'plugin.yaml')));
        assert.ok(readFileSync(join(hermesHome, 'config.yaml'), 'utf8').includes('- agentguard'));
      }
    }
  });

  it('normalizes --agent values to lowercase', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-uppercase-home-'));
    const cwd = mkdtempSync(join(tmpdir(), 'agentguard-init-uppercase-cwd-'));
    const hermesHome = join(home, '.hermes');
    const cliPath = resolve('dist', 'cli.js');

    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'init', '--agent', 'Hermes', '--force'], {
      cwd,
      env: { ...process.env, AGENTGUARD_HOME: home, HERMES_HOME: hermesHome },
    });

    const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as { agentHost?: string };
    assert.equal(config.agentHost, 'hermes');
    assert.match(stdout, /Installed hermes template:/);
    assert.ok(stdout.includes(join(hermesHome, 'plugins', 'agentguard')));
    assert.match(stdout, /Hermes native plugin enabled in config\.yaml/);
    assert.ok(readFileSync(join(hermesHome, 'config.yaml'), 'utf8').includes('- agentguard'));
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
    assert.ok(existsSync(join(cwd, '.hermes', 'plugins', 'agentguard', 'plugin.yaml')));
    assert.ok(readFileSync(join(cwd, '.hermes', 'config.yaml'), 'utf8').includes('- agentguard'));
    assert.ok(existsSync(join(cwd, '.codex', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(existsSync(join(cwd, '.codex', 'agentguard-hook.json')));
    assert.match(stdout, /Installed openclaw template:/);
    assert.match(stdout, /Installed hermes template:/);
    assert.match(stdout, /Hermes native plugin enabled in config\.yaml/);
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
