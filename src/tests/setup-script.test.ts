import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const projectRoot = resolve(__dirname, '..', '..');
const setupPath = join(projectRoot, 'setup.sh');

function makeStubbedPath(): string {
  const bin = mkdtempSync(join(tmpdir(), 'agentguard-setup-bin-'));
  const npm = join(bin, 'npm');
  writeFileSync(
    npm,
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      'if [ "${1:-}" = "run" ] && [ "${2:-}" = "build" ]; then',
      '  mkdir -p dist',
      'fi',
      'exit 0',
      '',
    ].join('\n')
  );
  chmodSync(npm, 0o700);
  return `${bin}:${process.env.PATH ?? ''}`;
}

async function runSetup(args: string[], home: string): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync('bash', [setupPath, ...args], {
    cwd: projectRoot,
    env: {
      ...process.env,
      HOME: home,
      PATH: makeStubbedPath(),
      npm_config_ignore_scripts: 'true',
    },
    maxBuffer: 1024 * 1024,
  });
}

describe('setup.sh', () => {
  it('falls back to the Claude Code skill path when no agent directory is detected', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-setup-home-'));

    const { stdout } = await runSetup([], home);

    const skillDir = join(home, '.claude', 'skills', 'agentguard');
    assert.match(stdout, /Platform detected: claude-code/);
    assert.ok(existsSync(join(skillDir, 'SKILL.md')));
    assert.ok(existsSync(join(skillDir, 'scripts', 'trust-cli.js')));
    assert.equal(JSON.parse(readFileSync(join(skillDir, 'package.json'), 'utf8')).type, 'module');
  });

  it('installs to an explicit target path without relying on auto-detection', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-setup-home-'));
    const target = join(home, 'custom skills');

    const { stdout } = await runSetup(['--target', target], home);

    const skillDir = join(target, 'agentguard');
    assert.match(stdout, /Platform detected: custom/);
    assert.ok(existsSync(join(skillDir, 'SKILL.md')));
    assert.ok(existsSync(join(skillDir, 'scripts', 'action-cli.js')));
  });
});
