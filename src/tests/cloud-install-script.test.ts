import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const projectRoot = resolve(__dirname, '..', '..');
const installerPath = join(projectRoot, 'scripts', 'cloud-install.sh');

function installFakeCommands(root: string): { bin: string; npmLog: string; agentguardLog: string } {
  const bin = join(root, 'bin');
  const npmLog = join(root, 'npm-call.json');
  const agentguardLog = join(root, 'agentguard-calls.jsonl');
  mkdirSync(bin, { recursive: true });

  const npm = join(bin, 'npm');
  writeFileSync(npm, [
    '#!/usr/bin/env node',
    'const fs = require("node:fs");',
    'fs.writeFileSync(process.env.NPM_CALL_LOG, JSON.stringify(process.argv.slice(2)));',
    '',
  ].join('\n'));
  chmodSync(npm, 0o755);

  const agentguard = join(bin, 'agentguard');
  writeFileSync(agentguard, [
    '#!/usr/bin/env node',
    'const fs = require("node:fs");',
    'fs.appendFileSync(process.env.AGENTGUARD_CALL_LOG, JSON.stringify(process.argv.slice(2)) + "\\n");',
    'if (process.argv[2] === "connect") {',
    '  process.stdout.write("Registered local AgentGuard agent (agt_cloud_test).\\n");',
    '  process.stdout.write("Open this link to bind this agent to your account:\\n");',
    '  process.stdout.write("https://agentguard.example/activate?token=cloud-test\\n");',
    '}',
    '',
  ].join('\n'));
  chmodSync(agentguard, 0o755);

  return { bin, npmLog, agentguardLog };
}

async function runInstaller(extraEnv: Record<string, string> = {}) {
  const root = mkdtempSync(join(tmpdir(), 'agentguard-cloud-install-'));
  const commands = installFakeCommands(root);
  assert.ok(existsSync(installerPath), 'cloud installer script must exist');
  const result = await execFileAsync('bash', [installerPath], {
    cwd: root,
    env: {
      ...process.env,
      PATH: `${commands.bin}:${process.env.PATH || ''}`,
      NPM_CALL_LOG: commands.npmLog,
      AGENTGUARD_CALL_LOG: commands.agentguardLog,
      AGENTGUARD_PACKAGE_SPEC: '@goplus/agentguard@1.2.3',
      AGENTGUARD_CLOUD_URL: 'https://agentguard.example',
      ...extraEnv,
    },
  });
  return {
    ...result,
    npmArgs: JSON.parse(readFileSync(commands.npmLog, 'utf8')) as string[],
    agentguardCalls: readFileSync(commands.agentguardLog, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as string[]),
  };
}

describe('Cloud install script', () => {
  it('uses init auto-discovery and returns the activation URL as its final line', async () => {
    const result = await runInstaller();

    assert.deepEqual(result.npmArgs, ['install', '-g', '@goplus/agentguard@1.2.3']);
    assert.deepEqual(result.agentguardCalls, [
      ['init', '--cloud', 'https://agentguard.example'],
      ['connect', '--cloud', 'https://agentguard.example'],
    ]);
    assert.equal(result.stdout.trimEnd().split('\n').at(-1),
      'AGENTGUARD_ACTIVATION_URL=https://agentguard.example/activate?token=cloud-test');
  });

  it('passes an explicitly configured agent host to init', async () => {
    const result = await runInstaller({ AGENTGUARD_AGENT: 'dsh' });

    assert.deepEqual(result.agentguardCalls[0], [
      'init', '--agent', 'dsh', '--cloud', 'https://agentguard.example',
    ]);
  });

  it('rejects explicit hosts that cannot return an Agent JWT activation link', async () => {
    await assert.rejects(
      runInstaller({ AGENTGUARD_AGENT: 'codex' }),
      (error: NodeJS.ErrnoException & { stderr?: string }) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr || '', /supports auto, openclaw, hermes, or dsh/);
        return true;
      }
    );
  });
});
