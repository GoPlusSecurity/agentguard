import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const projectRoot = resolve(__dirname, '..', '..');
const cliPath = join(projectRoot, 'dist', 'cli.js');
const packageJson = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8')) as { version: string };

function runCli(args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('node', [cliPath, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (data: Buffer) => (stdout += data.toString()));
    child.stderr.on('data', (data: Buffer) => (stderr += data.toString()));
    child.on('close', (code) => {
      resolvePromise({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

describe('AgentGuard CLI', () => {
  it('prints the package version for --version', async () => {
    const result = await runCli(['--version']);

    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout.trim(), packageJson.version);
  });
});
