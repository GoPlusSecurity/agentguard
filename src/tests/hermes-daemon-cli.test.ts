import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';

const homes: string[] = [];
const children: ChildProcess[] = [];

afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await once(child, 'exit');
    }
  }
  for (const home of homes.splice(0)) rmSync(home, { recursive: true, force: true });
});

describe('Hermes evaluator daemon CLI', () => {
  it('keeps one daemon alive until SIGTERM and removes its Unix socket', {
    skip: process.platform === 'win32',
  }, async () => {
    // Keep the Unix socket below macOS's short sockaddr_un path limit.
    const home = mkdtempSync(join(tmpdir(), 'ag-h-'));
    homes.push(home);
    const socketPath = join(home, 'run', 'hermes-evaluator.sock');
    const child = spawn(process.execPath, [resolve('dist', 'cli.js'), 'hermes-daemon'], {
      env: { ...process.env, AGENTGUARD_HOME: home },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);

    await waitForPathOrEarlyExit(socketPath, child, 2_000);
    assert.equal(child.exitCode, null);

    child.kill('SIGTERM');
    const [code, signal] = await once(child, 'exit') as [number | null, NodeJS.Signals | null];
    assert.equal(code, 0);
    assert.equal(signal, null);
    assert.equal(existsSync(socketPath), false);
    assert.equal(existsSync(`${socketPath}.lock`), false);
  });

  it('exits when the Unix lease helper is lost', {
    skip: process.platform === 'win32',
  }, async () => {
    const home = mkdtempSync(join(tmpdir(), 'ag-h-'));
    homes.push(home);
    const socketPath = join(home, 'run', 'hermes-evaluator.sock');
    const helper = join(home, 'fake-python');
    const stopFile = join(home, 'stop-lease-helper');
    writeFileSync(
      helper,
      '#!/bin/sh\nprintf "LOCKED\\n"\nwhile [ ! -f "$AGENTGUARD_TEST_LEASE_STOP" ]; do sleep 0.02; done\n',
      { mode: 0o700 },
    );
    chmodSync(helper, 0o700);
    const child = spawn(process.execPath, [resolve('dist', 'cli.js'), 'hermes-daemon'], {
      env: {
        ...process.env,
        AGENTGUARD_HOME: home,
        AGENTGUARD_HERMES_PYTHON: helper,
        AGENTGUARD_TEST_LEASE_STOP: stopFile,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);

    await waitForPathOrEarlyExit(socketPath, child, 10_000);
    writeFileSync(stopFile, 'stop');
    const [code, signal] = await waitForExitOrTimeout(child, 5_000);
    assert.equal(code, 0);
    assert.equal(signal, null);
    assert.equal(existsSync(socketPath), false);
  });
});

async function waitForPathOrEarlyExit(
  path: string,
  child: ChildProcess,
  timeoutMs: number,
): Promise<void> {
  const startedAt = Date.now();
  let stderr = '';
  child.stderr?.setEncoding('utf8');
  child.stderr?.on('data', chunk => { stderr += chunk; });
  while (!existsSync(path)) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Hermes daemon exited before creating its socket: ${stderr.trim()}`);
    }
    if (Date.now() - startedAt >= timeoutMs) {
      throw new Error(`Timed out waiting for Hermes daemon socket: ${path}`);
    }
    await new Promise(resolveDelay => setTimeout(resolveDelay, 10));
  }
}

async function waitForExitOrTimeout(
  child: ChildProcess,
  timeoutMs: number,
): Promise<[number | null, NodeJS.Signals | null]> {
  return await new Promise((resolveExit, rejectExit) => {
    const timer = setTimeout(() => {
      child.off('exit', onExit);
      rejectExit(new Error('Timed out waiting for Hermes daemon exit'));
    }, timeoutMs);
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      clearTimeout(timer);
      resolveExit([code, signal]);
    };
    child.once('exit', onExit);
  });
}
