import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const CLI = resolve('dist', 'cli.js');

/** Isolated AgentGuard home so the suite never reads the developer's own config. */
function seedHome(privacy?: Record<string, unknown>): string {
  const home = mkdtempSync(join(tmpdir(), 'agentguard-onboarding-'));
  writeFileSync(
    join(home, 'config.json'),
    JSON.stringify({
      version: 1,
      level: 'balanced',
      agentHost: 'claude-code',
      policyCachePath: join(home, 'policy-cache.json'),
      auditPath: join(home, 'audit.jsonl'),
      eventSpoolPath: join(home, 'events-spool.jsonl'),
      ...(privacy ? { privacy } : {}),
    }),
  );
  return home;
}

function runStatus(home: string, apiKey = ''): string {
  try {
    return execFileSync(process.execPath, [CLI, 'status'], {
      env: { ...process.env, AGENTGUARD_HOME: home, TYPESAFE_API_KEY: apiKey },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    return String((error as { stdout?: string }).stdout ?? '');
  }
}

describe('Privacy enhancement onboarding', () => {
  /**
   * Without a hint the feature is invisible: nothing in install or init mentions
   * it, so the only people who find it are the ones who already knew to look.
   */
  it('tells the user the enhancement exists when it is off', () => {
    const home = seedHome();
    try {
      const out = runStatus(home);
      assert.match(out, /Optional: enhanced privacy detection/);
      assert.match(out, /agentguard privacy status/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  /**
   * The worst state to leave silent: the user believes the enhancement is on,
   * so a clean result reads as a cleared one when nothing was actually judged.
   */
  it('is loud when enabled but no key is available', () => {
    const home = seedHome({ mode: 'jev' });
    try {
      const out = runStatus(home);
      assert.match(out, /INACTIVE/);
      assert.match(out, /TYPESAFE_API_KEY/);
      assert.match(out, /privacy enable --api-key/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('says nothing once the enhancement is actually working', () => {
    const home = seedHome({ mode: 'jev' });
    try {
      const out = runStatus(home, 'test-key');
      assert.doesNotMatch(out, /Optional: enhanced privacy detection/);
      assert.doesNotMatch(out, /INACTIVE/);
      assert.match(out, /Privacy enhancement: jev/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('surfaces the hint at the end of init, where setup actually happens', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-init-home-'));
    const fakeHome = mkdtempSync(join(tmpdir(), 'agentguard-fake-user-'));
    try {
      const { stdout } = await execFileAsync(process.execPath, [CLI, 'init', '--agent', 'claude-code'], {
        env: { ...process.env, AGENTGUARD_HOME: home, HOME: fakeHome, TYPESAFE_API_KEY: '' },
        cwd: fakeHome,
      });
      assert.match(stdout, /Optional: enhanced privacy detection/);
    } finally {
      rmSync(home, { recursive: true, force: true });
      rmSync(fakeHome, { recursive: true, force: true });
    }
  });

  it('mentions the enhancement in the postinstall next steps', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-pi-home-'));
    try {
      const { stdout } = await execFileAsync(process.execPath, [resolve('dist', 'postinstall.js')], {
        env: { ...process.env, AGENTGUARD_HOME: home, AGENTGUARD_SKIP_PACKAGE_NEXT_STEPS: '1' },
      });
      // `init` stays the one required step; the enhancement is presented as optional.
      assert.match(stdout, /Next step:\n {2}agentguard init\n/);
      assert.match(stdout, /Optional, after init:/);
      assert.match(stdout, /agentguard privacy status/);

      const nextSteps = readFileSync(join(home, 'next-steps.txt'), 'utf8');
      assert.match(nextSteps, /agentguard privacy status/);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
