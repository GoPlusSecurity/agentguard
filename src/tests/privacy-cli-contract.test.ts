import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = join(process.cwd(), 'dist', 'cli.js');

let fixture = '';
let home = '';

/** Write an isolated AgentGuard home so the suite never reads the real config. */
function seedHome(privacyMode: 'off' | 'jev'): string {
  const dir = mkdtempSync(join(tmpdir(), 'ag-home-'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'config.json'),
    JSON.stringify({
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy-cache.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'events-spool.jsonl'),
      ...(privacyMode === 'jev' ? { privacy: { mode: 'jev' } } : {}),
    }),
  );
  return dir;
}

function runScan(agentguardHome: string, extra: string[] = []) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, 'scan', fixture, ...extra], {
      env: { ...process.env, AGENTGUARD_HOME: agentguardHome, TYPESAFE_API_KEY: '' },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { stdout, stderr: '' };
  } catch (error) {
    const err = error as { stdout?: string; stderr?: string };
    return { stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

describe('Privacy enhancement CLI contract', () => {
  before(() => {
    fixture = mkdtempSync(join(tmpdir(), 'ag-scan-'));
    writeFileSync(join(fixture, 'readme.md'), '# notes\n\nnothing sensitive here at all.\n');
    home = seedHome('jev');
  });

  after(() => {
    rmSync(fixture, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  });

  /**
   * A misconfigured enhancement must be visible, but `scan` output is consumed
   * by CI and by `--json`. Routing the warning to stderr would break callers
   * that treat any stderr as failure, so it travels with the result instead.
   */
  it('keeps stderr clean when enhancement is enabled without a key', () => {
    const { stderr } = runScan(home);
    assert.equal(stderr, '', `scan must not write to stderr, got: ${stderr}`);
  });

  it('still reports the misconfiguration on stdout', () => {
    const { stdout } = runScan(home);
    assert.match(stdout, /Privacy:.*no TypeSafe API key/i, 'silent degradation is not acceptable');
  });

  it('emits parseable JSON when enhancement is misconfigured', () => {
    const { stdout } = runScan(home, ['--json']);
    const parsed = JSON.parse(stdout) as { privacy?: { warning?: string } };
    assert.ok(parsed.privacy?.warning, 'the warning must survive into machine-readable output');
  });

  /**
   * `checkup` has always exited 0 and several long-standing checks emit
   * informational coverage notes on an ordinary run. Only the opt-in semantic
   * pass may move the exit status, or every existing caller changes behaviour.
   */
  it('leaves checkup exit status untouched when enhancement is off', () => {
    const offHome = seedHome('off');
    try {
      let status = 0;
      try {
        execFileSync(process.execPath, [CLI, 'checkup', '--json'], {
          env: { ...process.env, AGENTGUARD_HOME: offHome, TYPESAFE_API_KEY: '' },
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 600_000,
        });
      } catch (error) {
        status = (error as { status?: number }).status ?? 0;
      }
      assert.equal(status, 0, 'a disabled enhancement must not change checkup exit status');
    } finally {
      rmSync(offHome, { recursive: true, force: true });
    }
  });

  it('says nothing about privacy when enhancement is off', () => {
    const offHome = seedHome('off');
    try {
      const { stdout, stderr } = runScan(offHome);
      assert.ok(!/Privacy:/.test(stdout), 'a check that never ran must not report a result');
      assert.equal(stderr, '');
    } finally {
      rmSync(offHome, { recursive: true, force: true });
    }
  });
});
