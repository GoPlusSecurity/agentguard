import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const projectRoot = resolve(__dirname, '..', '..');
const CLI_PATH = join(projectRoot, 'dist', 'cli.js');

function runCli(
  args: string[],
  home: string,
  env: Record<string, string> = {}
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('node', [CLI_PATH, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env, AGENTGUARD_HOME: home },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('close', (code) => {
      resolvePromise({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

describe('CLI checkup command modes', () => {
  it('plain checkup runs the local health report, not threat-feed advisory mode', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ag-cli-checkup-'));

    const result = await runCli(['checkup', '--json'], home);

    assert.equal(result.exitCode, 0);
    assert.equal(result.stderr, '');
    const parsed = JSON.parse(result.stdout) as {
      composite_score: number;
      dimensions: Record<string, unknown>;
      skills_scanned: number;
      advisoryCache?: unknown;
      results?: unknown;
    };
    assert.equal(typeof parsed.composite_score, 'number');
    assert.ok(parsed.dimensions.code_safety);
    assert.equal(parsed.skills_scanned, 0);
    assert.equal(parsed.advisoryCache, undefined);
    assert.equal(parsed.results, undefined);
  });

  it('plain checkup falls back to text output when the HTML report generator is not packaged', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ag-cli-checkup-'));
    const missingScript = join(home, 'missing-checkup-report.js');

    const result = await runCli(['checkup'], home, {
      AGENTGUARD_CHECKUP_REPORT_SCRIPT: missingScript,
    });

    assert.equal(result.exitCode, 0);
    assert.match(result.stdout, /AgentGuard Health Checkup/);
    assert.match(result.stdout, /Full visual report: unavailable/);
    assert.match(result.stderr, /Could not generate visual checkup report/);
  });

  it('requires Cloud connection for --against-advisory mode', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ag-cli-checkup-'));

    const result = await runCli(['checkup', '--against-advisory', 'AGS-2026-local', '--json'], home);

    assert.equal(result.exitCode, 1);
    assert.equal(result.stderr, '');
    const parsed = JSON.parse(result.stdout) as { success: boolean; error: string };
    assert.equal(parsed.success, false);
    assert.match(parsed.error, /agentguard connect --key <key>/);
  });
});
