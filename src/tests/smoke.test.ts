import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { SkillScanner } from '../scanner/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// D: guard-hook.js subprocess E2E
// ─────────────────────────────────────────────────────────────────────────────

// __dirname points to dist/tests/ after compilation, project root is 2 levels up
const projectRoot = resolve(__dirname, '..', '..');
const GUARD_HOOK_PATH = join(projectRoot, 'skills', 'agentguard', 'scripts', 'guard-hook.js');
const HERMES_HOOK_PATH = join(projectRoot, 'skills', 'agentguard', 'scripts', 'hermes-hook.js');

function runGuardHook(input: Record<string, unknown>): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return runNodeHook(GUARD_HOOK_PATH, input);
}

function runHermesHook(input: Record<string, unknown>): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return runNodeHook(HERMES_HOOK_PATH, input);
}

function runNodeHook(scriptPath: string, input: Record<string, unknown>): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolvePromise) => {
    // Isolate HOME to a temp dir so loadConfig/writeAuditLog don't touch real ~/.agentguard/
    const tempHome = mkdtempSync(join(tmpdir(), 'agentguard-smoke-'));
    const child = spawn('node', [scriptPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, HOME: tempHome },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

    child.stdin.write(JSON.stringify(input));
    child.stdin.end();

    child.on('close', (code) => {
      resolvePromise({ exitCode: code ?? 1, stdout, stderr });
    });

    // Timeout safety
    setTimeout(() => {
      child.kill();
      resolvePromise({ exitCode: -1, stdout, stderr: 'TIMEOUT' });
    }, 8000);
  });
}

describe('Smoke: guard-hook.js E2E', () => {
  it('should allow echo hello (exit 0)', async () => {
    const { exitCode } = await runGuardHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'echo hello' },
    });
    assert.equal(exitCode, 0);
  });

  it('should deny rm -rf / (exit 2)', async () => {
    const { exitCode, stderr } = await runGuardHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
    assert.equal(exitCode, 2);
    assert.ok(stderr.includes('AgentGuard'), 'stderr should mention AgentGuard');
  });

  it('should deny write to .env (exit 2)', async () => {
    const { exitCode } = await runGuardHook({
      hook_event_name: 'PreToolUse',
      tool_name: 'Write',
      tool_input: { file_path: '/project/.env' },
    });
    assert.equal(exitCode, 2);
  });

  it('should allow PostToolUse event (exit 0)', async () => {
    const { exitCode } = await runGuardHook({
      hook_event_name: 'PostToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
    });
    assert.equal(exitCode, 0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// E: hermes-hook.js subprocess E2E
// ─────────────────────────────────────────────────────────────────────────────

describe('Smoke: hermes-hook.js E2E', () => {
  it('should allow echo hello with empty JSON output', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'terminal',
      tool_input: { command: 'echo hello' },
    });
    assert.equal(exitCode, 0);
    assert.deepEqual(JSON.parse(stdout), {});
  });

  it('should block rm -rf / using Hermes stdout protocol', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'terminal',
      tool_input: { command: 'rm -rf /' },
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('AgentGuard'), 'message should mention AgentGuard');
  });

  it('should block write to .env using Hermes stdout protocol', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'write_file',
      tool_input: { path: '/project/.env' },
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string };
    assert.equal(payload.action, 'block');
  });

  it('should allow post_tool_call event for audit-only handling', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'post_tool_call',
      tool_name: 'terminal',
      tool_input: { command: 'rm -rf /' },
    });
    assert.equal(exitCode, 0);
    assert.deepEqual(JSON.parse(stdout), {});
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F: Scanner integration
// ─────────────────────────────────────────────────────────────────────────────

describe('Smoke: SkillScanner on vulnerable-skill', () => {
  it('should detect multiple violations in examples/vulnerable-skill', async () => {
    const scanner = new SkillScanner({ useExternalScanner: false });
    const vulnPath = join(projectRoot, 'examples', 'vulnerable-skill');
    const result = await scanner.quickScan(vulnPath);

    assert.equal(result.risk_level, 'critical', 'Vulnerable skill should be critical');
    assert.ok(result.risk_tags.length >= 5, `Expected at least 5 risk tags, got ${result.risk_tags.length}`);

    const expectedTags = ['SHELL_EXEC', 'PRIVATE_KEY_PATTERN', 'WEBHOOK_EXFIL'];
    for (const tag of expectedTags) {
      assert.ok(
        result.risk_tags.includes(tag as never),
        `Should detect ${tag}, got: ${result.risk_tags.join(', ')}`
      );
    }
  });
});
