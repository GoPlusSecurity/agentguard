import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { SkillScanner } from '../scanner/index.js';

// ─────────────────────────────────────────────────────────────────────────────
// D: guard-hook.js subprocess E2E
// ─────────────────────────────────────────────────────────────────────────────

// __dirname points to dist/tests/ after compilation, project root is 2 levels up
const projectRoot = resolve(__dirname, '..', '..');
const GUARD_HOOK_PATH = join(projectRoot, 'skills', 'agentguard', 'scripts', 'guard-hook.js');
const HERMES_HOOK_PATH = join(projectRoot, 'skills', 'agentguard', 'scripts', 'hermes-hook.js');
const TRUST_CLI_PATH = join(projectRoot, 'skills', 'agentguard', 'scripts', 'trust-cli.js');
const ACTION_CLI_PATH = join(projectRoot, 'skills', 'agentguard', 'scripts', 'action-cli.js');

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

function runHermesHookWithEnv(
  input: Record<string, unknown>,
  env: Record<string, string>
): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return runNodeHook(HERMES_HOOK_PATH, input, env);
}

function runHermesHookRaw(input: string): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return runNodeHookRaw(HERMES_HOOK_PATH, input);
}

function runNodeHook(
  scriptPath: string,
  input: Record<string, unknown>,
  env: Record<string, string> = {}
): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return runNodeHookRaw(scriptPath, JSON.stringify(input), env);
}

function runNodeHookRaw(
  scriptPath: string,
  input: string,
  env: Record<string, string> = {}
): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolvePromise) => {
    // Isolate HOME to a temp dir so loadConfig/writeAuditLog don't touch real ~/.agentguard/
    const tempHome = mkdtempSync(join(tmpdir(), 'agentguard-smoke-'));
    const child = spawn('node', [scriptPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, HOME: tempHome, ...env },
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result: { exitCode: number; stdout: string; stderr: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolvePromise(result);
    };

    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));

    child.stdin.write(input);
    child.stdin.end();

    child.on('close', (code) => {
      finish({ exitCode: code ?? 1, stdout, stderr });
    });

    // Timeout safety
    const timeout = setTimeout(() => {
      child.kill();
      finish({ exitCode: -1, stdout, stderr: 'TIMEOUT' });
    }, 8000);
  });
}

function makeInstalledSkillCli(scriptPath: string): { skillDir: string; script: string } {
  const skillDir = mkdtempSync(join(tmpdir(), 'agentguard-installed-skill-'));
  const scriptsDir = join(skillDir, 'scripts');
  mkdirSync(scriptsDir, { recursive: true });
  writeFileSync(join(skillDir, 'package.json'), JSON.stringify({ private: true, type: 'module' }, null, 2));
  cpSync(scriptPath, join(scriptsDir, scriptPath.split('/').pop() || 'cli.js'));
  const scopedDir = join(skillDir, 'node_modules', '@goplus');
  mkdirSync(scopedDir, { recursive: true });
  symlinkSync(projectRoot, join(scopedDir, 'agentguard'), 'dir');
  return { skillDir, script: join(scriptsDir, scriptPath.split('/').pop() || 'cli.js') };
}

function runInstalledSkillCli(
  scriptPath: string,
  args: string[]
): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  return new Promise((resolvePromise) => {
    const { skillDir, script } = makeInstalledSkillCli(scriptPath);
    const home = mkdtempSync(join(tmpdir(), 'agentguard-cli-home-'));
    const child = spawn('node', [script, ...args], {
      cwd: skillDir,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, HOME: home, AGENTGUARD_HOME: join(home, '.agentguard') },
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (result: { exitCode: number; stdout: string; stderr: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolvePromise(result);
    };

    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('close', (code) => finish({ exitCode: code ?? 1, stdout, stderr }));

    const timeout = setTimeout(() => {
      child.kill();
      finish({ exitCode: -1, stdout, stderr: 'TIMEOUT' });
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

  it('should block confirm-only secret reads because Hermes has no ask protocol', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'terminal',
      tool_input: { command: 'cat /home/hermes/.hermes/.env' },
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; decision?: string; block?: boolean; message?: string };
    assert.equal(payload.action, 'block');
    assert.equal(payload.decision, 'block');
    assert.equal(payload.block, true);
    assert.ok(payload.message?.includes('requires confirmation'));
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

  it('should fail closed when the Hermes engine cannot load for pre_tool_call', async () => {
    const { exitCode, stdout } = await runHermesHookWithEnv(
      {
        hook_event_name: 'pre_tool_call',
        tool_name: 'terminal',
        tool_input: { command: 'echo hello' },
      },
      { AGENTGUARD_TEST_FORCE_ENGINE_LOAD_FAILURE: '1' }
    );
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('unable to load Hermes hook engine'));
  });

  it('should block unknown pre_tool_call tools', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'browser_click',
      tool_input: { selector: '#danger' },
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('not recognized by AgentGuard'));
  });

  it('should block terminal payloads without a command', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'terminal',
      tool_input: {},
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('missing command'));
  });

  it('should block file payloads without a path', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'write_file',
      tool_input: { content: 'secret' },
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('missing path'));
  });

  it('should block URL payloads without a URL', async () => {
    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'browser_navigate',
      tool_input: { selector: '#login' },
    });
    assert.equal(exitCode, 0);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('missing URL'));
  });

  it('should evaluate Hermes open-style URL tools', async () => {
    const getResult = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'open',
      tool_input: { url: 'https://www.tiktok.com' },
    });
    assert.equal(getResult.exitCode, 0);
    assert.deepEqual(JSON.parse(getResult.stdout), {});

    const { exitCode, stdout } = await runHermesHook({
      hook_event_name: 'pre_tool_call',
      tool_name: 'open',
      tool_input: { url: 'https://www.tiktok.com', method: 'POST' },
    });
    assert.equal(exitCode, 0);
    assert.deepEqual(JSON.parse(stdout), {});
  });

  it('should block invalid stdin without waiting for the stdin timeout', async () => {
    const start = performance.now();
    const { exitCode, stdout } = await runHermesHookRaw('{not-json');
    const elapsedMs = performance.now() - start;
    assert.equal(exitCode, 0);
    assert.ok(elapsedMs < 2000, `hook should exit promptly, took ${elapsedMs}ms`);
    const payload = JSON.parse(stdout) as { action?: string; message?: string };
    assert.equal(payload.action, 'block');
    assert.ok(payload.message?.includes('invalid or missing Hermes hook payload'));
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// F: skill CLI subprocess E2E
// ─────────────────────────────────────────────────────────────────────────────

describe('Smoke: skill CLI scripts E2E', () => {
  it('runs trust-cli.js from an installed ESM skill directory', async () => {
    const { exitCode, stdout, stderr } = await runInstalledSkillCli(TRUST_CLI_PATH, ['list']);

    assert.equal(exitCode, 0, stderr);
    assert.doesNotThrow(() => JSON.parse(stdout));
  });

  it('runs action-cli.js from an installed ESM skill directory', async () => {
    const { exitCode, stdout, stderr } = await runInstalledSkillCli(ACTION_CLI_PATH, [
      'decide',
      '--type',
      'exec_command',
      '--command',
      'echo hello',
    ]);

    assert.equal(exitCode, 0, stderr);
    const payload = JSON.parse(stdout) as { decision?: string; risk_level?: string };
    assert.ok(payload.decision || payload.risk_level, stdout);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// G: Scanner integration
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
