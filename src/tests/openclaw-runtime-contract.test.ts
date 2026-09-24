import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { registerOpenClawPlugin } from '../adapters/openclaw-plugin.js';
import type { ProtectOptions, ProtectResult } from '../runtime/protect.js';
import { createTestContext } from './helpers/test-utils.js';

type HookHandler = (event: unknown, context?: unknown) => Promise<unknown> | unknown;

type TypedHookRegistration = {
  pluginId: string;
  hookName: string;
  handler: HookHandler;
  source: string;
  priority?: number;
  registrationId?: string;
  timeoutMs?: number;
  matcher?: readonly string[];
};

type InstalledOpenClaw = {
  root: string;
  version: string;
  hookRuntimeUrl: string;
  pluginRuntimeUrl: string;
};

type HookRunner = {
  hasHooks(name: string): boolean;
  getHookCount(name: string): number;
  runBeforeAgentRun(event: unknown, context: unknown): Promise<unknown>;
  runBeforeToolCall(event: unknown, context: unknown): Promise<unknown>;
  runAfterToolCall(event: unknown, context: unknown): Promise<void>;
  runLlmInput(event: unknown, context: unknown): Promise<void>;
  runLlmOutput(event: unknown, context: unknown): Promise<void>;
  runModelCallStarted(event: unknown, context: unknown): Promise<void>;
  runModelCallEnded(event: unknown, context: unknown): Promise<void>;
  runBeforeCompaction(event: unknown, context: unknown): Promise<void>;
  runAfterCompaction(event: unknown, context: unknown): Promise<void>;
};

const installed = discoverOpenClaw();
let resetRuntime: (() => void) | undefined;

afterEach(() => {
  resetRuntime?.();
  resetRuntime = undefined;
});

describe('Installed OpenClaw public hook runtime contract', {
  skip: installed ? false : 'OpenClaw is not available via OPENCLAW_PACKAGE_ROOT or PATH',
}, () => {
  it(`executes AgentGuard lifecycle gates and observers through OpenClaw ${installed?.version ?? 'unavailable'}`, async () => {
    assert.ok(installed);
    const hookRuntime = await import(installed.hookRuntimeUrl) as {
      initializeGlobalHookRunner(registry: unknown): void;
      resetGlobalHookRunner(): void;
    };
    const pluginRuntime = await import(installed.pluginRuntimeUrl) as {
      getGlobalHookRunner(): HookRunner | null;
    };
    resetRuntime = hookRuntime.resetGlobalHookRunner;

    const ctx = createTestContext();
    const typedHooks: TypedHookRegistration[] = [];
    const protectCalls: ProtectOptions[] = [];
    try {
      registerOpenClawPlugin({
        id: 'agentguard',
        name: 'AgentGuard',
        source: '/agentguard/dist/openclaw.js',
        on: (hookName: string, ...args: unknown[]) => {
          const handler = args.at(-1);
          assert.equal(typeof handler, 'function');
          const options = args.length === 2 ? args[0] as Record<string, unknown> : undefined;
          typedHooks.push({
            pluginId: 'agentguard',
            hookName,
            handler: handler as HookHandler,
            source: '/agentguard/dist/openclaw.js',
            ...(options ?? {}),
          });
        },
      } as never, {
        skipAutoScan: true,
        registry: ctx.agentguard.registry as never,
        protectAction: async options => {
          protectCalls.push(options);
          const raw = options.rawInput as Record<string, unknown>;
          if (options.toolName === 'openclaw.before_agent_run' && String(raw.input).includes('BLOCK_ME')) {
            return protectResult('block', options, 'PII_EGRESS');
          }
          if (options.phase === 'pre' && options.toolName === 'read') {
            return protectResult('require_approval', options, 'SECRET_ACCESS');
          }
          return null;
        },
      });

      hookRuntime.initializeGlobalHookRunner({
        hooks: [],
        typedHooks,
        plugins: [{ id: 'agentguard', packageVersion: '1.2.1-beta.2', status: 'loaded' }],
      });
      const runner = pluginRuntime.getGlobalHookRunner();
      assert.ok(runner);

      const agentContext = {
        runId: 'run-real-runtime',
        agentId: 'main',
        sessionKey: 'agent:main:main',
        sessionId: 'session-real-runtime',
        modelProviderId: 'openai',
        modelId: 'gpt-test',
      };
      const block = await runner.runBeforeAgentRun({
        prompt: 'BLOCK_ME personal data',
        messages: [{ role: 'user', content: 'history' }],
        systemPrompt: 'Keep data private.',
      }, agentContext);
      assert.deepEqual(block, {
        decision: {
          outcome: 'block',
          reason: 'GoPlus AgentGuard blocked this initial OpenClaw run input (risk 80/100, high; policy fixture-policy). Reasons: Personal data.',
          message: 'AgentGuard blocked the initial OpenClaw run input.',
        },
        pluginId: 'agentguard',
      });

      const pass = await runner.runBeforeAgentRun({
        prompt: 'ordinary request',
        messages: [],
      }, agentContext);
      assert.deepEqual(pass, {
        decision: { outcome: 'pass' },
        pluginId: 'agentguard',
      });

      await runner.runLlmInput({
        runId: 'run-real-runtime', sessionId: 'session-real-runtime',
        provider: 'openai', model: 'gpt-test', prompt: 'ordinary request',
        historyMessages: [], imagesCount: 0,
      }, agentContext);
      await runner.runModelCallStarted({
        runId: 'run-real-runtime', callId: 'call-first', sessionId: 'session-real-runtime',
        provider: 'openai', model: 'gpt-test',
      }, agentContext);
      await runner.runModelCallEnded({
        runId: 'run-real-runtime', callId: 'call-first', sessionId: 'session-real-runtime',
        provider: 'openai', model: 'gpt-test', durationMs: 10, outcome: 'completed',
        requestPayloadBytes: 100, responseStreamBytes: 200,
      }, agentContext);

      const toolContext = {
        ...agentContext,
        toolName: 'read',
        toolCallId: 'tool-first',
      };
      const approval = await runner.runBeforeToolCall({
        toolName: 'read', params: { path: '/workspace/.env' },
        runId: 'run-real-runtime', toolCallId: 'tool-first',
      }, toolContext);
      assert.deepEqual(approval, {
        params: undefined,
        block: undefined,
        blockReason: undefined,
        requireApproval: {
          title: 'AgentGuard approval required',
          description: 'GoPlus AgentGuard: runtime policy requires approval this OpenClaw tool call (risk 80/100, high; policy fixture-policy). Reasons: Protected path.',
          severity: 'critical',
          timeoutMs: 120_000,
          allowedDecisions: ['allow-once', 'deny'],
          pluginId: 'agentguard',
        },
      });
      await runner.runAfterToolCall({
        toolName: 'read', params: { path: '/workspace/.env' }, result: 'redacted',
        runId: 'run-real-runtime', toolCallId: 'tool-first',
      }, toolContext);

      await runner.runModelCallStarted({
        runId: 'run-real-runtime', callId: 'call-second-tool-loop', sessionId: 'session-real-runtime',
        provider: 'openai', model: 'gpt-test',
      }, agentContext);
      await runner.runModelCallEnded({
        runId: 'run-real-runtime', callId: 'call-second-tool-loop', sessionId: 'session-real-runtime',
        provider: 'openai', model: 'gpt-test', durationMs: 12, outcome: 'completed',
        responseStreamBytes: 220,
      }, agentContext);
      await runner.runLlmOutput({
        runId: 'run-real-runtime', sessionId: 'session-real-runtime',
        provider: 'openai', model: 'gpt-test', assistantTexts: ['done'],
      }, agentContext);

      const observerInputs = protectCalls
        .map(call => call.rawInput as Record<string, unknown>)
        .filter(raw => raw.canBlockCurrentAction === false);
      const requestIds = observerInputs.map(raw => (
        raw.llm as Record<string, unknown> | undefined
      )?.requestId);
      assert.ok(requestIds.includes('openclaw:call-first'));
      assert.ok(requestIds.includes('openclaw:call-second-tool-loop'));
      assert.ok(observerInputs.every(raw => (
        raw.missingFacts as string[]
      ).includes('retry_and_fallback')));
      assert.ok(observerInputs.every(raw => (
        raw.missingFacts as string[]
      ).includes('auxiliary_model_calls')));

      assert.equal(runner.hasHooks('before_agent_run'), true);
      assert.equal(runner.hasHooks('before_tool_call'), true);
      assert.equal(runner.hasHooks('model_call_started'), true);
      assert.equal(runner.getHookCount('model_call_started'), 1);
      const beforeUnsupported = protectCalls.length;
      assert.equal(runner.hasHooks('before_compaction'), false);
      assert.equal(runner.hasHooks('after_compaction'), false);
      await runner.runBeforeCompaction({ messageCount: 2, messages: [] }, agentContext);
      await runner.runAfterCompaction({ messageCount: 1, compactedCount: 1 }, agentContext);
      assert.equal(protectCalls.length, beforeUnsupported);
      for (const hookName of ['before_model_retry', 'before_model_fallback', 'auxiliary_model_call']) {
        assert.equal(runner.hasHooks(hookName), false);
        assert.equal(runner.getHookCount(hookName), 0);
      }
      assert.equal('runBeforeModelRetry' in runner, false);
      assert.equal('runBeforeModelFallback' in runner, false);
      assert.equal('runAuxiliaryModelCall' in runner, false);
    } finally {
      ctx.cleanup();
    }
  });
});

function discoverOpenClaw(): InstalledOpenClaw | undefined {
  const override = process.env.OPENCLAW_PACKAGE_ROOT;
  if (override) return readInstallation(resolve(override));

  for (const pathEntry of (process.env.PATH ?? '').split(delimiter)) {
    if (!pathEntry) continue;
    const executable = join(pathEntry, process.platform === 'win32' ? 'openclaw.cmd' : 'openclaw');
    if (!existsSync(executable)) continue;
    const root = findPackageRoot(dirname(realpathSync(executable)));
    if (root) return readInstallation(root);
  }
  return undefined;
}

function findPackageRoot(start: string): string | undefined {
  let current = resolve(start);
  for (;;) {
    const packagePath = join(current, 'package.json');
    if (existsSync(packagePath)) {
      const packageJson = JSON.parse(readFileSync(packagePath, 'utf8')) as { name?: string };
      if (packageJson.name === 'openclaw') return current;
    }
    const parent = dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

function readInstallation(root: string): InstalledOpenClaw | undefined {
  const packagePath = join(root, 'package.json');
  if (!existsSync(packagePath)) return undefined;
  const packageJson = JSON.parse(readFileSync(packagePath, 'utf8')) as {
    name?: string;
    version?: string;
    exports?: Record<string, string | { default?: string }>;
  };
  if (packageJson.name !== 'openclaw' || !packageJson.version) return undefined;
  const hookRuntime = publicExportTarget(packageJson, './plugin-sdk/hook-runtime');
  const pluginRuntime = publicExportTarget(packageJson, './plugin-sdk/plugin-runtime');
  if (!hookRuntime || !pluginRuntime) return undefined;
  return {
    root,
    version: packageJson.version,
    hookRuntimeUrl: pathToFileURL(resolvePublicTarget(root, hookRuntime)).href,
    pluginRuntimeUrl: pathToFileURL(resolvePublicTarget(root, pluginRuntime)).href,
  };
}

function publicExportTarget(
  packageJson: { exports?: Record<string, string | { default?: string }> },
  key: string,
): string | undefined {
  const value = packageJson.exports?.[key];
  return typeof value === 'string' ? value : value?.default;
}

function resolvePublicTarget(root: string, target: string): string {
  const resolved = resolve(root, target);
  const rel = relative(root, resolved);
  assert.ok(
    rel && rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel),
    'OpenClaw public export escaped its package root',
  );
  assert.ok(existsSync(resolved), `OpenClaw public export does not exist: ${target}`);
  return resolved;
}

function protectResult(
  decision: 'block' | 'require_approval',
  options: ProtectOptions,
  reasonCode: string,
): ProtectResult {
  const reason = {
    code: reasonCode,
    severity: 'high' as const,
    title: reasonCode === 'PII_EGRESS' ? 'Personal data' : 'Protected path',
    description: 'Installed-runtime test finding.',
  };
  return {
    policySource: 'default',
    event: {
      actionId: `act-${decision}`,
      sessionId: options.sessionId ?? 'unknown',
      agentHost: 'openclaw',
      actionType: options.actionType ?? 'other',
      toolName: options.toolName ?? 'unknown',
      input: '[LOCAL_ONLY_LLM_CONTENT]',
      decision,
      riskScore: 80,
      riskLevel: 'high',
      reasons: [reason],
      policyVersion: 'fixture-policy',
    },
    decision: {
      actionId: `act-${decision}`,
      decision,
      riskScore: 80,
      riskLevel: 'high',
      reasons: [reason],
      policyVersion: 'fixture-policy',
    },
  };
}
