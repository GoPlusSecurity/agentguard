import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtimeRoot = join(repoRoot, '.dsh-runtime/node_modules/@deepseek-ai');

const { Context } = await import(pathToFileURL(join(runtimeRoot, 'cordis/lib/index.js')).href);
const { default: SystemPrompt } = await import(pathToFileURL(join(runtimeRoot, 'dsh-system-prompt/lib/index.js')).href);
const { default: ToolRuntime } = await import(pathToFileURL(join(runtimeRoot, 'dsh-tools/lib/index.js')).href);
const { default: ApprovalService } = await import(pathToFileURL(join(runtimeRoot, 'dsh-user-approval/lib/index.js')).href);
const { Session } = await import(pathToFileURL(join(runtimeRoot, 'dsh-session/lib/index.js')).href);
const { translateDshPreDecision } = await import(pathToFileURL(join(repoRoot, 'dist/dsh/enforcement-adapter.js')).href);

const approvalDecision = {
  actionId: 'native-approval-contract',
  decision: 'require_approval',
  riskScore: 55,
  riskLevel: 'high',
  reasons: [{
    code: 'REMOTE_CODE_EXECUTION',
    severity: 'high',
    title: 'Remote code execution',
    description: 'Native approval contract probe',
  }],
  policyVersion: 'runtime-native-approval-test',
};

async function runCase({
  name,
  policy = 'ask',
  composeApproval = true,
  withAgent = true,
  answer,
  expectError,
  expectCalls,
  expectedOutcome,
  expectedError,
}) {
  const ctx = new Context();
  let bodyCalls = 0;
  let answerCalls = 0;
  const controller = new AbortController();
  try {
    await ctx.plugin(SystemPrompt);
    await ctx.plugin(ToolRuntime, { mode: 'native' });
    if (composeApproval) await ctx.plugin(ApprovalService, { policy });

    const session = Session.create(`approval-${name}`);
    session.append('turn/start', { turn: 1 });
    const agent = withAgent ? fakeAgent(ctx, session) : undefined;

    ctx.tools.register({
      name: 'approval_probe',
      description: 'DSH native approval state probe',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: {
        schema: {
          type: 'object',
          properties: { ok: { type: 'boolean' } },
          required: ['ok'],
          additionalProperties: false,
        },
        render: () => [{ type: 'text', text: 'approval probe complete' }],
      },
      async execute() {
        bodyCalls++;
        return { ok: true };
      },
    });
    ctx.on('tools/pre-execute', async (exec, next) =>
      exec.name === 'approval_probe' ? translateDshPreDecision(approvalDecision) : next());
    if (answer !== undefined) {
      ctx.on('approval/request', async () => {
        answerCalls++;
        if (answer === 'abort') {
          controller.abort();
          return new Promise(() => {});
        }
        return answer;
      });
    }

    const result = await ctx.tools.execute({
      callId: `call-${name}`,
      name: 'approval_probe',
      arguments: {},
      ...(agent ? { agent } : {}),
      signal: controller.signal,
    });
    assert.equal(result.isError, expectError, name);
    assert.equal(bodyCalls, expectCalls, name);
    if (expectedError) assert.match(result.error?.message ?? '', expectedError, name);

    const asked = session.events.filter(event => event.type === 'approval/asked');
    const decided = session.events.filter(event => event.type === 'approval/decided');
    if (expectedOutcome === undefined) {
      assert.equal(asked.length, 0, `${name}: no native audit pair expected`);
      assert.equal(decided.length, 0, `${name}: no native audit pair expected`);
    } else {
      assert.equal(asked.length, 1, `${name}: one approval/asked expected`);
      assert.equal(decided.length, 1, `${name}: one approval/decided expected`);
      assert.equal(decided[0].data.outcome, expectedOutcome, name);
      assert.equal(asked[0].data.id, decided[0].data.id, `${name}: audit IDs must pair`);
      assert.equal(asked[0].data.callId, `call-${name}`, name);
      assert.doesNotMatch(asked[0].data.reason ?? '', /Native approval contract probe/);
    }
    return { name, outcome: expectedOutcome ?? 'pre-service-deny', answerCalls };
  } finally {
    await ctx.fiber.dispose();
  }
}

function fakeAgent(ctx, session) {
  return {
    id: session.id,
    session,
    ctx,
    status: 'running',
    options: {},
    inbox: {},
    cancel() {},
    async whenIdle() {},
    runMaintenance(task) { return task(new AbortController().signal); },
    send() {},
    followup() {},
    steer() {},
    inject() {},
  };
}

const results = [];
results.push(await runCase({
  name: 'allowed-once', answer: 'allowed-once', expectError: false, expectCalls: 1,
  expectedOutcome: 'allowed-once',
}));
results.push(await runCase({
  name: 'rejected', answer: 'rejected', expectError: true, expectCalls: 0,
  expectedOutcome: 'rejected', expectedError: /user rejected/,
}));
results.push(await runCase({
  name: 'cancelled', answer: 'abort', expectError: true, expectCalls: 0,
  expectedOutcome: 'cancelled', expectedError: /aborted|cancelled/i,
}));
results.push(await runCase({
  name: 'unavailable', expectError: true, expectCalls: 0,
  expectedOutcome: 'unavailable', expectedError: /no approval channel is available/,
}));
const never = await runCase({
  name: 'headless-never', policy: 'never', answer: 'allowed-once', expectError: true, expectCalls: 0,
  expectedOutcome: 'rejected', expectedError: /user rejected/,
});
assert.equal(never.answerCalls, 0, 'headless never must not dispatch an interactive answerer');
results.push(never);
results.push(await runCase({
  name: 'missing-service', composeApproval: false, expectError: true, expectCalls: 0,
  expectedOutcome: undefined, expectedError: /requires approval/,
}));
results.push(await runCase({
  name: 'missing-agent', withAgent: false, expectError: true, expectCalls: 0,
  expectedOutcome: undefined, expectedError: /no agent/,
}));

console.log(JSON.stringify({
  nativeApprovalMatrix: true,
  cases: results.map(result => ({ name: result.name, outcome: result.outcome })),
  oneShotGrantOnly: true,
  auditPairsVerified: true,
  rawEvidenceExcluded: true,
}));
