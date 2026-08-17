import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const runtimeRoot = join(repoRoot, '.dsh-runtime/node_modules/@deepseek-ai');
const { Context } = await import(pathToFileURL(join(runtimeRoot, 'cordis/lib/index.js')).href);
const { default: SystemPrompt } = await import(pathToFileURL(join(runtimeRoot, 'dsh-system-prompt/lib/index.js')).href);
const { default: ToolRuntime } = await import(pathToFileURL(join(runtimeRoot, 'dsh-tools/lib/index.js')).href);
const {
  mergeDshPostDecisions,
  translateDshPostDecision,
} = await import(pathToFileURL(join(repoRoot, 'dist/dsh/enforcement-adapter.js')).href);

const originalSecret = 'ORIGINAL_RESPONSE_MUST_BE_SUPPRESSED';

function policyDecision(decision) {
  return {
    actionId: `post-${decision}`,
    decision,
    riskScore: decision === 'block' ? 95 : decision === 'require_approval' ? 55 : 20,
    riskLevel: decision === 'block' ? 'critical' : decision === 'require_approval' ? 'high' : 'medium',
    reasons: decision === 'allow' ? [] : [{
      code: decision === 'block' ? 'RESPONSE_MALICIOUS_SCRIPT' : 'NETWORK_OUTBOUND',
      severity: decision === 'block' ? 'critical' : 'high',
      title: 'response policy',
      description: originalSecret,
      evidence: originalSecret,
    }],
    policyVersion: 'runtime-post-contract',
  };
}

async function runCase({ name, decision, downstream, throwListener = false }) {
  const ctx = new Context();
  let bodyCalls = 0;
  try {
    await ctx.plugin(SystemPrompt);
    await ctx.plugin(ToolRuntime, { mode: 'native' });
    ctx.tools.register({
      name: 'post_probe',
      description: 'DSH post-execute policy probe',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: {
        schema: {
          type: 'object',
          properties: { payload: { type: 'string' } },
          required: ['payload'],
          additionalProperties: false,
        },
        render: (_args, value) => [{ type: 'text', text: value.payload }],
      },
      async execute() {
        bodyCalls++;
        return { payload: originalSecret };
      },
    });
    ctx.on('tools/post-execute', async (exec, _result, next) => {
      if (exec.name !== 'post_probe') return next();
      if (throwListener) throw new Error('POST_POLICY_LISTENER_FAILURE');
      const agentguard = translateDshPostDecision(policyDecision(decision));
      return mergeDshPostDecisions(agentguard, await next());
    });
    if (downstream) {
      ctx.on('tools/post-execute', async (exec, _result, next) => {
        if (exec.name !== 'post_probe') return next();
        return downstream;
      });
    }

    const result = await ctx.tools.execute({
      callId: `call-${name}`,
      name: 'post_probe',
      arguments: {},
      signal: new AbortController().signal,
    });
    assert.equal(bodyCalls, 1, `${name}: post policy runs after tool dispatch`);
    return result;
  } finally {
    await ctx.fiber.dispose();
  }
}

for (const decision of ['allow', 'warn']) {
  const result = await runCase({ name: decision, decision });
  assert.equal(result.isError, false, decision);
  assert.equal(result.value.payload, originalSecret, decision);
}

for (const decision of ['require_approval', 'block']) {
  const result = await runCase({ name: decision, decision });
  assert.equal(result.isError, true, decision);
  assert.equal(Object.hasOwn(result, 'value'), false, `${decision}: blocked result must not retain value`);
  assert.doesNotMatch(JSON.stringify(result), new RegExp(originalSecret), `${decision}: raw result/evidence must be suppressed`);
  assert.match(result.error.message, /AgentGuard/);
}

const downstreamBlock = {
  kind: 'block',
  feedback: [{ type: 'text', text: 'DOWNSTREAM_POLICY_BLOCK' }],
};
const preservedDownstream = await runCase({
  name: 'downstream-block', decision: 'allow', downstream: downstreamBlock,
});
assert.equal(preservedDownstream.isError, true);
assert.match(preservedDownstream.error.message, /DOWNSTREAM_POLICY_BLOCK/);
assert.doesNotMatch(JSON.stringify(preservedDownstream), new RegExp(originalSecret));

const agentguardWins = await runCase({
  name: 'agentguard-block', decision: 'block', downstream: { kind: 'accept' },
});
assert.equal(agentguardWins.isError, true);
assert.match(agentguardWins.error.message, /AgentGuard blocked/);

const listenerFailure = await runCase({
  name: 'listener-failure', decision: 'allow', throwListener: true,
});
assert.equal(listenerFailure.isError, true);
assert.match(listenerFailure.error.message, /POST_POLICY_LISTENER_FAILURE/);
assert.doesNotMatch(JSON.stringify(listenerFailure), new RegExp(originalSecret));

console.log(JSON.stringify({
  nativePostMatrix: true,
  acceptPreservesResult: true,
  approvalClassHeld: true,
  blockedValueSuppressed: true,
  downstreamBlockPreserved: true,
  listenerFailureContained: true,
  approvedResultResumeSupported: false,
}));
