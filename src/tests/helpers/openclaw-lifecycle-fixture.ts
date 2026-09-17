import assert from 'node:assert/strict';

type HookHandler = (event: unknown, context?: unknown) => Promise<unknown> | unknown;

type InputGateResult =
  | { outcome: 'pass' }
  | { outcome: 'block'; reason: string; message?: string; category?: string; metadata?: Record<string, unknown> };

type ToolApproval = {
  title: string;
  description: string;
  severity?: 'info' | 'warning' | 'critical';
  timeoutMs?: number;
  allowedDecisions?: Array<'allow-once' | 'allow-always' | 'deny'>;
};

type BeforeToolResult =
  | { block: true; blockReason: string; requireApproval?: never }
  | { block?: never; blockReason?: never; requireApproval: ToolApproval }
  | undefined;

/**
 * Read-only fixture for the public OpenClaw typed-hook contract used here.
 * It validates plugin return shapes instead of merely collecting callbacks.
 */
export class OpenClawLifecycleFixture {
  readonly handlers = new Map<string, HookHandler>();
  readonly api = {
    id: 'agentguard-contract-fixture',
    name: 'AgentGuard Contract Fixture',
    source: '/fixture/agentguard/index.ts',
    on: (event: string, ...args: unknown[]) => {
      const handler = args.at(-1);
      assert.equal(typeof handler, 'function', `OpenClaw hook ${event} requires a handler`);
      this.handlers.set(event, handler as HookHandler);
    },
  };

  async beforeAgentRun(event: unknown, context?: unknown): Promise<InputGateResult> {
    const result = await this.required('before_agent_run')(event, context);
    assertInputGateResult(result);
    return result;
  }

  async beforeToolCall(event: unknown, context?: unknown): Promise<BeforeToolResult> {
    const result = await this.required('before_tool_call')(event, context);
    assertBeforeToolResult(result);
    return result;
  }

  async observe(hook: 'llm_input' | 'llm_output' | 'model_call_started' | 'model_call_ended', event: unknown, context?: unknown): Promise<void> {
    const result = await this.required(hook)(event, context);
    assert.equal(result, undefined, `${hook} is an observer and must not return a gate result`);
  }

  lifecycleCoverage(): {
    mainRun: 'partial';
    secondToolLoop: 'observe_only';
    compaction: 'unsupported';
    retryAndFallback: 'unsupported';
    auxiliaryModelCalls: 'unsupported';
  } {
    assert.ok(this.handlers.has('before_agent_run'));
    assert.ok(this.handlers.has('model_call_started'));
    assert.equal(this.handlers.has('before_compaction'), false);
    assert.equal(this.handlers.has('after_compaction'), false);
    assert.equal(this.handlers.has('before_model_retry'), false);
    assert.equal(this.handlers.has('before_model_fallback'), false);
    assert.equal(this.handlers.has('auxiliary_model_call'), false);
    return {
      mainRun: 'partial',
      secondToolLoop: 'observe_only',
      compaction: 'unsupported',
      retryAndFallback: 'unsupported',
      auxiliaryModelCalls: 'unsupported',
    };
  }

  private required(name: string): HookHandler {
    const handler = this.handlers.get(name);
    assert.ok(handler, `OpenClaw hook ${name} was not registered`);
    return handler;
  }
}

function assertInputGateResult(value: unknown): asserts value is InputGateResult {
  assert.ok(isRecord(value), 'before_agent_run must return an input-gate object');
  if (value.outcome === 'pass') {
    assert.deepEqual(Object.keys(value), ['outcome']);
    return;
  }
  assert.equal(value.outcome, 'block');
  assert.equal(typeof value.reason, 'string');
  assert.ok(String(value.reason).length > 0);
  assert.equal('requireApproval' in value, false, 'before_agent_run cannot request approval');
  const allowed = new Set(['outcome', 'reason', 'message', 'category', 'metadata']);
  assert.ok(Object.keys(value).every(key => allowed.has(key)), 'before_agent_run returned a non-contract field');
}

function assertBeforeToolResult(value: unknown): asserts value is BeforeToolResult {
  if (value === undefined) return;
  assert.ok(isRecord(value), 'before_tool_call must return an object or undefined');
  if (value.block === true) {
    assert.equal(typeof value.blockReason, 'string');
    assert.ok(String(value.blockReason).length > 0);
    assert.equal(value.requireApproval, undefined);
    return;
  }
  assert.ok(isRecord(value.requireApproval), 'before_tool_call must block or request approval');
  const approval = value.requireApproval;
  assert.equal(typeof approval.title, 'string');
  assert.equal(typeof approval.description, 'string');
  assert.ok(String(approval.title).length > 0 && String(approval.title).length <= 80);
  assert.ok(String(approval.description).length > 0 && String(approval.description).length <= 512);
  if (approval.allowedDecisions !== undefined) {
    assert.ok(Array.isArray(approval.allowedDecisions));
    assert.ok(approval.allowedDecisions.every(decision => (
      decision === 'allow-once' || decision === 'allow-always' || decision === 'deny'
    )));
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
