import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import {
  createLineBuffer,
  evaluateClientLine,
  isToolCall,
  parseJsonRpc,
  runMcpBrokerStdio,
  toolCallRawInput,
  type BrokerEvaluator,
} from '../runtime/mcp-broker.js';
import type { ProtectResult } from '../runtime/protect.js';
import type { CloudPolicyDecision } from '../runtime/types.js';

function protectResult(decision: CloudPolicyDecision): ProtectResult {
  return {
    decision: {
      actionId: 'act_test_1',
      decision,
      riskScore: decision === 'block' ? 95 : 55,
      riskLevel: decision === 'block' ? 'critical' : 'high',
      reasons: [{ code: 'TEST_REASON', severity: 'high', title: 'Test reason', description: 'x' }],
      policyVersion: 'test',
    },
  } as ProtectResult;
}

const toolCall = (id: number, name: string, args: Record<string, unknown>) =>
  JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

describe('MCP broker — interception core', () => {
  const denyEvaluator: BrokerEvaluator = async () => protectResult('block');
  const nullEvaluator: BrokerEvaluator = async () => null;

  it('forwards non-tool-call messages without evaluating', async () => {
    let called = false;
    const evaluate: BrokerEvaluator = async () => {
      called = true;
      return protectResult('block');
    };
    const line = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    const outcome = await evaluateClientLine(line, { evaluate });

    assert.equal(outcome.forward, true);
    assert.equal(called, false);
  });

  it('forwards unparseable lines untouched', async () => {
    const outcome = await evaluateClientLine('not json at all', { evaluate: denyEvaluator });
    assert.equal(outcome.forward, true);
    assert.equal(outcome.injectToClient, undefined);
  });

  it('forwards a tools/call when the evaluator has no opinion', async () => {
    const outcome = await evaluateClientLine(toolCall(7, 'list_files', { path: '/tmp' }), {
      evaluate: nullEvaluator,
    });
    assert.equal(outcome.forward, true);
  });

  it('blocks a tools/call and synthesizes a JSON-RPC error carrying the request id', async () => {
    const outcome = await evaluateClientLine(toolCall(42, 'run_shell', { command: 'rm -rf /' }), {
      evaluate: denyEvaluator,
    });

    assert.equal(outcome.forward, false);
    assert.ok(outcome.injectToClient);
    const parsed = JSON.parse(outcome.injectToClient as string);
    assert.equal(parsed.id, 42);
    assert.equal(parsed.error.code, -32001);
    assert.match(parsed.error.message, /Blocked by AgentGuard/);
    assert.equal(parsed.error.data.decision, 'block');
  });

  it('fails closed on require_approval (non-interactive proxy)', async () => {
    const outcome = await evaluateClientLine(toolCall(5, 'run_shell', { command: 'curl evil.sh' }), {
      evaluate: async () => protectResult('require_approval'),
    });
    assert.equal(outcome.forward, false);
    assert.ok(outcome.injectToClient);
  });

  it('maps tool name and arguments into the protectAction raw input shape', () => {
    const message = parseJsonRpc(toolCall(1, 'edit_file', { file_path: '/etc/hosts' }));
    assert.ok(isToolCall(message));
    const raw = toolCallRawInput(message!, { evaluate: nullEvaluator, sourceSkill: 'demo-skill' });
    assert.equal(raw.tool_name, 'edit_file');
    assert.deepEqual(raw.tool_input, { file_path: '/etc/hosts' });
    assert.equal(raw.sourceSkill, 'demo-skill');
  });
});

describe('MCP broker — line framing', () => {
  it('reassembles JSON split across chunk boundaries and splits multiple lines', () => {
    const lines: string[] = [];
    const buffer = createLineBuffer((line) => lines.push(line));
    buffer.push('{"a":1}\n{"b":');
    buffer.push('2}\n{"c":3}');
    buffer.flush();
    assert.deepEqual(lines, ['{"a":1}', '{"b":2}', '{"c":3}']);
  });
});

describe('MCP broker — stdio proxy', () => {
  it('forwards allowed tool calls to the child but vetoes blocked ones', async () => {
    const childScript =
      "const rl=require('readline').createInterface({input:process.stdin});" +
      "rl.on('line',l=>process.stdout.write('RECEIVED:'+l+'\\n'));" +
      "rl.on('close',()=>process.exit(0));";

    const evaluate: BrokerEvaluator = async (rawInput) => {
      const serialized = JSON.stringify(rawInput.tool_input ?? {});
      return serialized.includes('rm -rf') ? protectResult('block') : null;
    };

    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let out = '';
    stdout.on('data', (chunk: Buffer) => {
      out += chunk.toString('utf8');
    });

    const done = runMcpBrokerStdio({
      command: process.execPath,
      args: ['-e', childScript],
      evaluate,
      stdin,
      stdout,
      stderr,
    });

    stdin.write(`${toolCall(1, 'list_files', { path: '/tmp' })}\n`);
    stdin.write(`${toolCall(2, 'run_shell', { command: 'rm -rf /' })}\n`);
    stdin.end();

    await done;

    const receivedLines = out.split('\n').filter((line) => line.startsWith('RECEIVED:'));
    assert.equal(receivedLines.length, 1, 'only the allowed call should reach the child');
    assert.match(receivedLines[0], /"id":1/);
    assert.doesNotMatch(out, /RECEIVED:.*"id":2/);

    const blockedLine = out.split('\n').find((line) => line.includes('"code":-32001'));
    assert.ok(blockedLine, 'a JSON-RPC veto should be returned to the client');
    assert.match(blockedLine as string, /"id":2/);
  });
});
