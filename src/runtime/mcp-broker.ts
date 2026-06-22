import { spawn } from 'node:child_process';
import type { AgentGuardConfig } from '../config.js';
import { protectAction, type ProtectResult } from './protect.js';
import type { RuntimeAgentHost } from './types.js';

/**
 * Inline MCP enforcement broker.
 *
 * The AgentGuard MCP server (`mcp-server.ts`) is advisory: the agent has to
 * choose to call `action_scanner_decide`. This broker is the opposite — it sits
 * transparently in front of a downstream MCP server, forwards JSON-RPC traffic
 * untouched, but intercepts `tools/call` requests and runs them through the same
 * runtime policy used by the hook path (`protectAction`). A blocked call is
 * never forwarded; instead a JSON-RPC error response is synthesized back to the
 * agent so the tool simply appears to fail.
 *
 * A stdio proxy is non-interactive, so there is no channel to prompt the user
 * mid-stream. The broker therefore fails closed: both `block` and
 * `require_approval` decisions stop the call. Low-risk actions (which
 * `protectAction` reports as `null`) are forwarded unchanged.
 *
 * Scope: stdio transport only. That is the sole MCP transport AgentGuard
 * targets (see `mcp-server.ts` and the `type: 'stdio'` installer registration),
 * so an SSE/HTTP proxy is intentionally out of scope.
 */

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

/** Evaluate a tool call. Returns a ProtectResult, or null when there is no opinion (low risk). */
export type BrokerEvaluator = (rawInput: Record<string, unknown>) => Promise<ProtectResult | null>;

export interface BrokerOptions {
  evaluate: BrokerEvaluator;
  sourceSkill?: string;
}

export interface ClientLineOutcome {
  /** Forward the original line unchanged to the downstream server. */
  forward: boolean;
  /** A JSON-RPC error line to write back to the client instead of forwarding. */
  injectToClient?: string;
  /** The blocking decision, for audit/logging. */
  blocked?: ProtectResult;
}

/** JSON-RPC implementation-defined server error code for an AgentGuard veto. */
const JSONRPC_BLOCKED_CODE = -32001;

export function parseJsonRpc(line: string): JsonRpcMessage | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as JsonRpcMessage;
  } catch {
    return null;
  }
}

export function isToolCall(message: JsonRpcMessage | null): message is JsonRpcMessage {
  return Boolean(
    message &&
    message.method === 'tools/call' &&
    message.params &&
    typeof message.params === 'object'
  );
}

export function toolCallRawInput(message: JsonRpcMessage, options: BrokerOptions): Record<string, unknown> {
  const params = (message.params || {}) as Record<string, unknown>;
  const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
  return {
    tool_name: typeof params.name === 'string' ? params.name : 'mcp_tool',
    tool_input: args,
    ...(options.sourceSkill ? { sourceSkill: options.sourceSkill } : {}),
  };
}

export function blockedResponse(message: JsonRpcMessage, result: ProtectResult): string {
  const reasons = result.decision.reasons
    .map((reason) => reason.title)
    .filter(Boolean)
    .slice(0, 3)
    .join(', ');
  return JSON.stringify({
    jsonrpc: '2.0',
    id: message.id ?? null,
    error: {
      code: JSONRPC_BLOCKED_CODE,
      message:
        `Blocked by AgentGuard: ${result.decision.decision} ` +
        `(risk ${result.decision.riskScore}/100${reasons ? `; ${reasons}` : ''})`,
      data: {
        decision: result.decision.decision,
        actionId: result.decision.actionId,
        riskScore: result.decision.riskScore,
        riskLevel: result.decision.riskLevel,
        reasons: result.decision.reasons,
      },
    },
  });
}

function isBlockingDecision(result: ProtectResult): boolean {
  return result.decision.decision === 'block' || result.decision.decision === 'require_approval';
}

/**
 * Decide what to do with a single client→server line. Non-tool-call traffic and
 * unparseable lines are forwarded untouched so the broker never breaks the
 * protocol; only `tools/call` requests are evaluated.
 */
export async function evaluateClientLine(line: string, options: BrokerOptions): Promise<ClientLineOutcome> {
  const message = parseJsonRpc(line);
  if (!isToolCall(message)) return { forward: true };

  const result = await options.evaluate(toolCallRawInput(message, options));
  if (result && isBlockingDecision(result)) {
    return { forward: false, injectToClient: blockedResponse(message, result), blocked: result };
  }
  return { forward: true };
}

/** Newline-delimited framing that tolerates chunk boundaries splitting a JSON message. */
export function createLineBuffer(onLine: (line: string) => void): {
  push: (chunk: string) => void;
  flush: () => void;
} {
  let buffer = '';
  return {
    push(chunk: string): void {
      buffer += chunk;
      let index = buffer.indexOf('\n');
      while (index >= 0) {
        onLine(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
        index = buffer.indexOf('\n');
      }
    },
    flush(): void {
      if (buffer.length > 0) {
        onLine(buffer);
        buffer = '';
      }
    },
  };
}

export function defaultBrokerEvaluator(
  config: AgentGuardConfig,
  agentHost: RuntimeAgentHost = 'other'
): BrokerEvaluator {
  return (rawInput) => protectAction({ config, rawInput, agentHost, phase: 'pre' });
}

export interface RunMcpBrokerStdioOptions extends BrokerOptions {
  command: string;
  args?: string[];
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
  stderr?: NodeJS.WritableStream;
  onBlocked?: (result: ProtectResult) => void;
}

/**
 * Spawn a downstream MCP server and proxy stdio between it and the client,
 * vetoing tool calls inline. Resolves with the child's exit code.
 */
export function runMcpBrokerStdio(options: RunMcpBrokerStdioOptions): Promise<number> {
  const child = spawn(options.command, options.args ?? [], { stdio: ['pipe', 'pipe', 'pipe'] });
  const clientOut = options.stdout ?? process.stdout;
  const clientErr = options.stderr ?? process.stderr;
  const clientIn = options.stdin ?? process.stdin;

  // Single writer for the client stream. Downstream stdout chunks and the
  // broker's own synthesized JSON-RPC errors share `clientOut`; funnelling both
  // through one serialized queue keeps each message atomic so an injected error
  // can never be spliced into the middle of a downstream response. The queue
  // also honors backpressure (waits for `drain`) instead of unbounded buffering.
  let writeChain: Promise<void> = Promise.resolve();
  const writeClient = (data: string | Buffer): void => {
    writeChain = writeChain.then(
      () =>
        new Promise<void>((res) => {
          if (clientOut.write(data)) res();
          else clientOut.once('drain', () => res());
        })
    );
  };

  child.stdout.on('data', (chunk: Buffer) => writeClient(chunk));
  child.stderr.on('data', (chunk: Buffer) => clientErr.write(chunk));

  // Serialize per-line handling so forwarding order is preserved across async
  // policy evaluations.
  let chain: Promise<void> = Promise.resolve();
  const buffer = createLineBuffer((line) => {
    chain = chain.then(async () => {
      if (!line.trim()) {
        child.stdin.write(`${line}\n`);
        return;
      }
      const outcome = await evaluateClientLine(line, options);
      if (outcome.forward) {
        child.stdin.write(`${line}\n`);
      } else if (outcome.injectToClient) {
        writeClient(`${outcome.injectToClient}\n`);
        if (outcome.blocked) options.onBlocked?.(outcome.blocked);
      }
    });
  });

  clientIn.on('data', (chunk: Buffer) => buffer.push(chunk.toString('utf8')));
  clientIn.on('end', () => {
    buffer.flush();
    chain.then(() => child.stdin.end()).catch(() => child.stdin.end());
  });

  // Resolve only after the child has exited AND every buffered evaluation plus
  // its client write has drained. Resolving on `exit` alone could drop a
  // synthesized block response that was still in flight when the child died.
  // The child's own exit code is propagated unchanged.
  return new Promise((resolve) => {
    const settle = (code: number) => {
      chain
        .then(() => writeChain)
        .then(() => resolve(code))
        .catch(() => resolve(code));
    };
    child.on('exit', (code) => settle(code ?? 0));
    child.on('error', () => settle(1));
  });
}
