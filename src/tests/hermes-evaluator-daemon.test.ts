import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createServer as createNetServer, createConnection, type Socket } from 'node:net';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ProtectOptions, ProtectResult } from '../runtime/protect.js';
import type { AgentGuardConfig } from '../config.js';
import {
  defaultHermesLoopbackPort,
  requestHermesEvaluation,
  resolveHermesIpcEndpoint,
  startHermesEvaluatorDaemon,
  type HermesEvaluatorDaemon,
  type HermesEvaluatorRequest,
} from '../hermes/evaluator-daemon.js';

const roots: string[] = [];
const daemons: HermesEvaluatorDaemon[] = [];

afterEach(async () => {
  await Promise.all(daemons.splice(0).map(daemon => daemon.close()));
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function unixEndpoint() {
  const root = mkdtempSync(join(tmpdir(), 'agentguard-hermes-ipc-'));
  roots.push(root);
  return { kind: 'unix' as const, path: join(root, 'run', 'evaluator.sock') };
}

function configFor(endpointPath: string): AgentGuardConfig {
  const root = join(endpointPath, '..', '..');
  return {
    version: 1,
    level: 'balanced',
    policyCachePath: join(root, 'policy.json'),
    auditPath: join(root, 'audit.jsonl'),
    eventSpoolPath: join(root, 'spool.jsonl'),
  };
}

function request(id = 'request-1'): HermesEvaluatorRequest {
  return {
    version: 1,
    id,
    action: {
      actionType: 'llm_request',
      toolName: 'hermes.pre_api_request',
      sessionId: 'session-1',
      phase: 'pre',
      rawInput: {
        input: 'personal_email="private.person@example.invalid"',
        lifecycleStage: 'model_request',
        canBlockCurrentAction: false,
      },
    },
  };
}

function observedResult(): ProtectResult {
  return {
    decision: {
      actionId: 'action-1',
      decision: 'block',
      policyDecision: 'block',
      riskScore: 90,
      riskLevel: 'high',
      reasons: [],
      policyVersion: 'test',
    },
    event: {
      sessionId: 'session-1',
      agentHost: 'hermes',
      actionType: 'llm_request',
      toolName: 'hermes.pre_api_request',
      input: '[LOCAL_ONLY_LLM_CONTENT]',
      actionId: 'action-1',
      decision: 'block',
      policyDecision: 'block',
      riskScore: 90,
      riskLevel: 'high',
      reasons: [],
      policyVersion: 'test',
      canBlockCurrentAction: false,
      coverageLevel: 'observe_only',
      enforcementStatus: 'would_block',
      missingFacts: ['final_destination'],
    },
    policySource: 'default',
  };
}

describe('Hermes persistent evaluator daemon', () => {
  it('frames one evaluation per connection and forces the Hermes host', async () => {
    const endpoint = unixEndpoint();
    const seen: ProtectOptions[] = [];
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect(options) {
        seen.push(options);
        return observedResult();
      },
    });
    daemons.push(daemon);

    const response = await requestHermesEvaluation(daemon.endpoint, request(), { timeoutMs: 500 });

    assert.equal(response.id, 'request-1');
    assert.equal(response.ok, true);
    assert.deepEqual(response.result, {
      decision: 'block',
      policyDecision: 'block',
      actionId: 'action-1',
      riskScore: 90,
      riskLevel: 'high',
      reasons: [],
      policyVersion: 'test',
      policySource: 'default',
      coverageLevel: 'observe_only',
      enforcementStatus: 'would_block',
      canBlockCurrentAction: false,
      missingFacts: ['final_destination'],
    });
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.agentHost, 'hermes');
    assert.equal(seen[0]?.actionType, 'llm_request');
    assert.equal(seen[0]?.toolName, 'hermes.pre_api_request');
    assert.equal(seen[0]?.sessionId, 'session-1');
    assert.equal(seen[0]?.phase, 'pre');
    assert.deepEqual(seen[0]?.rawInput, request().action.rawInput);
  });

  it('derives would_block through the real runtime for observer-only model traffic', async () => {
    const endpoint = unixEndpoint();
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
    });
    daemons.push(daemon);
    const observerRequest = request('real-runtime-observer');
    observerRequest.action.rawInput = {
      input: 'personal_email="private.person@corp.invalid"',
      lifecycleStage: 'model_request',
      canBlockCurrentAction: false,
      coverageLevel: 'observe_only',
      missingFacts: [],
      llm: {
        schemaVersion: 1,
        requestId: 'real-runtime-observer',
        sessionId: 'session-1',
        purpose: 'conversation',
        lifecycleStage: 'model_request',
        canBlockCurrentAction: false,
        destination: {
          scheme: 'https',
          host: 'untrusted-relay.invalid',
          path: '/v1/messages',
          tier: 'T4',
        },
        credentialKind: 'none',
        credentialPresent: false,
        payloadBytes: 50,
        attachmentBytes: 0,
        messageCount: 1,
        filePathCount: 0,
      },
    };

    const response = await requestHermesEvaluation(daemon.endpoint, observerRequest, {
      timeoutMs: 1_000,
    });

    assert.equal(response.ok, true);
    if (!response.ok) return;
    assert.equal(response.result?.policyDecision, 'block');
    assert.equal(response.result?.enforcementStatus, 'would_block');
    assert.equal(response.result?.canBlockCurrentAction, false);
  });

  it('restricts the Unix runtime directory and socket to the current user', async () => {
    const endpoint = unixEndpoint();
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(daemon);

    assert.equal(statSync(join(endpoint.path, '..')).mode & 0o777, 0o700);
    assert.equal(statSync(endpoint.path).mode & 0o777, 0o600);
    assert.equal(statSync(`${endpoint.path}.lock`).mode & 0o777, 0o600);
    assert.equal(statSync(`${endpoint.path}.lease`).mode & 0o777, 0o600);
  });

  it('refuses to replace the socket of an already running daemon', async () => {
    const endpoint = unixEndpoint();
    const first = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(first);

    let second: HermesEvaluatorDaemon | undefined;
    try {
      second = await startHermesEvaluatorDaemon({
        endpoint,
        loadConfig: () => configFor(endpoint.path),
        async protect() { return null; },
      });
    } catch (error) {
      assert.match(String(error), /already running/i);
      return;
    }
    daemons.push(second);
    assert.fail('a second daemon replaced the live Unix socket');
  });

  it('releases the kernel lease when the daemon closes', async () => {
    const endpoint = unixEndpoint();
    const first = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(first);
    await first.close();

    const second = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(second);
    const response = await requestHermesEvaluation(second.endpoint, request('lease-restart'), {
      timeoutMs: 500,
    });
    assert.equal(response.ok, true);
  });

  it('completes the daemon lifecycle when the lease helper exits unexpectedly', async () => {
    const endpoint = unixEndpoint();
    const helper = join(endpoint.path, '..', 'fake-python');
    const stopFile = join(endpoint.path, '..', 'stop-lease-helper');
    mkdirSync(join(endpoint.path, '..'), { recursive: true });
    writeFileSync(
      helper,
      '#!/bin/sh\nprintf "LOCKED\\n"\nwhile [ ! -f "$AGENTGUARD_TEST_LEASE_STOP" ]; do sleep 0.02; done\n',
      { mode: 0o700 },
    );
    chmodSync(helper, 0o700);
    const previousPython = process.env.AGENTGUARD_HERMES_PYTHON;
    const previousStop = process.env.AGENTGUARD_TEST_LEASE_STOP;
    process.env.AGENTGUARD_HERMES_PYTHON = helper;
    process.env.AGENTGUARD_TEST_LEASE_STOP = stopFile;
    let daemon: HermesEvaluatorDaemon | undefined;
    try {
      daemon = await startHermesEvaluatorDaemon({
        endpoint,
        loadConfig: () => configFor(endpoint.path),
        async protect() { return null; },
      });
      daemons.push(daemon);
      writeFileSync(stopFile, 'stop');
      await Promise.race([
        daemon.closed,
        new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error('daemon did not close after lease loss')), 1_000);
        }),
      ]);
      assert.equal(existsSync(endpoint.path), false);
    } finally {
      if (previousPython === undefined) delete process.env.AGENTGUARD_HERMES_PYTHON;
      else process.env.AGENTGUARD_HERMES_PYTHON = previousPython;
      if (previousStop === undefined) delete process.env.AGENTGUARD_TEST_LEASE_STOP;
      else process.env.AGENTGUARD_TEST_LEASE_STOP = previousStop;
      await daemon?.close();
    }
  });

  it('serializes daemon ownership across symlink aliases of the runtime directory', async () => {
    const endpoint = unixEndpoint();
    const aliasContainer = mkdtempSync(join(tmpdir(), 'agentguard-hermes-alias-'));
    roots.push(aliasContainer);
    const aliasRoot = join(aliasContainer, 'same-home');
    symlinkSync(join(endpoint.path, '..', '..'), aliasRoot, 'dir');
    const aliasEndpoint = {
      kind: 'unix' as const,
      path: join(aliasRoot, 'run', 'evaluator.sock'),
    };
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(daemon);

    await assert.rejects(
      startHermesEvaluatorDaemon({
        endpoint: aliasEndpoint,
        loadConfig: () => configFor(aliasEndpoint.path),
        async protect() { return null; },
      }),
      /lease is held/i,
    );
  });

  it('atomically recovers a lock left by a dead daemon process', async () => {
    const endpoint = unixEndpoint();
    mkdirSync(join(endpoint.path, '..'), { recursive: true });
    writeFileSync(`${endpoint.path}.lock`, JSON.stringify({
      pid: 2_147_483_647,
      token: 'a'.repeat(64),
    }), { mode: 0o600 });

    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(daemon);

    const response = await requestHermesEvaluation(daemon.endpoint, request('stale-lock'), {
      timeoutMs: 500,
    });
    assert.equal(response.ok, true);
  });

  it('recovers a stale lock after its PID has been reused', async () => {
    const endpoint = unixEndpoint();
    mkdirSync(join(endpoint.path, '..'), { recursive: true });
    writeFileSync(`${endpoint.path}.lock`, JSON.stringify({
      pid: process.pid,
      token: 'b'.repeat(64),
      processIdentity: 'a different process start identity',
    }), { mode: 0o600 });

    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(daemon);
    assert.equal(statSync(endpoint.path).isSocket(), true);
  });

  it('derives the default Windows loopback port from the current user home', () => {
    const token = 'test-token-that-is-at-least-32-bytes';
    const first = resolveHermesIpcEndpoint({
      platform: 'win32',
      home: 'C:\\Users\\alice\\.agentguard',
      env: { AGENTGUARD_HERMES_IPC_TOKEN: token },
    });
    const second = resolveHermesIpcEndpoint({
      platform: 'win32',
      home: 'C:\\Users\\bob\\.agentguard',
      env: { AGENTGUARD_HERMES_IPC_TOKEN: token },
    });

    assert.equal(first.kind, 'tcp');
    assert.equal(second.kind, 'tcp');
    if (first.kind !== 'tcp' || second.kind !== 'tcp') return;
    assert.equal(first.port, defaultHermesLoopbackPort('C:\\Users\\alice\\.agentguard'));
    assert.notEqual(first.port, second.port);
  });

  it('keeps daemon ownership when its live socket path is moved', async () => {
    const endpoint = unixEndpoint();
    const first = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      async protect() { return null; },
    });
    daemons.push(first);
    renameSync(endpoint.path, `${endpoint.path}.old`);

    await assert.rejects(
      startHermesEvaluatorDaemon({
        endpoint,
        loadConfig: () => configFor(endpoint.path),
        async protect() { return null; },
      }),
      /already running|lock/i,
    );
  });

  it('rejects a request beyond the configured byte limit before evaluation', async () => {
    const endpoint = unixEndpoint();
    let evaluations = 0;
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      maxRequestBytes: 128,
      async protect() {
        evaluations += 1;
        return null;
      },
    });
    daemons.push(daemon);

    const response = await rawExchange(endpoint.path, `${'x'.repeat(129)}\n`);

    assert.equal(response.ok, false);
    assert.equal(response.error?.code, 'REQUEST_TOO_LARGE');
    assert.equal(evaluations, 0);
  });

  it('rejects an oversized client request before opening an IPC connection', async () => {
    let connections = 0;
    const server = createNetServer(socket => {
      connections += 1;
      socket.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const endpoint = {
      kind: 'tcp' as const,
      host: '127.0.0.1' as const,
      port: address.port,
      token: 'test-token-that-is-at-least-32-bytes',
    };
    const oversized = request();
    oversized.action.rawInput = { input: 'x'.repeat(512) };

    try {
      await assert.rejects(
        requestHermesEvaluation(endpoint, oversized, { timeoutMs: 500, maxRequestBytes: 128 }),
        /request exceeded the byte limit/i,
      );
      assert.equal(connections, 0);
    } finally {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it('returns a complete newline frame when an incomplete request times out', async () => {
    const endpoint = unixEndpoint();
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      requestTimeoutMs: 40,
      async protect() { return null; },
    });
    daemons.push(daemon);

    const line = await rawExchangeLine(endpoint.path, '{"version":1');

    assert.ok(line.endsWith('\n'));
    const response = JSON.parse(line) as { ok: boolean; error?: { code?: string } };
    assert.equal(response.ok, false);
    assert.equal(response.error?.code, 'REQUEST_TIMEOUT');
  });

  it('waits for a newline response frame and rejects a hanging partial response', async () => {
    let acceptedSocket: Socket | undefined;
    const server = createNetServer(socket => {
      acceptedSocket = socket;
      socket.write('{"version":1,"id":"request-1","ok":true}');
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const endpoint = {
      kind: 'tcp' as const,
      host: '127.0.0.1' as const,
      port: address.port,
      token: 'test-token-that-is-at-least-32-bytes',
    };

    try {
      await assert.rejects(
        requestHermesEvaluation(endpoint, request(), { timeoutMs: 40 }),
        /timed out/i,
      );
    } finally {
      acceptedSocket?.destroy();
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it('uses an absolute client deadline even when a server drips response bytes', async () => {
    let interval: NodeJS.Timeout | undefined;
    const server = createNetServer(socket => {
      interval = setInterval(() => socket.write(' '), 15);
      const destroyTimer = setTimeout(() => socket.destroy(), 180);
      socket.on('error', () => {});
      socket.once('close', () => {
        clearTimeout(destroyTimer);
        if (interval) clearInterval(interval);
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const endpoint = {
      kind: 'tcp' as const,
      host: '127.0.0.1' as const,
      port: address.port,
      token: 'test-token-that-is-at-least-32-bytes',
    };
    const startedAt = Date.now();

    try {
      await assert.rejects(
        requestHermesEvaluation(endpoint, request(), { timeoutMs: 50 }),
        /timed out/i,
      );
      assert.ok(Date.now() - startedAt < 130);
    } finally {
      if (interval) clearInterval(interval);
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it('uses an absolute server deadline even when a client drips request bytes', async () => {
    const endpoint = unixEndpoint();
    const daemon = await startHermesEvaluatorDaemon({
      endpoint,
      loadConfig: () => configFor(endpoint.path),
      requestTimeoutMs: 50,
      async protect() { return null; },
    });
    daemons.push(daemon);
    const startedAt = Date.now();
    const line = await drippingRequest(endpoint.path, 15, 180);

    assert.equal(JSON.parse(line).error?.code, 'REQUEST_TIMEOUT');
    assert.ok(Date.now() - startedAt < 130);
  });

  it('authenticates a loopback server before sending credentials or action content', async () => {
    const frames: Array<Record<string, unknown>> = [];
    const server = createNetServer(socket => {
      let buffered = '';
      socket.setEncoding('utf8');
      socket.on('data', chunk => {
        buffered += chunk;
        const newline = buffered.indexOf('\n');
        if (newline < 0) return;
        frames.push(JSON.parse(buffered.slice(0, newline)) as Record<string, unknown>);
        socket.end(`${JSON.stringify({
          version: 1,
          id: 'request-1',
          kind: 'challenge',
          serverNonce: 'attacker-controlled',
          serverProof: 'invalid',
        })}\n`);
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const endpoint = {
      kind: 'tcp' as const,
      host: '127.0.0.1' as const,
      port: address.port,
      token: 'test-token-that-is-at-least-32-bytes',
    };

    try {
      await assert.rejects(
        requestHermesEvaluation(endpoint, request(), { timeoutMs: 500 }),
        /authentication/i,
      );
      assert.equal(frames.length, 1);
      assert.equal(frames[0]?.kind, 'hello');
      assert.equal(typeof frames[0]?.clientNonce, 'string');
      assert.equal(JSON.stringify(frames[0]).includes(endpoint.token), false);
      assert.equal(JSON.stringify(frames[0]).includes('private.person'), false);
    } finally {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it('requires the shared token on the Windows loopback transport', async () => {
    let evaluations = 0;
    const daemon = await startHermesEvaluatorDaemon({
      endpoint: {
        kind: 'tcp',
        host: '127.0.0.1',
        port: 0,
        token: 'correct-token-that-is-at-least-32b',
      },
      loadConfig: () => ({
        version: 1,
        level: 'balanced',
        policyCachePath: join(tmpdir(), 'unused-policy.json'),
        auditPath: join(tmpdir(), 'unused-audit.jsonl'),
        eventSpoolPath: join(tmpdir(), 'unused-spool.jsonl'),
      }),
      async protect() {
        evaluations += 1;
        return null;
      },
    });
    daemons.push(daemon);
    assert.equal(daemon.endpoint.kind, 'tcp');
    if (daemon.endpoint.kind !== 'tcp') return;

    const denied = await rawTcpExchange(daemon.endpoint.port, {
      ...request('wrong-token'),
      authToken: 'wrong-token',
    });
    assert.equal(denied.ok, false);
    assert.equal(denied.error?.code, 'UNAUTHORIZED');
    assert.equal(evaluations, 0);

    const mismatchedId = await rawTcpMismatchedIdExchange(daemon.endpoint.port);
    assert.equal(mismatchedId.ok, false);
    assert.equal(mismatchedId.error?.code, 'UNAUTHORIZED');
    assert.equal(evaluations, 0);

    const allowed = await requestHermesEvaluation(daemon.endpoint, request('right-token'), { timeoutMs: 500 });
    assert.equal(allowed.ok, true);
    assert.equal(evaluations, 1);
  });
});

async function rawExchange(path: string, payload: string): Promise<{
  ok: boolean;
  error?: { code?: string };
}> {
  return JSON.parse(await rawExchangeLine(path, payload));
}

async function rawExchangeLine(path: string, payload: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const socket = createConnection(path);
    let response = '';
    socket.setEncoding('utf8');
    socket.once('error', reject);
    socket.on('data', chunk => { response += chunk; });
    socket.once('end', () => resolve(response));
    socket.once('connect', () => socket.write(payload));
  });
}

async function rawTcpExchange(port: number, payload: Record<string, unknown>): Promise<{
  ok: boolean;
  error?: { code?: string };
}> {
  return await new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    let response = '';
    socket.setEncoding('utf8');
    socket.once('error', reject);
    socket.on('data', chunk => { response += chunk; });
    socket.once('end', () => resolve(JSON.parse(response)));
    socket.once('connect', () => socket.end(`${JSON.stringify(payload)}\n`));
  });
}

async function rawTcpMismatchedIdExchange(port: number): Promise<{
  ok: boolean;
  error?: { code?: string };
}> {
  return await new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    let buffered = '';
    let challenged = false;
    socket.setEncoding('utf8');
    socket.once('error', reject);
    socket.once('connect', () => socket.write(`${JSON.stringify({
      version: 1,
      id: 'hello-id',
      kind: 'hello',
      clientNonce: 'a'.repeat(64),
    })}\n`));
    socket.on('data', chunk => {
      buffered += chunk;
      const newline = buffered.indexOf('\n');
      if (newline < 0) return;
      const frame = JSON.parse(buffered.slice(0, newline)) as Record<string, unknown>;
      buffered = buffered.slice(newline + 1);
      if (!challenged) {
        challenged = true;
        assert.equal(frame.kind, 'challenge');
        socket.write(`${JSON.stringify({
          ...request('different-action-id'),
          authProof: '',
        })}\n`);
        return;
      }
      socket.destroy();
      resolve(frame as { ok: boolean; error?: { code?: string } });
    });
  });
}

async function drippingRequest(path: string, intervalMs: number, stopAfterMs: number): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const socket = createConnection(path);
    let response = '';
    let interval: NodeJS.Timeout | undefined;
    const stop = setTimeout(() => {
      if (interval) clearInterval(interval);
    }, stopAfterMs);
    socket.setEncoding('utf8');
    socket.once('error', reject);
    socket.on('data', chunk => { response += chunk; });
    socket.once('end', () => {
      clearTimeout(stop);
      if (interval) clearInterval(interval);
      resolve(response);
    });
    socket.once('connect', () => {
      interval = setInterval(() => socket.write('{'), intervalMs);
    });
  });
}
