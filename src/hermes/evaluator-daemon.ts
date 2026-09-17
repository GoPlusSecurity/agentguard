import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
} from 'node:child_process';
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { ensureConfig, type AgentGuardConfig } from '../config.js';
import {
  protectAction,
  type ProtectOptions,
  type ProtectResult,
} from '../runtime/protect.js';
import type {
  CoverageLevel,
  EnforcementStatus,
  MissingLlmFact,
  PolicyReason,
  RuntimeActionType,
  RuntimeRiskLevel,
} from '../runtime/types.js';

export const HERMES_IPC_VERSION = 1 as const;
export const DEFAULT_HERMES_MAX_REQUEST_BYTES = 1024 * 1024;
export const DEFAULT_HERMES_IPC_TIMEOUT_MS = 10_000;
export const DEFAULT_HERMES_MAX_RESPONSE_BYTES = 256 * 1024;
const HERMES_LOOPBACK_PORT_BASE = 40_000;
const HERMES_LOOPBACK_PORT_SPAN = 20_000;

export type HermesIpcEndpoint =
  | { kind: 'unix'; path: string }
  | { kind: 'tcp'; host: '127.0.0.1'; port: number; token: string };

export interface HermesEvaluatorRequest {
  version: typeof HERMES_IPC_VERSION;
  id: string;
  authProof?: string;
  action: {
    rawInput: unknown;
    actionType?: RuntimeActionType;
    toolName?: string;
    sessionId?: string;
    phase?: 'pre' | 'post';
  };
}

export interface HermesEvaluatorResult {
  decision: ProtectResult['decision']['decision'];
  policyDecision: ProtectResult['decision']['decision'];
  actionId: string;
  riskScore: number;
  riskLevel: RuntimeRiskLevel;
  reasons: PolicyReason[];
  policyVersion: string;
  policySource: ProtectResult['policySource'];
  coverageLevel?: CoverageLevel;
  enforcementStatus?: EnforcementStatus;
  canBlockCurrentAction?: boolean;
  missingFacts?: MissingLlmFact[];
}

export type HermesEvaluatorResponse =
  | {
      version: typeof HERMES_IPC_VERSION;
      id: string;
      ok: true;
      result: HermesEvaluatorResult | null;
    }
  | {
      version: typeof HERMES_IPC_VERSION;
      id: string;
      ok: false;
      error: { code: string; message: string };
    };

interface HermesAuthenticationChallenge {
  version: typeof HERMES_IPC_VERSION;
  id: string;
  kind: 'challenge';
  serverNonce: string;
  serverProof: string;
}

interface ConnectionAuthentication {
  id: string;
  clientNonce: string;
  serverNonce: string;
}

export interface HermesEvaluatorDaemon {
  endpoint: HermesIpcEndpoint;
  readonly closed: Promise<void>;
  close(): Promise<void>;
}

export interface StartHermesEvaluatorDaemonOptions {
  endpoint?: HermesIpcEndpoint;
  maxRequestBytes?: number;
  requestTimeoutMs?: number;
  protect?: (options: ProtectOptions) => Promise<ProtectResult | null>;
  loadConfig?: () => AgentGuardConfig;
}

export function resolveHermesIpcEndpoint(options: {
  platform?: NodeJS.Platform;
  home?: string;
  env?: NodeJS.ProcessEnv;
} = {}): HermesIpcEndpoint {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const home = options.home ?? env.AGENTGUARD_HOME?.trim() ?? join(homedir(), '.agentguard');
  if (platform !== 'win32') {
    return { kind: 'unix', path: join(home, 'run', 'hermes-evaluator.sock') };
  }

  const token = env.AGENTGUARD_HERMES_IPC_TOKEN?.trim() ?? '';
  if (Buffer.byteLength(token, 'utf8') < 32) {
    throw new Error('AGENTGUARD_HERMES_IPC_TOKEN must contain at least 32 bytes on Windows');
  }
  const rawPort = env.AGENTGUARD_HERMES_IPC_PORT?.trim();
  const port = rawPort === undefined || rawPort === ''
    ? defaultHermesLoopbackPort(home)
    : Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('AGENTGUARD_HERMES_IPC_PORT must be an integer from 1 to 65535');
  }
  return { kind: 'tcp', host: '127.0.0.1', port, token };
}

export function defaultHermesLoopbackPort(home: string): number {
  const digest = createHash('sha256').update(resolve(home), 'utf8').digest();
  return HERMES_LOOPBACK_PORT_BASE + (digest.readUInt32BE(0) % HERMES_LOOPBACK_PORT_SPAN);
}

export async function startHermesEvaluatorDaemon(
  options: StartHermesEvaluatorDaemonOptions = {},
): Promise<HermesEvaluatorDaemon> {
  const endpoint = options.endpoint ?? resolveHermesIpcEndpoint();
  const maxRequestBytes = positiveInteger(
    options.maxRequestBytes,
    DEFAULT_HERMES_MAX_REQUEST_BYTES,
    'maxRequestBytes',
  );
  const requestTimeoutMs = positiveInteger(
    options.requestTimeoutMs,
    DEFAULT_HERMES_IPC_TIMEOUT_MS,
    'requestTimeoutMs',
  );
  const protect = options.protect ?? protectAction;
  const loadConfig = options.loadConfig ?? ensureConfig;
  validateEndpoint(endpoint);

  let unixLease: UnixDaemonLease | undefined;
  let unixLock: UnixDaemonLock | undefined;
  if (endpoint.kind === 'unix') {
    try {
      unixLease = await acquireUnixDaemonLease(endpoint.path);
      assertUnixDaemonLease(unixLease);
      unixLock = acquireUnixDaemonLock(endpoint.path);
      await prepareUnixSocket(endpoint.path, unixLock);
      assertUnixDaemonLock(unixLock);
    } catch (error) {
      if (unixLock) releaseUnixDaemonLock(unixLock);
      if (unixLease) await closeUnixDaemonLease(unixLease);
      throw error;
    }
  }

  const sockets = new Set<Socket>();
  const server = createServer({ allowHalfOpen: true }, socket => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    handleConnection(socket, endpoint, {
      maxRequestBytes,
      requestTimeoutMs,
      protect,
      loadConfig,
    });
  });

  try {
    if (unixLock) assertUnixDaemonLock(unixLock);
    if (unixLease) assertUnixDaemonLease(unixLease);
    await listen(server, endpoint);
    if (unixLock) assertUnixDaemonLock(unixLock);
    if (unixLease) assertUnixDaemonLease(unixLease);
  } catch (error) {
    await closeServer(server, sockets);
    if (unixLock) releaseUnixDaemonLock(unixLock);
    if (unixLease) await closeUnixDaemonLease(unixLease);
    throw error;
  }
  let boundEndpoint = endpoint;
  let unixSocketIdentity: SocketIdentity | undefined;
  if (endpoint.kind === 'unix') {
    try {
      unixSocketIdentity = socketIdentity(endpoint.path);
      chmodSync(endpoint.path, 0o600);
    } catch (error) {
      try {
        await closeServer(server, sockets);
        if (unixSocketIdentity) removeOwnedSocket(endpoint.path, unixSocketIdentity);
      } finally {
        if (unixLock) releaseUnixDaemonLock(unixLock);
        if (unixLease) await closeUnixDaemonLease(unixLease);
      }
      throw error;
    }
  } else {
    const address = server.address();
    if (!address || typeof address === 'string') {
      await closeServer(server, sockets);
      throw new Error('Hermes evaluator did not bind a TCP address');
    }
    boundEndpoint = { ...endpoint, port: address.port };
  }

  let resolveClosed!: () => void;
  const closed = new Promise<void>(resolveLifecycle => { resolveClosed = resolveLifecycle; });
  let closePromise: Promise<void> | undefined;
  const daemon: HermesEvaluatorDaemon = {
    endpoint: boundEndpoint,
    closed,
    close() {
      if (!closePromise) {
        closePromise = (async () => {
          try {
            if (endpoint.kind === 'unix' && unixSocketIdentity) {
              try {
                await closeServer(server, sockets);
                removeOwnedSocket(endpoint.path, unixSocketIdentity);
              } finally {
                if (unixLock) releaseUnixDaemonLock(unixLock);
                if (unixLease) await closeUnixDaemonLease(unixLease);
              }
            } else {
              await closeServer(server, sockets);
            }
          } finally {
            resolveClosed();
          }
        })();
      }
      return closePromise;
    },
  };
  unixLease?.onLost(() => {
    void daemon.close().catch(() => {
      // `closed` still resolves in close()'s finally block so the CLI can exit.
    });
  });
  return daemon;
}

export async function requestHermesEvaluation(
  endpoint: HermesIpcEndpoint,
  request: HermesEvaluatorRequest,
  options: { timeoutMs?: number; maxRequestBytes?: number; maxResponseBytes?: number } = {},
): Promise<HermesEvaluatorResponse> {
  validateEndpoint(endpoint);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_HERMES_IPC_TIMEOUT_MS, 'timeoutMs');
  const maxRequestBytes = positiveInteger(
    options.maxRequestBytes,
    DEFAULT_HERMES_MAX_REQUEST_BYTES,
    'maxRequestBytes',
  );
  const maxResponseBytes = positiveInteger(
    options.maxResponseBytes,
    DEFAULT_HERMES_MAX_RESPONSE_BYTES,
    'maxResponseBytes',
  );
  const sizeCheckedRequest = endpoint.kind === 'tcp'
    ? { ...request, authProof: '0'.repeat(64) }
    : request;
  if (Buffer.byteLength(`${JSON.stringify(sizeCheckedRequest)}\n`, 'utf8') > maxRequestBytes) {
    throw new Error('Hermes evaluator request exceeded the byte limit');
  }

  return await new Promise<HermesEvaluatorResponse>((resolve, reject) => {
    const socket = endpoint.kind === 'unix'
      ? createConnection(endpoint.path)
      : createConnection({ host: endpoint.host, port: endpoint.port });
    let buffered = Buffer.alloc(0);
    let totalBytes = 0;
    let settled = false;
    let phase: 'challenge' | 'response' = endpoint.kind === 'tcp' ? 'challenge' : 'response';
    const clientNonce = endpoint.kind === 'tcp' ? randomBytes(32).toString('hex') : '';

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadlineTimer);
      socket.destroy();
      reject(error);
    };
    const deadlineTimer = setTimeout(
      () => fail(new Error('Hermes evaluator response timed out')),
      timeoutMs,
    );
    socket.once('error', error => fail(error));
    socket.once('connect', () => {
      if (endpoint.kind === 'unix') {
        socket.write(`${JSON.stringify(request)}\n`);
        return;
      }
      socket.write(`${JSON.stringify({
        version: HERMES_IPC_VERSION,
        id: request.id,
        kind: 'hello',
        clientNonce,
      })}\n`);
    });
    socket.on('data', (chunk: Buffer) => {
      if (settled) return;
      totalBytes += chunk.length;
      if (totalBytes > maxResponseBytes) {
        fail(new Error('Hermes evaluator response exceeded the byte limit'));
        return;
      }
      buffered = Buffer.concat([buffered, chunk]);
      while (!settled) {
        const newline = buffered.indexOf(0x0a);
        if (newline < 0) return;
        const frame = buffered.subarray(0, newline);
        buffered = buffered.subarray(newline + 1);
        let value: unknown;
        try {
          value = JSON.parse(frame.toString('utf8')) as unknown;
        } catch {
          fail(new Error('Hermes evaluator returned malformed JSON'));
          return;
        }

        if (phase === 'challenge') {
          if (endpoint.kind !== 'tcp' || !isValidChallenge(value, request.id, clientNonce, endpoint.token)) {
            fail(new Error('Hermes evaluator server authentication failed'));
            return;
          }
          const challenge = value as HermesAuthenticationChallenge;
          const authenticatedRequest: HermesEvaluatorRequest = {
            ...request,
            authProof: authenticationProof(
              endpoint.token,
              'client',
              request.id,
              clientNonce,
              challenge.serverNonce,
            ),
          };
          phase = 'response';
          socket.write(`${JSON.stringify(authenticatedRequest)}\n`);
          continue;
        }

        const response = value as HermesEvaluatorResponse;
        if (buffered.toString('utf8').trim().length > 0) {
          fail(new Error('Hermes evaluator returned multiple response frames'));
          return;
        }
        if (response.version !== HERMES_IPC_VERSION || response.id !== request.id) {
          fail(new Error('Hermes evaluator returned a mismatched response'));
          return;
        }
        settled = true;
        clearTimeout(deadlineTimer);
        socket.destroy();
        resolve(response);
      }
    });
    socket.once('end', () => {
      if (!settled) fail(new Error('Hermes evaluator response ended before a newline frame'));
    });
  });
}

interface ConnectionOptions {
  maxRequestBytes: number;
  requestTimeoutMs: number;
  protect: (options: ProtectOptions) => Promise<ProtectResult | null>;
  loadConfig: () => AgentGuardConfig;
}

function handleConnection(
  socket: Socket,
  endpoint: HermesIpcEndpoint,
  options: ConnectionOptions,
): void {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  let finished = false;
  let evaluating = false;
  let authentication: ConnectionAuthentication | undefined;
  const finish = (response: HermesEvaluatorResponse) => {
    if (finished) return;
    finished = true;
    clearTimeout(requestDeadline);
    socket.end(`${JSON.stringify(response)}\n`);
  };
  const fail = (code: string, message: string, id = '') => finish(errorResponse(id, code, message));

  const requestDeadline = setTimeout(() => {
    fail('REQUEST_TIMEOUT', 'Hermes evaluator request timed out');
  }, options.requestTimeoutMs);
  socket.once('error', () => {
    finished = true;
    clearTimeout(requestDeadline);
  });
  socket.on('data', (chunk: Buffer) => {
    if (finished || evaluating) return;
    totalBytes += chunk.length;
    if (totalBytes > options.maxRequestBytes) {
      fail('REQUEST_TOO_LARGE', 'Hermes evaluator request exceeded the byte limit');
      return;
    }
    chunks.push(chunk);
    const buffered = Buffer.concat(chunks, totalBytes);
    const newline = buffered.indexOf(0x0a);
    if (newline < 0) return;
    const trailing = buffered.subarray(newline + 1).toString('utf8').trim();
    if (trailing.length > 0) {
      fail('MULTIPLE_REQUESTS', 'Only one evaluator request is allowed per connection');
      return;
    }

    if (endpoint.kind === 'tcp' && !authentication) {
      const hello = parseAuthenticationHello(buffered.subarray(0, newline));
      if (!hello) {
        fail('UNAUTHORIZED', 'Hermes evaluator authentication handshake failed');
        return;
      }
      const serverNonce = randomBytes(32).toString('hex');
      authentication = { id: hello.id, clientNonce: hello.clientNonce, serverNonce };
      chunks.length = 0;
      totalBytes = 0;
      const challenge: HermesAuthenticationChallenge = {
        version: HERMES_IPC_VERSION,
        id: hello.id,
        kind: 'challenge',
        serverNonce,
        serverProof: authenticationProof(
          endpoint.token,
          'server',
          hello.id,
          hello.clientNonce,
          serverNonce,
        ),
      };
      socket.write(`${JSON.stringify(challenge)}\n`);
      return;
    }

    evaluating = true;
    socket.pause();
    void evaluateFrame(buffered.subarray(0, newline), endpoint, options, authentication)
      .then(finish)
      .catch(() => fail('EVALUATION_FAILED', 'AgentGuard evaluation failed'));
  });
}

async function evaluateFrame(
  frame: Buffer,
  endpoint: HermesIpcEndpoint,
  options: ConnectionOptions,
  authentication?: ConnectionAuthentication,
): Promise<HermesEvaluatorResponse> {
  let request: HermesEvaluatorRequest;
  try {
    request = JSON.parse(frame.toString('utf8')) as HermesEvaluatorRequest;
  } catch {
    return errorResponse('', 'MALFORMED_JSON', 'Hermes evaluator request was not valid JSON');
  }
  const validation = validateRequest(request);
  if (validation) return errorResponse(request?.id ?? '', 'INVALID_REQUEST', validation);
  if (endpoint.kind === 'tcp') {
    if (
      !authentication
      || request.id !== authentication.id
      || typeof request.authProof !== 'string'
      || !/^[a-f0-9]{64}$/.test(request.authProof)
    ) {
      return errorResponse(request.id, 'UNAUTHORIZED', 'Hermes evaluator authentication failed');
    }
    const expectedProof = authenticationProof(
      endpoint.token,
      'client',
      request.id,
      authentication.clientNonce,
      authentication.serverNonce,
    );
    if (!tokensMatch(request.authProof, expectedProof)) {
      return errorResponse(request.id, 'UNAUTHORIZED', 'Hermes evaluator authentication failed');
    }
  }

  const result = await options.protect({
    config: options.loadConfig(),
    rawInput: request.action.rawInput,
    agentHost: 'hermes',
    actionType: request.action.actionType,
    toolName: request.action.toolName,
    sessionId: request.action.sessionId,
    decisionMode: 'local-first',
    phase: request.action.phase,
  });
  return {
    version: HERMES_IPC_VERSION,
    id: request.id,
    ok: true,
    result: result ? serializeResult(result) : null,
  };
}

function serializeResult(result: ProtectResult): HermesEvaluatorResult {
  return {
    decision: result.decision.decision,
    policyDecision: result.decision.policyDecision ?? result.decision.decision,
    actionId: result.decision.actionId,
    riskScore: result.decision.riskScore,
    riskLevel: result.decision.riskLevel,
    reasons: result.decision.reasons,
    policyVersion: result.decision.policyVersion,
    policySource: result.policySource,
    coverageLevel: result.event.coverageLevel,
    enforcementStatus: result.event.enforcementStatus,
    canBlockCurrentAction: result.event.canBlockCurrentAction,
    missingFacts: result.event.missingFacts,
  };
}

function parseAuthenticationHello(frame: Buffer): { id: string; clientNonce: string } | null {
  let value: unknown;
  try {
    value = JSON.parse(frame.toString('utf8')) as unknown;
  } catch {
    return null;
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const hello = value as Record<string, unknown>;
  if (hello.version !== HERMES_IPC_VERSION || hello.kind !== 'hello') return null;
  if (typeof hello.id !== 'string' || hello.id.length < 1 || hello.id.length > 200) return null;
  if (typeof hello.clientNonce !== 'string' || !/^[a-f0-9]{64}$/.test(hello.clientNonce)) return null;
  return { id: hello.id, clientNonce: hello.clientNonce };
}

function isValidChallenge(
  value: unknown,
  id: string,
  clientNonce: string,
  token: string,
): value is HermesAuthenticationChallenge {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const challenge = value as Partial<HermesAuthenticationChallenge>;
  if (
    challenge.version !== HERMES_IPC_VERSION
    || challenge.id !== id
    || challenge.kind !== 'challenge'
    || typeof challenge.serverNonce !== 'string'
    || !/^[a-f0-9]{64}$/.test(challenge.serverNonce)
  ) return false;
  return tokensMatch(
    challenge.serverProof,
    authenticationProof(token, 'server', id, clientNonce, challenge.serverNonce),
  );
}

function authenticationProof(
  token: string,
  role: 'client' | 'server',
  id: string,
  clientNonce: string,
  serverNonce: string,
): string {
  return createHmac('sha256', token)
    .update([role, String(HERMES_IPC_VERSION), id, clientNonce, serverNonce].join('\0'))
    .digest('hex');
}

function validateRequest(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'Request must be an object';
  const request = value as Partial<HermesEvaluatorRequest>;
  if (request.version !== HERMES_IPC_VERSION) return 'Unsupported protocol version';
  if (typeof request.id !== 'string' || request.id.length < 1 || request.id.length > 200) {
    return 'Request id must contain 1 to 200 characters';
  }
  if (!request.action || typeof request.action !== 'object' || Array.isArray(request.action)) {
    return 'Request action must be an object';
  }
  return null;
}

function validateEndpoint(endpoint: HermesIpcEndpoint): void {
  if (endpoint.kind === 'unix') {
    if (!endpoint.path) throw new Error('Hermes evaluator Unix socket path is required');
    return;
  }
  if (endpoint.host !== '127.0.0.1') {
    throw new Error('Hermes evaluator TCP transport must bind to 127.0.0.1');
  }
  if (!Number.isSafeInteger(endpoint.port) || endpoint.port < 0 || endpoint.port > 65_535) {
    throw new Error('Hermes evaluator TCP port must be an integer from 0 to 65535');
  }
  if (Buffer.byteLength(endpoint.token, 'utf8') < 32) {
    throw new Error('Hermes evaluator TCP token must contain at least 32 bytes');
  }
}

interface UnixDaemonLock {
  path: string;
  token: string;
}

interface UnixDaemonLease {
  child: ChildProcessWithoutNullStreams;
  path: string;
  closing: boolean;
  onLost(callback: () => void): void;
}

const UNIX_LEASE_HELPER = [
  'import fcntl, os, sys',
  'fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o600)',
  'os.fchmod(fd, 0o600)',
  'try:',
  '    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)',
  'except BlockingIOError:',
  '    sys.exit(73)',
  'sys.stdout.write("LOCKED\\n")',
  'sys.stdout.flush()',
  'sys.stdin.buffer.read()',
].join('\n');

async function acquireUnixDaemonLease(socketPath: string): Promise<UnixDaemonLease> {
  const directory = dirname(socketPath);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const canonicalDirectory = realpathSync.native(directory);
  const path = join(canonicalDirectory, `${basename(socketPath)}.lease`);
  const python = process.env.AGENTGUARD_HERMES_PYTHON?.trim() || 'python3';
  const child = spawn(python, ['-c', UNIX_LEASE_HELPER, path], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => { stderr += chunk; });

  await new Promise<void>((resolveLease, rejectLease) => {
    let stdout = '';
    const timer = setTimeout(() => finish(new Error('Timed out acquiring the Hermes evaluator lease')), 3_000);
    const onData = (chunk: Buffer | string) => {
      stdout += chunk.toString();
      if (stdout.includes('LOCKED\n')) finish();
    };
    const onError = (error: Error) => finish(error);
    const onExit = (code: number | null) => finish(new Error(
      code === 73
        ? `Hermes evaluator daemon is already running or its lease is held: ${path}`
        : `Hermes evaluator lease helper exited before locking: ${stderr.trim() || code}`,
    ));
    const finish = (error?: Error) => {
      clearTimeout(timer);
      child.stdout.off('data', onData);
      child.off('error', onError);
      child.off('exit', onExit);
      if (error) {
        child.kill('SIGKILL');
        rejectLease(error);
      } else {
        resolveLease();
      }
    };
    child.stdout.on('data', onData);
    child.once('error', onError);
    child.once('exit', onExit);
  });

  const lostHandlers = new Set<() => void>();
  const lease: UnixDaemonLease = {
    child,
    path,
    closing: false,
    onLost(callback) {
      if (child.exitCode !== null || child.signalCode !== null) queueMicrotask(callback);
      else lostHandlers.add(callback);
    },
  };
  child.once('exit', () => {
    if (lease.closing) return;
    for (const callback of lostHandlers) callback();
    lostHandlers.clear();
  });
  return lease;
}

function assertUnixDaemonLease(lease: UnixDaemonLease): void {
  if (lease.child.exitCode !== null || lease.child.signalCode !== null) {
    throw new Error(`Lost Hermes evaluator daemon lease ownership: ${lease.path}`);
  }
}

async function closeUnixDaemonLease(lease: UnixDaemonLease): Promise<void> {
  if (lease.closing) return;
  lease.closing = true;
  if (lease.child.exitCode !== null || lease.child.signalCode !== null) return;
  lease.child.stdin.end();
  await new Promise<void>(resolveLease => {
    const timer = setTimeout(() => lease.child.kill('SIGKILL'), 1_000);
    lease.child.once('exit', () => {
      clearTimeout(timer);
      resolveLease();
    });
  });
}

function acquireUnixDaemonLock(socketPath: string): UnixDaemonLock {
  const directory = dirname(socketPath);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const path = `${socketPath}.lock`;
  const processIdentity = processStartIdentity(process.pid);
  if (!processIdentity) {
    throw new Error('Unable to determine the Hermes evaluator process start identity');
  }

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const token = randomBytes(32).toString('hex');
    const uniquePath = `${path}.${process.pid}.${token}`;
    writeFileSync(uniquePath, JSON.stringify({ pid: process.pid, token, processIdentity }), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    try {
      linkSync(uniquePath, path);
      return { path, token };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    } finally {
      try {
        unlinkSync(uniquePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }

    let observedStat;
    try {
      observedStat = lstatSync(path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    const observedOwner = readUnixDaemonLock(path);
    if (observedOwner) {
      const activeIdentity = processStartIdentity(observedOwner.pid);
      if (
        activeIdentity === observedOwner.processIdentity
        || (!observedOwner.processIdentity && processIsAlive(observedOwner.pid))
      ) {
        throw new Error(`Hermes evaluator daemon is already running (lock: ${path})`);
      }
    }

    const quarantinePath = `${path}.stale.${process.pid}.${randomBytes(16).toString('hex')}`;
    try {
      renameSync(path, quarantinePath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    const movedStat = lstatSync(quarantinePath);
    if (movedStat.dev !== observedStat.dev || movedStat.ino !== observedStat.ino) {
      try {
        linkSync(quarantinePath, path);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          throw new Error(
            `Hermes evaluator lock changed during stale recovery; displaced lock preserved at ${quarantinePath}`,
          );
        }
        throw error;
      }
      unlinkSync(quarantinePath);
      continue;
    }
    unlinkSync(quarantinePath);
  }

  throw new Error(`Unable to acquire Hermes evaluator daemon lock: ${path}`);
}

function readUnixDaemonLock(path: string): {
  pid: number;
  token: string;
  processIdentity?: string;
} | null {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    if (!Number.isSafeInteger(value.pid) || (value.pid as number) < 1) return null;
    if (typeof value.token !== 'string' || !/^[a-f0-9]{64}$/.test(value.token)) return null;
    if (value.processIdentity !== undefined && typeof value.processIdentity !== 'string') return null;
    return {
      pid: value.pid as number,
      token: value.token,
      processIdentity: value.processIdentity,
    };
  } catch {
    return null;
  }
}

function processStartIdentity(pid: number): string | null {
  try {
    const value = execFileSync('/bin/ps', ['-p', String(pid), '-o', 'lstart='], {
      encoding: 'utf8',
      maxBuffer: 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, LC_ALL: 'C', LANG: 'C' },
    }).trim();
    return value || null;
  } catch {
    return null;
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function assertUnixDaemonLock(lock: UnixDaemonLock): void {
  if (readUnixDaemonLock(lock.path)?.token !== lock.token) {
    throw new Error(`Lost Hermes evaluator daemon lock ownership: ${lock.path}`);
  }
}

function releaseUnixDaemonLock(lock: UnixDaemonLock): void {
  try {
    if (readUnixDaemonLock(lock.path)?.token === lock.token) unlinkSync(lock.path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    assertUnixDaemonLock(lock);
  }
}

async function prepareUnixSocket(path: string, lock: UnixDaemonLock): Promise<void> {
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  assertUnixDaemonLock(lock);
  try {
    const stat = lstatSync(path);
    if (!stat.isSocket()) throw new Error(`Refusing to replace non-socket path: ${path}`);
    if (typeof process.getuid === 'function' && typeof stat.uid === 'number' && stat.uid !== process.getuid()) {
      throw new Error(`Refusing to replace a socket owned by another user: ${path}`);
    }
    if (await unixSocketIsActive(path)) {
      throw new Error(`Hermes evaluator daemon is already running: ${path}`);
    }
    assertUnixDaemonLock(lock);
    const current = lstatSync(path);
    if (current.dev !== stat.dev || current.ino !== stat.ino) {
      throw new Error(`Refusing to replace a Unix socket that changed during validation: ${path}`);
    }
    unlinkSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

function unixSocketIsActive(path: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    let settled = false;
    const finish = (active: boolean, error?: Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(active);
    };
    socket.setTimeout(250, () => finish(true));
    socket.once('connect', () => finish(true));
    socket.once('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ECONNREFUSED' || error.code === 'ENOENT') finish(false);
      else finish(false, error);
    });
  });
}

interface SocketIdentity {
  dev: number;
  ino: number;
}

function socketIdentity(path: string): SocketIdentity {
  const stat = lstatSync(path);
  if (!stat.isSocket()) throw new Error(`Expected a Unix socket: ${path}`);
  return { dev: stat.dev, ino: stat.ino };
}

function removeOwnedSocket(path: string, expected: SocketIdentity): void {
  try {
    const stat = lstatSync(path);
    if (!stat.isSocket()) return;
    if (typeof process.getuid === 'function' && typeof stat.uid === 'number' && stat.uid !== process.getuid()) return;
    if (stat.dev !== expected.dev || stat.ino !== expected.ino) return;
    unlinkSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

function listen(server: Server, endpoint: HermesIpcEndpoint): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      server.off('listening', onListening);
      reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    if (endpoint.kind === 'unix') server.listen(endpoint.path);
    else server.listen(endpoint.port, endpoint.host);
  });
}

async function closeServer(server: Server, sockets: Set<Socket>): Promise<void> {
  for (const socket of sockets) socket.destroy();
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
}

function errorResponse(id: string, code: string, message: string): HermesEvaluatorResponse {
  return { version: HERMES_IPC_VERSION, id, ok: false, error: { code, message } };
}

function tokensMatch(actual: string | undefined, expected: string): boolean {
  if (typeof actual !== 'string') return false;
  const left = Buffer.from(actual, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length > 0 && left.length === right.length && timingSafeEqual(left, right);
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return resolved;
}
