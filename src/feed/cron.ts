import { spawn } from 'node:child_process';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';

export type CronBackend = 'auto' | 'openclaw' | 'qclaw' | 'hermes' | 'system';
export type ResolvedCronBackend = 'openclaw' | 'openclaw-gateway' | 'qclaw-gateway' | 'hermes' | 'system';
export type CronAgentHost = 'claude-code' | 'codex' | 'openclaw' | 'hermes' | 'qclaw';

export interface OpenClawCronInstallResult {
  name: string;
  schedule: string;
  timezone: string;
  created: boolean;
  backend?: ResolvedCronBackend;
  command?: string;
  script?: string;
}

export interface OpenClawGatewayOptions {
  host?: string;
  port?: number;
  url?: string;
  label?: string;
  timeoutMs?: number;
  request?: (method: string, params: unknown) => Promise<unknown>;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
}

export type CommandRunner = (command: string, args: string[], input?: string) => Promise<CommandResult>;

interface OpenClawCronJob {
  id?: string;
  name?: string;
}

class GatewayHttpFallbackError extends Error {}

export function validateCronExpression(value: string): string {
  const expr = value.trim();
  const fields = expr.split(/\s+/);
  if (fields.length !== 5) {
    throw new Error('Invalid --cron. Use a standard five-field cron expression, for example "0 * * * *".');
  }
  if (fields.some((field) => field.length === 0)) {
    throw new Error('Invalid --cron. Use a standard five-field cron expression, for example "0 * * * *".');
  }
  return fields.join(' ');
}

export function localTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
}

export async function installThreatFeedCron(
  options: {
    name: string;
    cronExpression: string;
    quiet: boolean;
    force: boolean;
    backend?: CronBackend;
    agentHost?: CronAgentHost;
    agentGuardHome?: string;
    hermesHome?: string;
    timezone?: string;
  },
  adapters: {
    gateway?: OpenClawGatewayOptions;
    runCommand?: CommandRunner;
  } = {}
): Promise<OpenClawCronInstallResult> {
  const backend = options.backend ?? 'auto';
  if (backend === 'auto' && !options.agentHost) {
    throw new Error(
      'Cron target auto requires a saved agent host. Run `agentguard init --agent <claude-code|codex|openclaw|hermes|qclaw>` first, or pass `--cron-target openclaw`, `--cron-target qclaw`, `--cron-target hermes`, or `--cron-target system`.'
    );
  }
  if (backend === 'system' || (backend === 'auto' && options.agentHost !== 'openclaw' && options.agentHost !== 'qclaw' && options.agentHost !== 'hermes')) {
    return installSystemThreatFeedCron(options, adapters.runCommand);
  }

  if (backend === 'hermes' || (backend === 'auto' && options.agentHost === 'hermes')) {
    return installHermesNativeThreatFeedCron(options, adapters.runCommand);
  }

  if (backend === 'openclaw' || (backend === 'auto' && options.agentHost === 'openclaw')) {
    let nativeError: Error | null = null;
    try {
      const result = await installOpenClawNativeThreatFeedCron(options, adapters.runCommand);
      result.backend = 'openclaw';
      return result;
    } catch (err) {
      nativeError = err as Error;
      if (!(nativeError instanceof CronBackendUnavailableError)) {
        throw nativeError;
      }
    }

    try {
      const result = await installOpenClawThreatFeedCron(options, adapters.gateway);
      result.backend = 'openclaw-gateway';
      return result;
    } catch (gatewayError) {
      throw new Error(
        `Could not install OpenClaw cron. Native openclaw command failed: ${nativeError.message}. ` +
        `Gateway fallback failed: ${(gatewayError as Error).message}`
      );
    }
  }

  if (backend === 'qclaw' || (backend === 'auto' && options.agentHost === 'qclaw')) {
    const result = await installOpenClawThreatFeedCron(
      options,
      qclawGatewayOptions(adapters.gateway)
    );
    result.backend = 'qclaw-gateway';
    return result;
  }

  throw new Error('Invalid cron target. Use auto, openclaw, qclaw, hermes, or system.');
}

export async function installOpenClawThreatFeedCron(
  options: {
    name: string;
    cronExpression: string;
    quiet: boolean;
    force: boolean;
    timezone?: string;
  },
  gateway: OpenClawGatewayOptions = {}
): Promise<OpenClawCronInstallResult> {
  const schedule = validateCronExpression(options.cronExpression);
  const timezone = options.timezone ?? localTimeZone();
  const command = threatFeedCommand(options.quiet, { notifyRun: true });
  const existing = await findOpenClawCronJobsByName(options.name, gateway);
  if (existing.length > 0 && !options.force) {
    return {
      name: options.name,
      schedule,
      timezone,
      created: false,
      backend: 'openclaw-gateway',
      command,
    };
  }

  const description = `AgentGuard Cloud threat feed subscription (${schedule})`;
  const message = openClawCronMessage(options.quiet);

  if (existing.length > 0) {
    await removeOpenClawCronJobs(existing, gateway);
  }
  await openClawGatewayRequest(
    'cron.add',
    {
      name: options.name,
      description,
      enabled: true,
      schedule: {
        kind: 'cron',
        expr: schedule,
        tz: timezone,
      },
      sessionTarget: 'isolated',
      payload: {
        kind: 'agentTurn',
        message,
        timeoutSeconds: 300,
      },
      delivery: {
        mode: 'announce',
        channel: 'last',
      },
    },
    gateway
  );

  return {
    name: options.name,
    schedule,
    timezone,
    created: true,
    backend: 'openclaw-gateway',
    command,
  };
}

async function findOpenClawCronJobsByName(
  name: string,
  gateway: OpenClawGatewayOptions
): Promise<OpenClawCronJob[]> {
  const listed = await openClawGatewayRequest('cron.list', {}, gateway);
  return extractOpenClawCronJobs(listed).filter((job) => job.name === name);
}

async function installOpenClawNativeThreatFeedCron(
  options: {
    name: string;
    cronExpression: string;
    quiet: boolean;
    force: boolean;
    timezone?: string;
  },
  runCommand: CommandRunner = execCommand
): Promise<OpenClawCronInstallResult> {
  const schedule = validateCronExpression(options.cronExpression);
  const timezone = options.timezone ?? localTimeZone();
  const command = threatFeedCommand(options.quiet, { notifyRun: true });
  const message = openClawCronMessage(options.quiet);
  let existing: CommandResult;
  try {
    existing = await runCommand('openclaw', ['cron', 'list']);
  } catch (err) {
    throw new CronBackendUnavailableError(`Could not list native OpenClaw cron jobs. Is OpenClaw installed and available on PATH? ${(err as Error).message}`);
  }
  if (nativeCronListHasExactName(existing.stdout, options.name) && !options.force) {
    return {
      name: options.name,
      schedule,
      timezone,
      created: false,
      backend: 'openclaw',
      command,
    };
  }

  const args = [
    'cron',
    'add',
    '--name',
    options.name,
    '--description',
    `AgentGuard Cloud threat feed subscription (${schedule})`,
    '--cron',
    schedule,
    '--tz',
    timezone,
    '--session',
    'isolated',
    '--message',
    message,
    '--timeout-seconds',
    '300',
    '--announce',
    '--channel',
    'last',
    '--thinking',
    'off',
  ];
  if (options.force) args.push('--force');
  await runCommand('openclaw', args);
  return {
    name: options.name,
    schedule,
    timezone,
    created: true,
    backend: 'openclaw',
    command,
  };
}

class CronBackendUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CronBackendUnavailableError';
  }
}

function nativeCronListHasExactName(stdout: string, name: string): boolean {
  const jsonJobs = extractOpenClawCronJobs(parseJsonOrNull(stdout));
  if (jsonJobs.some((job) => job.name === name)) return true;

  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .some((line) => nativeCronListLineHasExactName(line, name));
}

function nativeCronListLineHasExactName(line: string, name: string): boolean {
  const quoted = line.match(/(["'])(.*?)\1/);
  if (quoted?.[2] === name) return true;

  const cells = line.split(/\s{2,}|\t+/).map((cell) => cell.trim()).filter(Boolean);
  return cells.includes(name);
}

function parseJsonOrNull(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

async function installHermesNativeThreatFeedCron(
  options: {
    name: string;
    cronExpression: string;
    quiet: boolean;
    force: boolean;
    agentGuardHome?: string;
    hermesHome?: string;
    timezone?: string;
  },
  runCommand: CommandRunner = execCommand
): Promise<OpenClawCronInstallResult> {
  const schedule = validateCronExpression(options.cronExpression);
  const timezone = options.timezone ?? localTimeZone();
  const command = threatFeedCommand(options.quiet);
  let existing: CommandResult;
  try {
    existing = await runCommand('hermes', ['cron', 'list']);
  } catch (err) {
    throw new Error(`Could not list Hermes cron jobs. Is Hermes installed and available on PATH? ${(err as Error).message}`);
  }
  if (existing.stdout.includes(options.name) && !options.force) {
    return {
      name: options.name,
      schedule,
      timezone,
      created: false,
      backend: 'hermes',
      command,
    };
  }

  if (existing.stdout.includes(options.name) && options.force) {
    await runCommand('hermes', ['cron', 'remove', options.name]);
  }

  const script = await writeHermesThreatFeedScript(options);
  await runCommand('hermes', [
    'cron',
    'create',
    schedule,
    '--name',
    options.name,
    '--deliver',
    'local',
    '--script',
    script,
    '--no-agent',
  ]);

  return {
    name: options.name,
    schedule,
    timezone,
    created: true,
    backend: 'hermes',
    command,
    script,
  };
}

async function installSystemThreatFeedCron(
  options: {
    name: string;
    cronExpression: string;
    quiet: boolean;
    force: boolean;
    agentGuardHome?: string;
    timezone?: string;
  },
  runCommand: CommandRunner = execCommand
): Promise<OpenClawCronInstallResult> {
  const schedule = validateCronExpression(options.cronExpression);
  const timezone = options.timezone ?? localTimeZone();
  const command = threatFeedCommand(options.quiet);
  const home = validateCronFilesystemPath(options.agentGuardHome ?? join(homedir(), '.agentguard'), 'AGENTGUARD_HOME');
  const jobId = sanitizeCronJobId(options.name);
  const begin = `# AgentGuard begin ${jobId}`;
  const end = `# AgentGuard end ${jobId}`;
  const script = await writeSystemThreatFeedScript({
    name: options.name,
    quiet: options.quiet,
    agentGuardHome: home,
  });
  const logPath = validateCronFilesystemPath(join(home, 'feed-cron.log'), 'system cron log path');
  const line = `${schedule} ${shellQuote(script)} >> ${shellQuote(logPath)} 2>&1`;
  const existing = await runCommand('crontab', ['-l']).then((result) => result.stdout, () => '');
  const hasExisting = existing.includes(begin);
  if (hasExisting && !options.force) {
    return {
      name: options.name,
      schedule,
      timezone,
      created: false,
      backend: 'system',
      command,
      script,
    };
  }

  const withoutExisting = removeAgentGuardCronBlock(existing, jobId).trimEnd();
  const next = `${withoutExisting}${withoutExisting ? '\n' : ''}${begin}\n${line}\n${end}\n`;
  await runCommand('crontab', ['-'], next);
  return {
    name: options.name,
    schedule,
    timezone,
    created: true,
    backend: 'system',
    command,
    script,
  };
}

function threatFeedCommand(quiet: boolean, options: { notifyRun?: boolean } = {}): string {
  const modeFlag = options.notifyRun ? '--cron-notify-run' : '--json --cron-run';
  return `agentguard subscribe${quiet ? ' --quiet' : ''} ${modeFlag}`;
}

function qclawGatewayOptions(gateway: OpenClawGatewayOptions = {}): OpenClawGatewayOptions {
  return {
    ...gateway,
    port: gateway.port ?? 28789,
    label: gateway.label ?? 'QClaw Gateway',
  };
}

async function writeHermesThreatFeedScript(options: {
  name: string;
  quiet: boolean;
  agentGuardHome?: string;
  hermesHome?: string;
}): Promise<string> {
  const hermesHome = (options.hermesHome ?? process.env.HERMES_HOME?.trim()) || join(homedir(), '.hermes');
  const scriptsDir = join(hermesHome, 'scripts');
  await mkdir(scriptsDir, { recursive: true });
  const scriptName = `${sanitizeHermesScriptName(options.name)}.sh`;
  const scriptPath = join(scriptsDir, scriptName);
  const lines = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    `export AGENTGUARD_HOME=${shellQuote(options.agentGuardHome ?? join(homedir(), '.agentguard'))}`,
    process.env.PATH ? `export PATH=${shellQuote(process.env.PATH)}` : '',
    `exec ${threatFeedCommand(options.quiet)}`,
    '',
  ].filter(Boolean);
  await writeFile(scriptPath, lines.join('\n'), { mode: 0o700 });
  await chmod(scriptPath, 0o700).catch(() => undefined);
  return scriptName;
}

async function writeSystemThreatFeedScript(options: {
  name: string;
  quiet: boolean;
  agentGuardHome: string;
}): Promise<string> {
  const scriptsDir = join(options.agentGuardHome, 'scripts');
  await mkdir(scriptsDir, { recursive: true });
  const scriptPath = validateCronFilesystemPath(join(scriptsDir, `${sanitizeCronJobId(options.name)}.sh`), 'system cron script path');
  const lines = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    `export AGENTGUARD_HOME=${shellQuote(options.agentGuardHome)}`,
    process.env.PATH ? `export PATH=${shellQuote(process.env.PATH)}` : '',
    `exec ${threatFeedCommand(options.quiet)}`,
    '',
  ].filter(Boolean);
  await writeFile(scriptPath, lines.join('\n'), { mode: 0o700 });
  await chmod(scriptPath, 0o700).catch(() => undefined);
  return scriptPath;
}

function validateCronFilesystemPath(value: string, label: string): string {
  if (!isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path for system cron installation.`);
  }
  if (/[\0\r\n'"]/.test(value)) {
    throw new Error(`${label} must not contain quotes or newlines for system cron installation.`);
  }
  return value;
}

function sanitizeCronJobId(value: string): string {
  const normalized = value.trim().replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized || 'agentguard-threat-feed';
}

function sanitizeHermesScriptName(value: string): string {
  const normalized = value.trim().replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized ? `agentguard-${normalized}` : 'agentguard-threat-feed';
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function openClawCronMessage(quiet: boolean): string {
  const mode = quiet ? 'quiet' : 'manual';
  const command = threatFeedCommand(quiet, { notifyRun: true });
  if (!quiet) {
    return [
      `Mode: ${mode}.`,
      `Command: \`${command}\`.`,
      `Run exactly the command above.`,
      '',
      'Rules:',
      '- If the command fails, prints no stdout, or prints only `NO_REPLY`, output `NO_REPLY`.',
      '- If the command prints threat-feed advisories, read the full output, including any remediation guidance.',
      '- Respond in the same language as the user would naturally use for this chat.',
      '- Summarize the new threat(s), identify the likely local impact, and give concise manual response steps.',
      '- Preserve advisory IDs and severity labels.',
      '- Do not claim a local match was found unless the command output explicitly says so.',
      '',
      'Follow these rules exactly.',
    ].join('\n');
  }
  return [
    `Mode: ${mode}.`,
    `Command: \`${command}\`.`,
    `Run exactly the command above.`,
    '',
    'Rules:',
    '- The command prints either the exact notification body or `NO_REPLY`.',
    '- Output the command stdout exactly as your final response.',
    '- Do not summarize, transform, add labels, or send a separate message.',
    '- If the command fails or prints no stdout, output `NO_REPLY`.',
    '',
    'Follow these rules exactly.',
  ].join('\n');
}

function removeAgentGuardCronBlock(value: string, name: string): string {
  const begin = `# AgentGuard begin ${name}`;
  const end = `# AgentGuard end ${name}`;
  const lines = value.split(/\r?\n/);
  const kept: string[] = [];
  let skipping = false;
  for (const line of lines) {
    if (line.trim() === begin) {
      skipping = true;
      continue;
    }
    if (line.trim() === end) {
      skipping = false;
      continue;
    }
    if (!skipping) kept.push(line);
  }
  return kept.join('\n');
}

function execCommand(command: string, args: string[], input?: string): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      fn();
    };
    const timeout = setTimeout(() => {
      child.kill('SIGTERM');
      finish(() => reject(new Error(`${command} ${args.join(' ')} timed out after 10000ms`)));
    }, 10000);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on('error', (err) => {
      finish(() => reject(err));
    });
    child.on('close', (code) => {
      if (code === 0) {
        finish(() => resolve({ stdout, stderr }));
        return;
      }
      finish(() => reject(new Error(`${command} ${args.join(' ')} failed with exit code ${code}: ${stderr || stdout}`.trim())));
    });
    if (input) child.stdin.write(input);
    child.stdin.end();
  });
}

async function removeOpenClawCronJobs(
  jobs: OpenClawCronJob[],
  gateway: OpenClawGatewayOptions
): Promise<void> {
  for (const job of jobs) {
    if (!job.id) continue;
    await openClawGatewayRequest('cron.remove', { jobId: job.id }, gateway);
  }
}

export function extractOpenClawCronJobs(value: unknown): OpenClawCronJob[] {
  if (Array.isArray(value)) return value as OpenClawCronJob[];
  if (!value || typeof value !== 'object') return [];
  const obj = value as {
    jobs?: unknown;
    cronJobs?: unknown;
    result?: unknown;
    data?: unknown;
  };
  for (const candidate of [obj.jobs, obj.cronJobs, obj.result, obj.data]) {
    const jobs = extractOpenClawCronJobs(candidate);
    if (jobs.length > 0) return jobs;
  }
  return [];
}

export function openClawGatewayRequest(
  method: string,
  params: unknown,
  options: OpenClawGatewayOptions = {}
): Promise<unknown> {
  if (options.request) {
    return options.request(method, params);
  }

  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 18789;
  const label = options.label ?? 'OpenClaw Gateway';
  const timeoutMs = options.timeoutMs ?? 5000;
  if (options.url) {
    return openClawGatewayWebSocketRequest({ url: options.url, method, params, label, timeoutMs });
  }

  return openClawGatewayHttpRequest({ host, port, method, params, label, timeoutMs }).catch((err) => {
    if (err instanceof GatewayHttpFallbackError) {
      return openClawGatewayWebSocketRequest({ url: `ws://${host}:${port}`, method, params, label, timeoutMs });
    }
    throw err;
  });
}

function openClawGatewayHttpRequest(options: {
  host: string;
  port: number;
  method: string;
  params: unknown;
  label: string;
  timeoutMs: number;
}): Promise<unknown> {
  const payload = JSON.stringify({
    jsonrpc: '2.0',
    method: options.method,
    params: legacyGatewayParams(options.method, options.params),
    id: 1,
  });

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const succeed = (value: unknown) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const req = http.request(
      {
        hostname: options.host,
        port: options.port,
        path: '/',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('error', (err) => {
          fail(new Error(`${options.label} ${options.method} response failed: ${err.message}`));
        });
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          let parsed: any;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            fail(new GatewayHttpFallbackError(`${options.label} returned non-JSON response: ${data}`));
            return;
          }
          if (res.statusCode && res.statusCode >= 400) {
            fail(new GatewayHttpFallbackError(`${options.label} ${options.method} failed with HTTP ${res.statusCode}`));
            return;
          }
          if (parsed?.error) {
            fail(new Error(`${options.label} ${options.method} failed: ${parsed.error.message ?? JSON.stringify(parsed.error)}`));
            return;
          }
          succeed(parsed?.result ?? parsed);
        });
      }
    );
    req.on('error', (err) => {
      fail(new GatewayHttpFallbackError(`Could not reach ${options.label} at ${options.host}:${options.port}: ${err.message}`));
    });
    req.setTimeout(options.timeoutMs, () => {
      const err = new GatewayHttpFallbackError(`${options.label} ${options.method} request timed out after ${options.timeoutMs}ms`);
      fail(err);
      req.destroy(err);
    });
    req.write(payload);
    req.end();
  });
}

function legacyGatewayParams(method: string, params: unknown): unknown {
  if (method === 'cron.add' && !Array.isArray(params)) return [params];
  return params;
}

function openClawGatewayWebSocketRequest(options: {
  url: string;
  method: string;
  params: unknown;
  label: string;
  timeoutMs: number;
}): Promise<unknown> {
  const endpoint = parseGatewayWebSocketUrl(options.url, options.label);

  return new Promise((resolve, reject) => {
    const connectRequestId = randomUUID();
    const methodRequestId = randomUUID();
    const websocketKey = randomBytes(16).toString('base64');
    let handshakeComplete = false;
    let connected = false;
    let settled = false;
    let buffer = Buffer.alloc(0);
    let fragmentedText: Buffer[] | null = null;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.destroy();
      reject(err);
    };
    const succeed = (value: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      socket.end();
      resolve(value);
    };

    const socket = net.createConnection({ host: endpoint.hostname, port: endpoint.port }, () => {
      socket.write(buildWebSocketHandshake(endpoint, websocketKey));
    });

    const timeout = setTimeout(() => {
      fail(new Error(`${options.label} ${options.method} request timed out after ${options.timeoutMs}ms`));
    }, options.timeoutMs);

    socket.on('error', (err) => {
      fail(new Error(`Could not reach ${options.label} at ${endpoint.hostname}:${endpoint.port}: ${err.message}`));
    });
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!handshakeComplete) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;
        const header = buffer.subarray(0, headerEnd + 4).toString('utf8');
        buffer = buffer.subarray(headerEnd + 4);
        try {
          validateWebSocketHandshake(header, websocketKey, options.label);
        } catch (err) {
          fail(err as Error);
          return;
        }
        handshakeComplete = true;
      }

      while (true) {
        let parsed: ReturnType<typeof readWebSocketFrame>;
        try {
          parsed = readWebSocketFrame(buffer);
        } catch (err) {
          fail(err as Error);
          return;
        }
        if (!parsed) break;
        buffer = parsed.rest;
        if (parsed.opcode === 0x8) {
          fail(new Error(`${options.label} closed the WebSocket before ${options.method} completed`));
          return;
        }
        if (parsed.opcode === 0x9) {
          socket.write(encodeWebSocketFrame(parsed.payload.toString('utf8'), 0xA));
          continue;
        }
        if (parsed.opcode === 0xA) continue;
        if (parsed.opcode === 0x1) {
          if (fragmentedText) {
            fail(new Error(`${options.label} started a new WebSocket text message before completing the previous one`));
            return;
          }
          if (parsed.fin) {
            handleGatewayFrame(parsed.payload.toString('utf8'));
          } else {
            fragmentedText = [parsed.payload];
          }
          continue;
        }
        if (parsed.opcode === 0x0) {
          if (!fragmentedText) {
            fail(new Error(`${options.label} returned an unexpected WebSocket continuation frame`));
            return;
          }
          fragmentedText.push(parsed.payload);
          if (parsed.fin) {
            const complete = Buffer.concat(fragmentedText);
            fragmentedText = null;
            handleGatewayFrame(complete.toString('utf8'));
          }
        }
      }
    });

    function handleGatewayFrame(raw: string): void {
      let frame: any;
      try {
        frame = JSON.parse(raw);
      } catch {
        fail(new Error(`${options.label} returned non-JSON WebSocket frame: ${raw}`));
        return;
      }
      if (frame?.type === 'event' && frame.event === 'connect.challenge') {
        socket.write(encodeWebSocketFrame(JSON.stringify({
          type: 'req',
          id: connectRequestId,
          method: 'connect',
          params: openClawConnectParams(),
        })));
        return;
      }
      if (frame?.type !== 'res') return;
      if (frame.id === connectRequestId) {
        if (!frame.ok) {
          fail(new Error(`${options.label} connect failed: ${gatewayFrameErrorMessage(frame)}`));
          return;
        }
        connected = true;
        socket.write(encodeWebSocketFrame(JSON.stringify({
          type: 'req',
          id: methodRequestId,
          method: options.method,
          params: options.params,
        })));
        return;
      }
      if (connected && frame.id === methodRequestId) {
        if (!frame.ok) {
          fail(new Error(`${options.label} ${options.method} failed: ${gatewayFrameErrorMessage(frame)}`));
          return;
        }
        succeed(frame.payload);
      }
    }
  });
}

function parseGatewayWebSocketUrl(raw: string, label: string): { hostname: string; port: number; path: string; hostHeader: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`${label} URL is invalid: ${raw}`);
  }
  if (parsed.protocol !== 'ws:') {
    throw new Error(`${label} URL must use ws:// for Gateway WebSocket RPC.`);
  }
  const port = parsed.port ? Number(parsed.port) : 80;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`${label} URL has an invalid port: ${raw}`);
  }
  const path = `${parsed.pathname || '/'}${parsed.search}`;
  const hostname = parsed.hostname;
  const hostHeader = parsed.port ? parsed.host : `${parsed.hostname}:${port}`;
  return { hostname, port, path, hostHeader };
}

function buildWebSocketHandshake(endpoint: { path: string; hostHeader: string }, key: string): string {
  return [
    `GET ${endpoint.path || '/'} HTTP/1.1`,
    `Host: ${endpoint.hostHeader}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    'Sec-WebSocket-Version: 13',
    '',
    '',
  ].join('\r\n');
}

function validateWebSocketHandshake(header: string, key: string, label: string): void {
  const [statusLine, ...lines] = header.split(/\r\n/);
  if (!/^HTTP\/1\.[01] 101\b/.test(statusLine ?? '')) {
    throw new Error(`${label} WebSocket upgrade failed: ${statusLine || 'empty response'}`);
  }
  const headers = new Map<string, string>();
  for (const line of lines) {
    const index = line.indexOf(':');
    if (index === -1) continue;
    headers.set(line.slice(0, index).trim().toLowerCase(), line.slice(index + 1).trim());
  }
  const expected = createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
  if (headers.get('sec-websocket-accept') !== expected) {
    throw new Error(`${label} WebSocket upgrade returned an invalid accept key.`);
  }
}

function readWebSocketFrame(buffer: Buffer): { fin: boolean; opcode: number; payload: Buffer; rest: Buffer } | null {
  if (buffer.length < 2) return null;
  const first = buffer[0]!;
  const second = buffer[1]!;
  const fin = (first & 0x80) !== 0;
  const opcode = first & 0x0f;
  const masked = (second & 0x80) !== 0;
  if (masked) {
    throw new Error('WebSocket server frames must not be masked.');
  }
  if (opcode >= 0x8 && !fin) {
    throw new Error('WebSocket control frames must not be fragmented.');
  }
  let length = second & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < offset + 2) return null;
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buffer.length < offset + 8) return null;
    const longLength = buffer.readBigUInt64BE(offset);
    if (longLength > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('WebSocket frame is too large.');
    }
    length = Number(longLength);
    offset += 8;
  }
  if (opcode >= 0x8 && length > 125) {
    throw new Error('WebSocket control frames must not exceed 125 bytes.');
  }
  const mask = masked ? buffer.subarray(offset, offset + 4) : null;
  if (masked) offset += 4;
  if (buffer.length < offset + length) return null;
  const payload = Buffer.from(buffer.subarray(offset, offset + length));
  if (mask) {
    for (let i = 0; i < payload.length; i += 1) {
      payload[i] = payload[i]! ^ mask[i % 4]!;
    }
  }
  return { fin, opcode, payload, rest: buffer.subarray(offset + length) };
}

function encodeWebSocketFrame(text: string, opcode = 0x1): Buffer {
  const payload = Buffer.from(text, 'utf8');
  const mask = randomBytes(4);
  const headerLength = payload.length < 126 ? 2 : payload.length <= 0xffff ? 4 : 10;
  const header = Buffer.alloc(headerLength);
  header[0] = 0x80 | opcode;
  if (payload.length < 126) {
    header[1] = 0x80 | payload.length;
  } else if (payload.length <= 0xffff) {
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  const masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i += 1) {
    masked[i] = masked[i]! ^ mask[i % 4]!;
  }
  return Buffer.concat([header, mask, masked]);
}

function openClawConnectParams(): unknown {
  return {
    minProtocol: 3,
    maxProtocol: 3,
    client: {
      id: 'cli',
      version: 'agentguard',
      platform: process.platform,
      mode: 'cli',
    },
    caps: [],
    role: 'operator',
    scopes: [
      'operator.admin',
      'operator.read',
      'operator.write',
      'operator.approvals',
      'operator.pairing',
      'operator.talk.secrets',
    ],
  };
}

function gatewayFrameErrorMessage(frame: any): string {
  return frame?.error?.message ?? JSON.stringify(frame?.error ?? frame);
}
