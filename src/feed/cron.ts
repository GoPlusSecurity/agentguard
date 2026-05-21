import http from 'node:http';
import { spawn } from 'node:child_process';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

export type CronBackend = 'auto' | 'openclaw' | 'hermes' | 'system';
export type ResolvedCronBackend = 'openclaw' | 'openclaw-gateway' | 'hermes' | 'system';
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
      'Cron target auto requires a saved agent host. Run `agentguard init --agent <claude-code|codex|openclaw|hermes|qclaw>` first, or pass `--cron-target openclaw`, `--cron-target hermes`, or `--cron-target system`.'
    );
  }
  if (backend === 'system' || (backend === 'auto' && options.agentHost !== 'openclaw' && options.agentHost !== 'hermes')) {
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

  throw new Error('Invalid cron target. Use auto, openclaw, hermes, or system.');
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
  const command = threatFeedCommand(options.quiet);
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

  const mode = options.quiet ? 'quiet' : 'manual';
  const description = `AgentGuard Cloud threat feed subscription (${schedule})`;
  const message = openClawCronMessage(options.quiet);

  if (existing.length > 0) {
    await removeOpenClawCronJobs(existing, gateway);
  }
  await openClawGatewayRequest(
    'cron.add',
    [
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
          agentguard: {
            mode,
            command,
          },
        },
        delivery: {
          mode: 'none',
        },
      },
    ],
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
  const command = threatFeedCommand(options.quiet);
  const message = openClawCronMessage(options.quiet);
  const existing = await runCommand('openclaw', ['cron', 'list']).catch(() => null);
  if (existing && existing.stdout.includes(options.name) && !options.force) {
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
  const home = options.agentGuardHome ?? join(homedir(), '.agentguard');
  const begin = `# AgentGuard begin ${options.name}`;
  const end = `# AgentGuard end ${options.name}`;
  const pathPrefix = process.env.PATH ? `PATH="${process.env.PATH}" ` : '';
  const line = `${schedule} ${pathPrefix}AGENTGUARD_HOME="${home}" ${command} >> "${join(home, 'feed-cron.log')}" 2>&1`;
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
    };
  }

  const withoutExisting = removeAgentGuardCronBlock(existing, options.name).trimEnd();
  const next = `${withoutExisting}${withoutExisting ? '\n' : ''}${begin}\n${line}\n${end}\n`;
  await runCommand('crontab', ['-'], next);
  return {
    name: options.name,
    schedule,
    timezone,
    created: true,
    backend: 'system',
    command,
  };
}

function threatFeedCommand(quiet: boolean): string {
  return `agentguard subscribe${quiet ? ' --quiet' : ''} --json --cron-run`;
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

function sanitizeHermesScriptName(value: string): string {
  const normalized = value.trim().replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return normalized ? `agentguard-${normalized}` : 'agentguard-threat-feed';
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function openClawCronMessage(quiet: boolean): string {
  const mode = quiet ? 'quiet' : 'manual';
  const command = threatFeedCommand(quiet);
  return [
    `Mode: ${mode}.`,
    `Command: \`${command}\`.`,
    `Run exactly the command above.`,
    '',
    'Rules:',
    '- If the JSON field `hardFailures` is greater than 0, output a short error summary and do not send a notification.',
    '- If the JSON field `shouldNotify` is true, send `notification.body` exactly as-is using the current session notification context.',
    '- If `shouldNotify` is false, output "skipped" and finish without sending any message.',
    '- If the command fails or the JSON cannot be parsed, output a short error summary and do not send a notification.',
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

  const payload = JSON.stringify({
    jsonrpc: '2.0',
    method,
    params,
    id: 1,
  });
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 18789;
  const timeoutMs = options.timeoutMs ?? 5000;

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
        hostname: host,
        port,
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
          fail(new Error(`OpenClaw Gateway ${method} response failed: ${err.message}`));
        });
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          let parsed: any;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            fail(new Error(`OpenClaw Gateway returned non-JSON response: ${data}`));
            return;
          }
          if (parsed?.error) {
            fail(new Error(`OpenClaw Gateway ${method} failed: ${parsed.error.message ?? JSON.stringify(parsed.error)}`));
            return;
          }
          if (res.statusCode && res.statusCode >= 400) {
            fail(new Error(`OpenClaw Gateway ${method} failed with HTTP ${res.statusCode}`));
            return;
          }
          succeed(parsed?.result ?? parsed);
        });
      }
    );
    req.on('error', (err) => {
      fail(new Error(`Could not reach OpenClaw Gateway at ${host}:${port}: ${err.message}`));
    });
    req.setTimeout(timeoutMs, () => {
      const err = new Error(`OpenClaw Gateway ${method} request timed out after ${timeoutMs}ms`);
      fail(err);
      req.destroy(err);
    });
    req.write(payload);
    req.end();
  });
}
