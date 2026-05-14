import http from 'node:http';

export interface OpenClawCronInstallResult {
  name: string;
  schedule: string;
  created: boolean;
}

export interface OpenClawGatewayOptions {
  host?: string;
  port?: number;
  timeoutMs?: number;
  request?: (method: string, params: unknown) => Promise<unknown>;
}

interface OpenClawCronJob {
  id?: string;
  name?: string;
}

export function parseIntervalMinutes(value: string): number {
  if (!/^\d+$/.test(value)) {
    throw new Error('Invalid --interval-minutes. Use an integer between 1 and 59.');
  }
  const minutes = Number.parseInt(value, 10);
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 59) {
    throw new Error('Invalid --interval-minutes. Use an integer between 1 and 59.');
  }
  return minutes;
}

export async function installOpenClawThreatFeedCron(
  options: {
    name: string;
    intervalMinutes: number;
    force: boolean;
  },
  gateway: OpenClawGatewayOptions = {}
): Promise<OpenClawCronInstallResult> {
  const schedule = `*/${options.intervalMinutes} * * * *`;
  const existing = await findOpenClawCronJobsByName(options.name, gateway);
  if (existing.length > 0 && !options.force) {
    return {
      name: options.name,
      schedule,
      created: false,
    };
  }

  const description = `AgentGuard Cloud threat feed self-check every ${options.intervalMinutes} minute${options.intervalMinutes === 1 ? '' : 's'}`;
  const message = [
    'Run `agentguard subscribe --json --cron-run`.',
    '',
    'Rules:',
    '- If the JSON field `hardFailures` is greater than 0, output a short error summary and do not send a threat-match notification.',
    '- If the JSON field `shouldNotify` is true, send `notification.body` exactly as-is using the current session notification context.',
    '- If `shouldNotify` is false, output "skipped" and finish without sending any message.',
    '- If the command fails or the JSON cannot be parsed, output a short error summary and do not send a threat-match notification.',
    '',
    'Follow these rules exactly.',
  ].join('\n');

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
          kind: 'every',
          everyMs: options.intervalMinutes * 60 * 1000,
        },
        sessionTarget: 'isolated',
        payload: {
          kind: 'agentTurn',
          message,
          timeoutSeconds: 300,
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
    created: true,
  };
}

async function findOpenClawCronJobsByName(
  name: string,
  gateway: OpenClawGatewayOptions
): Promise<OpenClawCronJob[]> {
  const listed = await openClawGatewayRequest('cron.list', {}, gateway).catch(() => null);
  return extractOpenClawCronJobs(listed).filter((job) => job.name === name);
}

async function removeOpenClawCronJobs(
  jobs: OpenClawCronJob[],
  gateway: OpenClawGatewayOptions
): Promise<void> {
  for (const job of jobs) {
    if (!job.id) continue;
    await openClawGatewayRequest('cron.remove', { jobId: job.id }, gateway).catch(() => null);
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
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          let parsed: any;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            reject(new Error(`OpenClaw Gateway returned non-JSON response: ${data}`));
            return;
          }
          if (parsed?.error) {
            reject(new Error(`OpenClaw Gateway ${method} failed: ${parsed.error.message ?? JSON.stringify(parsed.error)}`));
            return;
          }
          if (res.statusCode && res.statusCode >= 400) {
            reject(new Error(`OpenClaw Gateway ${method} failed with HTTP ${res.statusCode}`));
            return;
          }
          resolve(parsed?.result ?? parsed);
        });
      }
    );
    req.on('error', (err) => {
      reject(new Error(`Could not reach OpenClaw Gateway at ${host}:${port}: ${err.message}`));
    });
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`OpenClaw Gateway ${method} request timed out after ${timeoutMs}ms`));
    });
    req.write(payload);
    req.end();
  });
}
