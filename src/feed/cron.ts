import http from 'node:http';

export interface OpenClawCronInstallResult {
  name: string;
  schedule: string;
  timezone: string;
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
  const existing = await findOpenClawCronJobsByName(options.name, gateway);
  if (existing.length > 0 && !options.force) {
    return {
      name: options.name,
      schedule,
      timezone,
      created: false,
    };
  }

  const mode = options.quiet ? 'quiet' : 'manual';
  const command = `agentguard subscribe${options.quiet ? ' --quiet' : ''} --json --cron-run`;
  const description = `AgentGuard Cloud threat feed subscription (${schedule})`;
  const message = [
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
