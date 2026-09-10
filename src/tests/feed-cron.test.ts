import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, utimesSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as cronModule from '../feed/cron.js';
import {
  installThreatFeedCron,
  installOpenClawThreatFeedCron,
  inspectThreatFeedCron,
  inspectWindowsThreatFeedTask,
  inspectSystemThreatFeedCron,
  removeThreatFeedCron,
  openClawGatewayRequest,
  validateCronExpression,
  type CommandRunner,
} from '../feed/cron.js';

type RpcCall = { method: string; params: any };

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

async function closeServer(server: http.Server | net.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function serverPort(server: http.Server | net.Server): number {
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return address.port;
}

function encodeServerWebSocketFrame(text: string, opcode = 0x1, fin = true): Buffer {
  const payload = Buffer.from(text, 'utf8');
  const headerLength = payload.length < 126 ? 2 : payload.length <= 0xffff ? 4 : 10;
  const header = Buffer.alloc(headerLength);
  header[0] = (fin ? 0x80 : 0) | opcode;
  if (payload.length < 126) {
    header[1] = payload.length;
  } else if (payload.length <= 0xffff) {
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  return Buffer.concat([header, payload]);
}

function readClientWebSocketFrame(buffer: Buffer): { payload: string; rest: Buffer } | null {
  if (buffer.length < 2) return null;
  let length = buffer[1]! & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buffer.length < offset + 2) return null;
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buffer.length < offset + 8) return null;
    length = Number(buffer.readBigUInt64BE(offset));
    offset += 8;
  }
  if (buffer.length < offset + 4 + length) return null;
  const mask = buffer.subarray(offset, offset + 4);
  offset += 4;
  const payload = Buffer.from(buffer.subarray(offset, offset + length));
  for (let i = 0; i < payload.length; i += 1) {
    payload[i] = payload[i]! ^ mask[i % 4]!;
  }
  return { payload: payload.toString('utf8'), rest: buffer.subarray(offset + length) };
}

function fakeGateway(jobs: Array<{ id: string; name: string }> = []): {
  calls: RpcCall[];
  request: (method: string, params: unknown) => Promise<unknown>;
} {
  const calls: RpcCall[] = [];
  return {
    calls,
    async request(method, params) {
      calls.push({ method, params });
      if (method === 'cron.list') return { jobs };
      return { ok: true };
    },
  };
}

function managedWindowsTaskXml(configPath: string, enabled = true): string {
  const config = JSON.parse(readFileSync(configPath, 'utf8')) as {
    nodeExecutable: string;
    cliEntrypoint: string;
  };
  return [
    '<Task>',
    '<Principals><Principal><UserId>S-1-5-21-100-200-300-1001</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>',
    `<Settings><Enabled>${enabled}</Enabled></Settings>`,
    `<Actions><Exec><Command>${config.nodeExecutable.replaceAll('&', '&amp;')}</Command><Arguments>&quot;${config.cliEntrypoint.replaceAll('&', '&amp;')}&quot; windows-cron-run --config &quot;${configPath.replaceAll('&', '&amp;')}&quot;</Arguments></Exec></Actions>`,
    '</Task>',
  ].join('');
}

function base64UrlEncode(value: Buffer): string {
  return value.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
}

function base64UrlDecode(value: string): Buffer {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, 'base64');
}

function publicKeyRawBase64UrlFromPem(publicKeyPem: string): string {
  const publicKey = createPublicKey(publicKeyPem);
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const raw = spki.length === ED25519_SPKI_PREFIX.length + 32 &&
    spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
    ? spki.subarray(ED25519_SPKI_PREFIX.length)
    : spki;
  return base64UrlEncode(raw);
}

function writeOpenClawIdentity(stateDir: string): { deviceId: string; publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const deviceId = createHash('sha256')
    .update(base64UrlDecode(publicKeyRawBase64UrlFromPem(publicKeyPem)))
    .digest('hex');
  const identityDir = join(stateDir, 'identity');
  mkdirSync(identityDir, { recursive: true });
  writeFileSync(join(identityDir, 'device.json'), JSON.stringify({
    version: 1,
    deviceId,
    publicKeyPem,
    privateKeyPem,
    createdAtMs: Date.now(),
  }));
  return { deviceId, publicKeyPem, privateKeyPem };
}

describe('feed/cron', () => {
  it('auto-inspects Windows Task Scheduler for a DSH subscription on Windows', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-inspect-auto-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    writeFileSync(join(scriptsDir, 'agentguard-threat-feed.windows-cron.json'), JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '*/20 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\agentguard\\cli.js',
    }));
    const commands: string[] = [];

    const status = await inspectThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'auto', agentHost: 'dsh', agentGuardHome: home },
      {
        platform: 'win32',
        async runCommand(command: string) {
          commands.push(command);
          if (command === 'whoami.exe') {
            return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
          }
          return { stdout: managedWindowsTaskXml(join(scriptsDir, 'agentguard-threat-feed.windows-cron.json')), stderr: '' };
        },
      },
    );

    assert.deepEqual(status, {
      name: 'agentguard-threat-feed',
      installed: true,
      cronExpression: '*/20 * * * *',
      backend: 'windows-task-scheduler',
    });
    assert.deepEqual(commands, ['schtasks.exe', 'whoami.exe']);
  });

  it('matches five-field cron expressions at minute precision in the requested timezone', () => {
    const cronMatchesAt = (cronModule as Record<string, unknown>).cronMatchesAt;
    assert.equal(typeof cronMatchesAt, 'function');
    const matches = cronMatchesAt as (expression: string, timezone: string, at: Date) => boolean;

    assert.equal(matches('*/15 * * * *', 'UTC', new Date('2026-09-07T10:30:45Z')), true);
    assert.equal(matches('*/15 * * * *', 'UTC', new Date('2026-09-07T10:31:00Z')), false);
    assert.equal(matches('0 3 * * *', 'Asia/Shanghai', new Date('2026-09-06T19:00:20Z')), true);
  });

  it('runs a due Windows cron tick once with the configured AgentGuard home', async () => {
    const runWindowsCronTick = (cronModule as Record<string, unknown>).runWindowsCronTick;
    assert.equal(typeof runWindowsCronTick, 'function');
    const runTick = runWindowsCronTick as (
      configPath: string,
      adapters: Record<string, unknown>,
    ) => Promise<{ ran: boolean; reason: string }>;
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-tick-'));
    const configPath = join(home, 'task.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '*/15 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
      cliEntrypoint: 'C:\\AgentGuard\\dist\\cli.js',
    }));
    const calls: Array<{ command: string; args: string[]; env?: NodeJS.ProcessEnv }> = [];
    const adapters = {
      now: () => new Date('2026-09-07T10:30:45Z'),
      runCommand: async (command: string, args: string[], _input?: string, options?: { env?: NodeJS.ProcessEnv }) => {
        calls.push({ command, args, env: options?.env });
        return { stdout: '{"supported":true}\n', stderr: '' };
      },
    };

    const first = await runTick(configPath, adapters);
    const second = await runTick(configPath, adapters);

    assert.deepEqual(first, { ran: true, reason: 'executed' });
    assert.deepEqual(second, { ran: false, reason: 'already-checked' });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.command, 'C:\\Program Files\\nodejs\\node.exe');
    assert.deepEqual(calls[0]?.args, [
      'C:\\AgentGuard\\dist\\cli.js', 'subscribe', '--quiet', '--json', '--cron-run',
    ]);
    assert.equal(calls[0]?.env?.AGENTGUARD_HOME, home);
  });

  it('catches up one missed Windows cron occurrence after a delayed scheduler tick', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-catchup-'));
    const configPath = join(home, 'task.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '15 * * * *',
      timezone: 'UTC',
      quiet: false,
      agentGuardHome: home,
      nodeExecutable: 'node.exe',
      cliEntrypoint: 'cli.js',
    }));
    writeFileSync(`${configPath}.state.json`, JSON.stringify({
      version: 1,
      lastCheckedMinute: '2026-09-07T10:00:00.000Z',
    }));
    let executions = 0;

    const result = await cronModule.runWindowsCronTick(configPath, {
      now: () => new Date('2026-09-07T10:31:20Z'),
      async runCommand() {
        executions += 1;
        return { stdout: '', stderr: '' };
      },
    });

    assert.deepEqual(result, { ran: true, reason: 'executed' });
    assert.equal(executions, 1);
  });

  it('recovers a stale Windows cron runner lock after an interrupted process', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-stale-lock-'));
    const configPath = join(home, 'task.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '* * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'node.exe',
      cliEntrypoint: 'cli.js',
    }));
    const lockPath = `${configPath}.lock`;
    writeFileSync(lockPath, 'interrupted');
    const stale = new Date('2026-09-07T10:00:00Z');
    utimesSync(lockPath, stale, stale);

    const result = await cronModule.runWindowsCronTick(configPath, {
      now: () => new Date('2026-09-07T10:30:00Z'),
      async runCommand() { return { stdout: '', stderr: '' }; },
    });

    assert.deepEqual(result, { ran: true, reason: 'executed' });
    assert.equal(existsSync(lockPath), false);
  });

  it('quarantines malformed Windows cron state instead of disabling future ticks', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-corrupt-state-'));
    const configPath = join(home, 'task.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '* * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'node.exe',
      cliEntrypoint: 'cli.js',
    }));
    writeFileSync(`${configPath}.state.json`, '{truncated');

    const result = await cronModule.runWindowsCronTick(configPath, {
      now: () => new Date('2026-09-07T10:30:00Z'),
      async runCommand() { return { stdout: '', stderr: '' }; },
    });

    assert.deepEqual(result, { ran: true, reason: 'executed' });
    assert.equal(
      readdirSync(home).some((name) => name.startsWith('task.json.state.json.corrupt-')),
      true,
    );
    assert.doesNotThrow(() => JSON.parse(readFileSync(`${configPath}.state.json`, 'utf8')));
  });

  it('validateCronExpression rejects non-five-field values', () => {
    assert.equal(validateCronExpression('0 * * * *'), '0 * * * *');
    assert.equal(validateCronExpression('  */5   * * * *  '), '*/5 * * * *');
    assert.throws(() => validateCronExpression('0 * * *'), /Invalid --cron/);
    assert.throws(() => validateCronExpression('0 * * * * *'), /Invalid --cron/);
  });

  it('preserves command exit codes for locale-independent scheduler errors', async () => {
    const execCommand = (cronModule as Record<string, unknown>).execCommand;
    assert.equal(typeof execCommand, 'function');
    const execute = execCommand as CommandRunner;

    await assert.rejects(
      execute(process.execPath, ['-e', 'process.exit(2)']),
      (error: unknown) => (error as { exitCode?: unknown }).exitCode === 2,
    );
  });

  it('decodes UTF-16LE command output used by native Windows tools', async () => {
    const expected = '<?xml version="1.0" encoding="UTF-16"?><Task>测试</Task>';
    const script = `process.stdout.write(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(${JSON.stringify(expected)}, 'utf16le')]))`;
    const result = await cronModule.execCommand(process.execPath, ['-e', script]);

    assert.equal(result.stdout, expected);
  });

  it('reports the configured command timeout', async () => {
    await assert.rejects(
      cronModule.execCommand(process.execPath, ['-e', 'setTimeout(() => {}, 1000)'], undefined, { timeoutMs: 25 }),
      /timed out after 25ms/,
    );
  });

  it('adds an OpenClaw cron job with no-delivery fallback and cron schedule', async () => {
    const gateway = fakeGateway();

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', cronExpression: '0 * * * *', quiet: false, force: false, timezone: 'Asia/Shanghai' },
      { request: gateway.request }
    );

    assert.equal(result.created, true);
    assert.equal(result.schedule, '0 * * * *');
    assert.equal(result.timezone, 'Asia/Shanghai');
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.add']);
    const job = gateway.calls[1].params;
    assert.equal(job.name, 'agentguard-threat-feed');
    assert.deepEqual(job.schedule, { kind: 'cron', expr: '0 * * * *', tz: 'Asia/Shanghai' });
    assert.deepEqual(job.delivery, { mode: 'none' });
    assert.equal(job.sessionTarget, 'isolated');
    assert.equal(job.payload.kind, 'agentTurn');
    assert.equal('agentguard' in job.payload, false);
    assert.match(job.payload.message, /Mode: manual/);
    assert.match(job.payload.message, /Command: `agentguard subscribe --json --cron-run`/);
    assert.match(job.payload.message, /agentguard subscribe --json --cron-run/);
    assert.match(job.payload.message, /handles its own OpenClaw notification delivery/);
    assert.match(job.payload.message, /NO_REPLY/);
  });

  it('auto-installs system crontab jobs for non-native cron agent hosts', async () => {
    for (const agentHost of ['codex', 'dsh'] as const) {
      const calls: Array<{ command: string; args: string[]; input?: string }> = [];
      const home = mkdtempSync(join(tmpdir(), `agentguard-system-${agentHost}-`));
      const runner: CommandRunner = async (command, args, input) => {
        calls.push({ command, args, input });
        if (command === 'crontab' && args[0] === '-l') {
          return { stdout: '# existing\n', stderr: '' };
        }
        return { stdout: '', stderr: '' };
      };

      const result = await installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: true,
          force: false,
          backend: 'auto',
          agentHost,
          agentGuardHome: home,
          timezone: 'UTC',
        },
        { runCommand: runner }
      );

      assert.equal(result.backend, 'system');
      assert.equal(result.created, true);
      assert.equal(calls[0].command, 'crontab');
      assert.deepEqual(calls[0].args, ['-l']);
      assert.equal(calls[1].command, 'crontab');
      assert.deepEqual(calls[1].args, ['-']);
      assert.match(calls[1].input ?? '', /# AgentGuard begin agentguard-threat-feed/);
      assert.match(calls[1].input ?? '', /agentguard-system-.*\/scripts\/agentguard-threat-feed\.sh/);
      assert.doesNotMatch(calls[1].input ?? '', /AGENTGUARD_HOME=/);
      const script = readFileSync(join(home, 'scripts', 'agentguard-threat-feed.sh'), 'utf8');
      assert.match(script, new RegExp(`export AGENTGUARD_HOME='${home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`));
      assert.match(script, /exec agentguard subscribe --quiet --json --cron-run/);
    }
  });

  it('auto-installs Windows Task Scheduler jobs for local agent hosts on Windows', async () => {
    for (const agentHost of ['claude-code', 'codex', 'dsh'] as const) {
      const calls: Array<{ command: string; args: string[]; input?: string }> = [];
      const home = mkdtempSync(join(tmpdir(), `agentguard-windows-${agentHost}-`));
      const runner: CommandRunner = async (command, args, input) => {
        calls.push({ command, args, input });
        if (command === 'schtasks.exe' && args[0] === '/Query') {
          throw Object.assign(new Error('localized task-not-found message'), { exitCode: 0x80070002 });
        }
        if (command === 'whoami.exe') {
          return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
        }
        return { stdout: '', stderr: '' };
      };

      const result = await installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: '*/15 * * * *',
          quiet: true,
          force: false,
          backend: 'auto',
          agentHost,
          agentGuardHome: home,
          timezone: 'Asia/Shanghai',
        },
        { runCommand: runner, platform: 'win32' } as Parameters<typeof installThreatFeedCron>[1]
      );

      assert.equal(result.backend, 'windows-task-scheduler');
      assert.equal(result.created, true);
      assert.equal(calls[0]?.command, 'schtasks.exe');
      assert.equal(calls[0]?.args[0], '/Query');
      assert.equal(calls[1]?.command, 'whoami.exe');
      assert.equal(calls[2]?.command, 'schtasks.exe');
      assert.equal(calls[2]?.args[0], '/Create');
    }
  });

  it('rejects invalid Windows cron syntax before querying or creating a task', async () => {
    let calls = 0;
    await assert.rejects(
      installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: 'invalid * * * *',
          quiet: true,
          force: false,
          backend: 'windows',
        },
        {
          platform: 'win32',
          async runCommand() {
            calls += 1;
            return { stdout: '', stderr: '' };
          },
        },
      ),
      /cron/i,
    );
    assert.equal(calls, 0);
  });

  it('registers a current-user Windows task from XML with a minute cron runner', async () => {
    const calls: Array<{ command: string; args: string[]; input?: string }> = [];
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-xml-'));
    const runner: CommandRunner = async (command, args, input) => {
      calls.push({ command, args, input });
      if (command === 'schtasks.exe' && args[0] === '/Query') {
        throw Object.assign(new Error('task not found'), { exitCode: 0x80070002 });
      }
      if (command === 'whoami.exe') {
        return { stdout: '"DESKTOP\\jeff","S-1-5-21-100-200-300-1001"\r\n', stderr: '' };
      }
      return { stdout: '', stderr: '' };
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '30 3 * * *',
        quiet: false,
        force: false,
        backend: 'windows',
        agentGuardHome: home,
        timezone: 'Asia/Shanghai',
      },
      {
        runCommand: runner,
        platform: 'win32',
        nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
        cliEntrypoint: 'C:\\Program Files\\AgentGuard & Tools\\dist\\cli.js',
        now: () => new Date('2026-09-07T10:30:20Z'),
      } as Parameters<typeof installThreatFeedCron>[1]
    );

    const xmlPath = join(home, 'scripts', 'agentguard-threat-feed.task.xml');
    const configPath = join(home, 'scripts', 'agentguard-threat-feed.windows-cron.json');
    const create = calls.find((call) => call.command === 'schtasks.exe' && call.args[0] === '/Create');
    assert.deepEqual(create?.args, [
      '/Create', '/TN', 'AgentGuard-agentguard-threat-feed', '/XML', xmlPath, '/F', '/HRESULT',
    ]);
    assert.equal(result.script, configPath);

    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.deepEqual(config, {
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '30 3 * * *',
      timezone: 'Asia/Shanghai',
      quiet: false,
      agentGuardHome: home,
      nodeExecutable: 'C:\\Program Files\\nodejs\\node.exe',
      cliEntrypoint: 'C:\\Program Files\\AgentGuard & Tools\\dist\\cli.js',
    });

    const xmlBytes = readFileSync(xmlPath);
    assert.deepEqual([...xmlBytes.subarray(0, 2)], [0xff, 0xfe]);
    const xml = xmlBytes.subarray(2).toString('utf16le');
    assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-16"\?>/);
    assert.match(xml, /<UserId>S-1-5-21-100-200-300-1001<\/UserId>/);
    assert.match(xml, /<LogonType>InteractiveToken<\/LogonType>/);
    assert.match(xml, /<RunLevel>LeastPrivilege<\/RunLevel>/);
    assert.match(xml, /<Interval>PT1M<\/Interval>/);
    assert.match(xml, /<MultipleInstancesPolicy>IgnoreNew<\/MultipleInstancesPolicy>/);
    assert.match(xml, /<ExecutionTimeLimit>PT10M<\/ExecutionTimeLimit>/);
    assert.match(xml, /<Command>C:\\Program Files\\nodejs\\node\.exe<\/Command>/);
    assert.match(xml, /AgentGuard &amp; Tools/);
    assert.match(xml, /windows-cron-run/);
  });

  it('does not overwrite a Windows task when Task Scheduler query is denied', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      throw Object.assign(new Error('access denied'), { exitCode: 0x80070005 });
    };

    await assert.rejects(
      installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: true,
          force: false,
          backend: 'windows',
        },
        { runCommand: runner, platform: 'win32' } as Parameters<typeof installThreatFeedCron>[1],
      ),
      /Could not query Windows scheduled task.*access denied/i,
    );
    assert.deepEqual(calls.map((call) => call.args[0]), ['/Query']);
  });

  it('does not trust an unrelated task that collides with the managed Windows task name', async () => {
    let calls = 0;
    await assert.rejects(
      installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: true,
          force: false,
          backend: 'windows',
        },
        {
          platform: 'win32',
          async runCommand() {
            calls += 1;
            return { stdout: '<Task><Actions><Exec><Command>unrelated.exe</Command></Exec></Actions></Task>', stderr: '' };
          },
        },
      ),
      /not a managed AgentGuard task/i,
    );
    assert.equal(calls, 1);
  });

  it('rejects Windows action paths containing environment expansion syntax', async () => {
    let calls = 0;
    await assert.rejects(
      installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: true,
          force: false,
          backend: 'windows',
          agentGuardHome: 'C:\\Users\\%USERNAME%\\.agentguard',
        },
        {
          platform: 'win32',
          async runCommand() {
            calls += 1;
            return { stdout: '', stderr: '' };
          },
        },
      ),
      /must not contain.*%/i,
    );
    assert.equal(calls, 0);
  });

  it('restores Windows runner files when forced task registration fails', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-create-rollback-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    const xmlPath = join(scriptsDir, 'agentguard-threat-feed.task.xml');
    const previousConfig = `${JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    })}\n`;
    writeFileSync(configPath, previousConfig);
    writeFileSync(xmlPath, 'previous xml\n');
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (command === 'whoami.exe') {
        return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
      }
      if (command === 'schtasks.exe' && args[0] === '/Create') {
        throw Object.assign(new Error('registration denied'), { exitCode: 0x80070005 });
      }
      return { stdout: managedWindowsTaskXml(configPath, false), stderr: '' };
    };

    await assert.rejects(
      installThreatFeedCron(
        {
          name: 'agentguard-threat-feed',
          cronExpression: '*/30 * * * *',
          quiet: true,
          force: true,
          backend: 'windows',
          agentGuardHome: home,
        },
        { platform: 'win32', runCommand: runner },
      ),
      /registration denied/,
    );

    assert.equal(readFileSync(configPath, 'utf8'), previousConfig);
    assert.equal(readFileSync(xmlPath, 'utf8'), 'previous xml\n');
    assert.equal(calls.some((call) => call.args.includes('/Enable')), false);
  });

  it('repairs a corrupt Windows runner config when force is set', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-force-repair-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    }));
    const existingXml = managedWindowsTaskXml(configPath);
    writeFileSync(configPath, '{not valid JSON');
    const runner: CommandRunner = async (command, args) => {
      if (command === 'whoami.exe') {
        return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
      }
      if (args[0] === '/Query') return { stdout: existingXml, stderr: '' };
      return { stdout: '', stderr: '' };
    };

    const result = await installThreatFeedCron({
      name: 'agentguard-threat-feed',
      cronExpression: '15 * * * *',
      quiet: true,
      force: true,
      backend: 'windows',
      agentGuardHome: home,
    }, {
      platform: 'win32',
      runCommand: runner,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    });

    assert.equal(result.created, true);
    assert.equal(JSON.parse(readFileSync(configPath, 'utf8')).cronExpression, '15 * * * *');
  });

  it('restores the registered Windows task when post-registration cleanup fails', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-task-rollback-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    const xmlPath = join(scriptsDir, 'agentguard-threat-feed.task.xml');
    const previousConfig = JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    });
    writeFileSync(configPath, previousConfig);
    writeFileSync(xmlPath, 'previous generated xml');
    const existingXml = managedWindowsTaskXml(configPath, false);
    mkdirSync(`${configPath}.state.json`);
    const registeredXml: string[] = [];
    const runner: CommandRunner = async (command, args) => {
      if (command === 'whoami.exe') {
        return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
      }
      if (args[0] === '/Query') return { stdout: existingXml, stderr: '' };
      if (args[0] === '/Create') {
        const bytes = readFileSync(args[4]!);
        assert.deepEqual([...bytes.subarray(0, 2)], [0xff, 0xfe]);
        registeredXml.push(bytes.subarray(2).toString('utf16le'));
      }
      return { stdout: '', stderr: '' };
    };

    await assert.rejects(
      installThreatFeedCron({
        name: 'agentguard-threat-feed',
        cronExpression: '30 * * * *',
        quiet: true,
        force: true,
        backend: 'windows',
        agentGuardHome: home,
      }, { platform: 'win32', runCommand: runner }),
      /directory|EISDIR/i,
    );

    assert.equal(registeredXml.length, 2);
    assert.equal(registeredXml[1], existingXml);
    assert.equal(readFileSync(configPath, 'utf8'), previousConfig);
    assert.equal(readFileSync(xmlPath, 'utf8'), 'previous generated xml');
  });

  it('resets Windows cron runner state after a successful forced reschedule', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-force-state-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    const statePath = `${configPath}.state.json`;
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    }));
    writeFileSync(statePath, JSON.stringify({ version: 1, lastCheckedMinute: '2026-09-07T10:00:00.000Z' }));
    const runner: CommandRunner = async (command) => {
      if (command === 'schtasks.exe') {
        return { stdout: managedWindowsTaskXml(configPath), stderr: '' };
      }
      return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
    };

    await installThreatFeedCron({
      name: 'agentguard-threat-feed',
      cronExpression: '30 * * * *',
      quiet: true,
      force: true,
      backend: 'windows',
      agentGuardHome: home,
    }, { platform: 'win32', runCommand: runner });

    assert.equal(existsSync(statePath), false);
  });

  it('deletes the managed Windows task and its runner files', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-remove-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    const xmlPath = join(scriptsDir, 'agentguard-threat-feed.task.xml');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    }));
    writeFileSync(xmlPath, '<Task/>');
    const lockStartedAtMs = Date.now();
    writeFileSync(`${configPath}.lock`, JSON.stringify({ version: 1, pid: 4242, startedAtMs: lockStartedAtMs }));
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (command === 'whoami.exe') {
        return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
      }
      if (command === 'powershell.exe') {
        return { stdout: JSON.stringify({
          pid: 4242,
          executablePath: 'C:\\node.exe',
          commandLine: `"C:\\node.exe" "C:\\cli.js" windows-cron-run --config "${configPath}"`,
          creationTimeMs: lockStartedAtMs,
        }), stderr: '' };
      }
      return { stdout: managedWindowsTaskXml(configPath), stderr: '' };
    };

    const result = await removeThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        backend: 'windows',
        agentGuardHome: home,
      },
      { runCommand: runner, platform: 'win32' } as Parameters<typeof removeThreatFeedCron>[1]
    );

    assert.deepEqual(result, [{
      name: 'agentguard-threat-feed',
      backend: 'windows-task-scheduler',
      removed: true,
    }]);
    assert.deepEqual(calls.map((call) => [call.command, call.args[0]]), [
      ['schtasks.exe', '/Query'],
      ['whoami.exe', '/User'],
      ['schtasks.exe', '/Change'],
      ['powershell.exe', '-NoProfile'],
      ['taskkill.exe', '/PID'],
      ['schtasks.exe', '/End'],
      ['schtasks.exe', '/Delete'],
    ]);
    assert.deepEqual(calls[2]?.args, [
      '/Change', '/TN', 'AgentGuard-agentguard-threat-feed', '/Disable',
    ]);
    assert.deepEqual(calls[4]?.args, [
      '/PID', '4242', '/T', '/F',
    ]);
    assert.deepEqual(calls[5]?.args, [
      '/End', '/TN', 'AgentGuard-agentguard-threat-feed',
    ]);
    assert.deepEqual(calls[6]?.args, [
      '/Delete', '/TN', 'AgentGuard-agentguard-threat-feed', '/F',
    ]);
    assert.equal(existsSync(configPath), false);
    assert.equal(existsSync(xmlPath), false);
  });

  it('does not delete a Windows task when its active runner cannot be stopped', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-remove-active-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    }));
    writeFileSync(`${configPath}.lock`, 'active');
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (command === 'whoami.exe') {
        return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
      }
      if (args[0] === '/End') throw new Error('access denied');
      return { stdout: managedWindowsTaskXml(configPath), stderr: '' };
    };

    const [result] = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'windows', agentGuardHome: home },
      { runCommand: runner, platform: 'win32' },
    );

    assert.equal(result?.removed, false);
    assert.match(result?.error ?? '', /could not stop active Windows scheduled task/i);
    assert.equal(calls.some((call) => call.args[0] === '/Delete'), false);
    assert.equal(existsSync(configPath), true);
    assert.equal(existsSync(`${configPath}.lock`), true);
  });

  it('refuses to kill a reused PID that is not the expected Windows runner', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-reused-pid-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    }));
    writeFileSync(`${configPath}.lock`, JSON.stringify({ version: 1, pid: 4242, startedAtMs: Date.now() }));
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (command === 'whoami.exe') {
        return { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' };
      }
      if (command === 'powershell.exe') {
        return { stdout: JSON.stringify({
          pid: 4242,
          executablePath: 'C:\\Windows\\System32\\notepad.exe',
          commandLine: 'notepad.exe',
          creationTimeMs: Date.now(),
        }), stderr: '' };
      }
      return { stdout: managedWindowsTaskXml(configPath), stderr: '' };
    };

    const [result] = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'windows', agentGuardHome: home },
      { runCommand: runner, platform: 'win32' },
    );

    assert.equal(result?.removed, false);
    assert.match(result?.error ?? '', /does not match the managed Windows runner/i);
    assert.equal(calls.some((call) => call.command === 'taskkill.exe'), false);
    assert.equal(calls.some((call) => call.args[0] === '/Delete'), false);
  });

  it('rejects a managed-looking Windows task owned by a different user SID', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-wrong-owner-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const configPath = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    writeFileSync(configPath, JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '0 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\cli.js',
    }));

    const status = await inspectWindowsThreatFeedTask(
      { name: 'agentguard-threat-feed', agentGuardHome: home },
      { runCommand: async (command) => command === 'whoami.exe'
        ? { stdout: 'user,S-1-5-21-999-888-777-1001\n', stderr: '' }
        : { stdout: managedWindowsTaskXml(configPath), stderr: '' } },
    );

    assert.equal(status.installed, false);
    assert.match(status.error ?? '', /not a managed AgentGuard task/i);
  });

  it('inspects the exact managed Windows task and cron expression', async () => {
    const inspectWindowsThreatFeedTask = (cronModule as Record<string, unknown>).inspectWindowsThreatFeedTask;
    assert.equal(typeof inspectWindowsThreatFeedTask, 'function');
    const inspectTask = inspectWindowsThreatFeedTask as (
      options: { name: string; agentGuardHome: string },
      adapters: { runCommand: CommandRunner },
    ) => Promise<{ name: string; installed: boolean; cronExpression?: string }>;
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-inspect-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    writeFileSync(join(scriptsDir, 'agentguard-threat-feed.windows-cron.json'), JSON.stringify({
      version: 1,
      name: 'agentguard-threat-feed',
      cronExpression: '*/15 * * * *',
      timezone: 'UTC',
      quiet: true,
      agentGuardHome: home,
      nodeExecutable: 'C:\\node.exe',
      cliEntrypoint: 'C:\\agentguard\\cli.js',
    }));

    const status = await inspectTask(
      { name: 'agentguard-threat-feed', agentGuardHome: home },
      { runCommand: async (command) => command === 'whoami.exe'
        ? { stdout: 'user,S-1-5-21-100-200-300-1001\n', stderr: '' }
        : {
            stdout: managedWindowsTaskXml(join(scriptsDir, 'agentguard-threat-feed.windows-cron.json')),
            stderr: '',
          } },
    );

    assert.deepEqual(status, {
      name: 'agentguard-threat-feed',
      installed: true,
      cronExpression: '*/15 * * * *',
    });
  });

  it('treats a missing Windows scheduled task as confirmed absent', async () => {
    const inspectWindowsThreatFeedTask = (cronModule as Record<string, unknown>).inspectWindowsThreatFeedTask as (
      options: { name: string; agentGuardHome?: string },
      adapters: { runCommand: CommandRunner },
    ) => Promise<{ name: string; installed: boolean; error?: string }>;
    const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-absent-cleanup-'));
    const scriptsDir = join(home, 'scripts');
    mkdirSync(scriptsDir, { recursive: true });
    const staleConfig = join(scriptsDir, 'agentguard-threat-feed.windows-cron.json');
    const staleState = `${staleConfig}.state.json`;
    writeFileSync(staleConfig, '{}');
    writeFileSync(staleState, '{}');
    const runner: CommandRunner = async () => {
      throw Object.assign(new Error('localized task-not-found message'), { exitCode: 0x80070002 });
    };

    const status = await inspectWindowsThreatFeedTask(
      { name: 'agentguard-threat-feed', agentGuardHome: home },
      { runCommand: runner },
    );
    const removal = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'windows', agentGuardHome: home },
      { runCommand: runner, platform: 'win32' } as Parameters<typeof removeThreatFeedCron>[1],
    );

    assert.deepEqual(status, { name: 'agentguard-threat-feed', installed: false });
    assert.deepEqual(removal, [{
      name: 'agentguard-threat-feed',
      backend: 'windows-task-scheduler',
      removed: false,
    }]);
    assert.equal(existsSync(staleConfig), false);
    assert.equal(existsSync(staleState), false);
  });

  it('uses Task Scheduler instead of crontab when removing all backends on Windows', async () => {
    const commands: string[] = [];
    const runner: CommandRunner = async (command) => {
      commands.push(command);
      if (command === 'schtasks.exe') {
        throw Object.assign(new Error('missing'), { exitCode: 2 });
      }
      return { stdout: '{"jobs":[]}', stderr: '' };
    };
    const gateway = { async request() { return { jobs: [] }; } };

    const results = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'all' },
      { platform: 'win32', runCommand: runner, gateway },
    );

    assert.equal(results.some((item) => item.backend === 'windows-task-scheduler'), true);
    assert.equal(results.some((item) => item.backend === 'system'), false);
    assert.equal(commands.includes('crontab'), false);
  });

  it('removes the managed system crontab block without touching other entries', async () => {
    const calls: Array<{ command: string; args: string[]; input?: string }> = [];
    const home = mkdtempSync(join(tmpdir(), 'agentguard-system-remove-'));
    const current = [
      '# existing',
      '# AgentGuard begin agentguard-threat-feed',
      '0 * * * * /tmp/agentguard-threat-feed.sh',
      '# AgentGuard end agentguard-threat-feed',
      '15 * * * * /tmp/other-job.sh',
      '',
    ].join('\n');
    const runner: CommandRunner = async (command, args, input) => {
      calls.push({ command, args, input });
      if (command === 'crontab' && args[0] === '-l') {
        return { stdout: current, stderr: '' };
      }
      return { stdout: '', stderr: '' };
    };

    const result = await removeThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        backend: 'system',
        agentGuardHome: home,
      },
      { runCommand: runner }
    );

    assert.deepEqual(result, [{ name: 'agentguard-threat-feed', backend: 'system', removed: true }]);
    assert.deepEqual(calls.map((call) => call.args[0]), ['-l', '-']);
    assert.match(calls[1].input ?? '', /# existing/);
    assert.match(calls[1].input ?? '', /other-job/);
    assert.doesNotMatch(calls[1].input ?? '', /AgentGuard begin agentguard-threat-feed/);
  });

  it('inspects the exact managed system crontab block and cron expression', async () => {
    const managedBlock = [
      '# AgentGuard begin agentguard-threat-feed',
      '*/15 * * * * /tmp/agentguard-threat-feed.sh',
      '# AgentGuard end agentguard-threat-feed',
      '',
    ].join('\n');

    const status = await inspectSystemThreatFeedCron(
      { name: 'agentguard-threat-feed' },
      { runCommand: async () => ({ stdout: managedBlock, stderr: '' }) }
    );

    assert.deepEqual(status, {
      name: 'agentguard-threat-feed',
      installed: true,
      cronExpression: '*/15 * * * *',
    });
  });

  it('reports a missing managed system crontab block as confirmed absent', async () => {
    const status = await inspectSystemThreatFeedCron(
      { name: 'agentguard-threat-feed' },
      { runCommand: async () => ({ stdout: '0 * * * * /tmp/unrelated.sh\n', stderr: '' }) }
    );

    assert.deepEqual(status, { name: 'agentguard-threat-feed', installed: false });
  });

  it('treats an explicit no-crontab response as confirmed absence', async () => {
    const runner: CommandRunner = async () => {
      throw new Error('crontab: no crontab for jeff');
    };

    const status = await inspectSystemThreatFeedCron(
      { name: 'agentguard-threat-feed' },
      { runCommand: runner }
    );
    const removal = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'system' },
      { runCommand: runner }
    );

    assert.deepEqual(status, { name: 'agentguard-threat-feed', installed: false });
    assert.deepEqual(removal, [{ name: 'agentguard-threat-feed', backend: 'system', removed: false }]);
  });

  it('reports unrelated crontab read failures and does not attempt a write', async () => {
    const calls: string[][] = [];
    const runner: CommandRunner = async (_command, args) => {
      calls.push(args);
      throw new Error('operation not permitted');
    };

    const status = await inspectSystemThreatFeedCron(
      { name: 'agentguard-threat-feed' },
      { runCommand: runner }
    );
    const removal = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'system' },
      { runCommand: runner }
    );

    assert.deepEqual(status, {
      name: 'agentguard-threat-feed',
      installed: false,
      error: 'operation not permitted',
    });
    assert.deepEqual(removal, [{
      name: 'agentguard-threat-feed',
      backend: 'system',
      removed: false,
      error: 'operation not permitted',
    }]);
    assert.deepEqual(calls, [['-l'], ['-l']]);
  });

  it('reports an incomplete managed cron block as an error without touching other jobs', async () => {
    const calls: Array<{ args: string[]; input?: string }> = [];
    const malformed = [
      '# existing',
      '# AgentGuard begin agentguard-threat-feed',
      '0 * * * * /tmp/agentguard-threat-feed.sh',
      '15 * * * * /tmp/other-job.sh',
      '',
    ].join('\n');
    const runner: CommandRunner = async (_command, args, input) => {
      calls.push({ args, input });
      return { stdout: malformed, stderr: '' };
    };

    const status = await inspectSystemThreatFeedCron(
      { name: 'agentguard-threat-feed' },
      { runCommand: runner }
    );
    const removal = await removeThreatFeedCron(
      { name: 'agentguard-threat-feed', backend: 'system' },
      { runCommand: runner }
    );

    assert.match(status.error ?? '', /incomplete managed system cron block/i);
    assert.equal(status.installed, false);
    assert.match(removal[0].error ?? '', /incomplete managed system cron block/i);
    assert.equal(removal[0].removed, false);
    assert.deepEqual(calls.map(call => call.args), [['-l'], ['-l']]);
  });

  it('removes OpenClaw gateway cron jobs by default subscribe name', async () => {
    const gateway = fakeGateway([{ id: 'job-1', name: 'agentguard-threat-feed' }]);

    const result = await removeThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        backend: 'openclaw',
      },
      {
        async runCommand() {
          throw new Error('native openclaw unavailable');
        },
        gateway: { request: gateway.request },
      }
    );

    assert.deepEqual(result.map((item) => item.backend), ['openclaw', 'openclaw-gateway']);
    assert.equal(result[0].removed, false);
    assert.match(result[0].error ?? '', /native openclaw unavailable/);
    assert.equal(result[1].removed, true);
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.remove']);
    assert.deepEqual(gateway.calls[1].params, { jobId: 'job-1' });
  });

  it('removes native OpenClaw cron jobs by id', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (args.join(' ') === 'cron list') {
        return {
          stdout: JSON.stringify({
            jobs: [
              { id: '7407b173-da3f-4ded-b6e3-722a9c5248b0', name: 'agentguard-threat-feed' },
            ],
          }),
          stderr: '',
        };
      }
      return { stdout: '', stderr: '' };
    };

    const result = await removeThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        backend: 'openclaw',
      },
      { runCommand: runner, gateway: { request: fakeGateway().request } }
    );

    assert.equal(result[0].backend, 'openclaw');
    assert.equal(result[0].removed, true);
    assert.deepEqual(calls.map((call) => call.args.slice(0, 2).join(' ')), ['cron list', 'cron remove']);
    assert.deepEqual(calls[1].args, ['cron', 'remove', '7407b173-da3f-4ded-b6e3-722a9c5248b0']);
  });

  it('rejects unsafe AgentGuard home paths for system crontab jobs', async () => {
    await assert.rejects(
      () =>
        installThreatFeedCron({
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: true,
          force: false,
          backend: 'system',
          agentGuardHome: '/tmp/ag-home"; touch /tmp/pwned #',
          timezone: 'UTC',
        }),
      /must not contain quotes or newlines/
    );
  });

  it('quotes paths with spaces for system crontab jobs', async () => {
    const calls: Array<{ command: string; args: string[]; input?: string }> = [];
    const root = mkdtempSync(join(tmpdir(), 'agentguard system root-'));
    const home = join(root, 'AgentGuard Home With Spaces');
    const runner: CommandRunner = async (command, args, input) => {
      calls.push({ command, args, input });
      if (command === 'crontab' && args[0] === '-l') {
        return { stdout: '', stderr: '' };
      }
      return { stdout: '', stderr: '' };
    };

    await installThreatFeedCron(
      {
        name: 'agentguard threat feed',
        cronExpression: '0 * * * *',
        quiet: true,
        force: false,
        backend: 'system',
        agentGuardHome: home,
        timezone: 'UTC',
      },
      { runCommand: runner }
    );

    const crontab = calls.find((call) => call.command === 'crontab' && call.args[0] === '-')?.input ?? '';
    assert.match(crontab, /'[^']*AgentGuard Home With Spaces\/scripts\/agentguard-threat-feed\.sh'/);
    assert.match(crontab, /'[^']*AgentGuard Home With Spaces\/feed-cron\.log'/);
    const script = readFileSync(join(home, 'scripts', 'agentguard-threat-feed.sh'), 'utf8');
    assert.match(script, /export AGENTGUARD_HOME='[^']*AgentGuard Home With Spaces'/);
  });

  it('uses native OpenClaw cron command before Gateway fallback for OpenClaw agents', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (args.join(' ') === 'cron list') return { stdout: '', stderr: '' };
      return { stdout: 'created', stderr: '' };
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '0 * * * *',
        quiet: false,
        force: false,
        backend: 'auto',
        agentHost: 'openclaw',
        timezone: 'UTC',
      },
      { runCommand: runner }
    );

    assert.equal(result.backend, 'openclaw');
    assert.deepEqual(calls.map((call) => call.args.slice(0, 2).join(' ')), ['cron list', 'cron add']);
    assert.ok(calls[1].args.includes('--timeout-seconds'));
    assert.ok(calls[1].args.includes('300'));
    assert.ok(calls[1].args.includes('--no-deliver'));
    assert.ok(!calls[1].args.includes('--announce'));
  });

  it('does not treat native OpenClaw cron name substrings as existing jobs', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (args.join(' ') === 'cron list') {
        return { stdout: 'agentguard-threat-feed-extra    0 * * * *\n', stderr: '' };
      }
      return { stdout: 'created', stderr: '' };
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '0 * * * *',
        quiet: false,
        force: false,
        backend: 'auto',
        agentHost: 'openclaw',
        timezone: 'UTC',
      },
      { runCommand: runner }
    );

    assert.equal(result.created, true);
    assert.deepEqual(calls.map((call) => call.args.slice(0, 2).join(' ')), ['cron list', 'cron add']);
  });

  it('leaves exact native OpenClaw cron names untouched unless force is set', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      return {
        stdout: JSON.stringify({ jobs: [{ name: 'agentguard-threat-feed' }] }),
        stderr: '',
      };
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '0 * * * *',
        quiet: false,
        force: false,
        backend: 'auto',
        agentHost: 'openclaw',
        timezone: 'UTC',
      },
      { runCommand: runner }
    );

    assert.equal(result.created, false);
    assert.deepEqual(calls.map((call) => call.args.slice(0, 2).join(' ')), ['cron list']);
  });

  it('replaces native OpenClaw cron jobs by id when force is set', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (args.join(' ') === 'cron list') {
        return {
          stdout: [
            'ID                                   Name                     Schedule',
            '7407b173-da3f-4ded-b6e3-722a9c5248b0 agentguard-threat-feed   cron */5 * * * * @ UTC',
          ].join('\n'),
          stderr: '',
        };
      }
      return { stdout: '', stderr: '' };
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '*/5 * * * *',
        quiet: true,
        force: true,
        backend: 'auto',
        agentHost: 'openclaw',
        timezone: 'UTC',
      },
      { runCommand: runner }
    );

    assert.equal(result.created, true);
    assert.deepEqual(calls.map((call) => call.args.slice(0, 2).join(' ')), ['cron list', 'cron remove', 'cron add']);
    assert.deepEqual(calls[1].args, ['cron', 'remove', '7407b173-da3f-4ded-b6e3-722a9c5248b0']);
    assert.ok(!calls[2].args.includes('--force'));
  });

  it('does not fall back to OpenClaw Gateway when native OpenClaw cron add fails', async () => {
    const gateway = fakeGateway();
    const runner: CommandRunner = async (_command, args) => {
      if (args.join(' ') === 'cron list') return { stdout: '', stderr: '' };
      throw new Error('invalid native OpenClaw cron arguments');
    };

    await assert.rejects(
      () =>
        installThreatFeedCron(
          {
            name: 'agentguard-threat-feed',
            cronExpression: '0 * * * *',
            quiet: false,
            force: false,
            backend: 'auto',
            agentHost: 'openclaw',
            timezone: 'UTC',
          },
          { runCommand: runner, gateway: { request: gateway.request } }
        ),
      /invalid native OpenClaw cron arguments/
    );
    assert.deepEqual(gateway.calls, []);
  });

  it('auto-installs QClaw Gateway cron jobs for QClaw agents', async () => {
    const gateway = fakeGateway();
    const runner: CommandRunner = async () => {
      throw new Error('system cron should not be used for qclaw auto target');
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '0 * * * *',
        quiet: false,
        force: false,
        backend: 'auto',
        agentHost: 'qclaw',
        timezone: 'UTC',
      },
      { runCommand: runner, gateway: { request: gateway.request } }
    );

    assert.equal(result.backend, 'qclaw-gateway');
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.add']);
    const job = gateway.calls[1].params;
    assert.equal(job.name, 'agentguard-threat-feed');
    assert.deepEqual(job.schedule, { kind: 'cron', expr: '0 * * * *', tz: 'UTC' });
    assert.deepEqual(job.delivery, { mode: 'announce', channel: 'last' });
    assert.equal('agentguard' in job.payload, false);
    assert.match(job.payload.message, /Command: `agentguard subscribe --cron-notify-run`/);
    assert.match(job.payload.message, /remediation guidance/);
    assert.match(job.payload.message, /manual response steps/);
  });

  it('auto-installs native Hermes cron jobs for Hermes agents', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const hermesHome = mkdtempSync(join(tmpdir(), 'agentguard-hermes-'));
    const runner: CommandRunner = async (command, args) => {
      calls.push({ command, args });
      if (args.join(' ') === 'cron list') return { stdout: 'No scheduled jobs.', stderr: '' };
      return { stdout: 'created', stderr: '' };
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '0 * * * *',
        quiet: true,
        force: false,
        backend: 'auto',
        agentHost: 'hermes',
        agentGuardHome: '/tmp/ag-home',
        hermesHome,
        timezone: 'UTC',
      },
      { runCommand: runner }
    );

    assert.equal(result.backend, 'hermes');
    assert.equal(result.script, 'agentguard-agentguard-threat-feed.sh');
    assert.deepEqual(calls.map((call) => call.args.slice(0, 2).join(' ')), ['cron list', 'cron create']);
    assert.deepEqual(calls[1].args, [
      'cron',
      'create',
      '0 * * * *',
      '--name',
      'agentguard-threat-feed',
      '--deliver',
      'local',
      '--script',
      'agentguard-agentguard-threat-feed.sh',
      '--no-agent',
    ]);
    const script = readFileSync(join(hermesHome, 'scripts', 'agentguard-agentguard-threat-feed.sh'), 'utf8');
    assert.match(script, /export AGENTGUARD_HOME='\/tmp\/ag-home'/);
    assert.match(script, /exec agentguard subscribe --quiet --json --cron-run/);
  });

  it('requires init --agent when auto has no saved agent host', async () => {
    await assert.rejects(
      () =>
        installThreatFeedCron({
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: false,
          force: false,
          backend: 'auto',
          timezone: 'UTC',
        }),
      /agentguard init --agent/
    );
  });

  it('fails fast when Hermes cron list is unavailable', async () => {
    const runner: CommandRunner = async () => {
      throw new Error('hermes command not found');
    };

    await assert.rejects(
      () =>
        installThreatFeedCron(
          {
            name: 'agentguard-threat-feed',
            cronExpression: '0 * * * *',
            quiet: false,
            force: false,
            backend: 'hermes',
            timezone: 'UTC',
          },
          { runCommand: runner }
        ),
      /Could not list Hermes cron jobs/
    );
  });

  it('falls back to OpenClaw Gateway when native OpenClaw cron command fails', async () => {
    const gateway = fakeGateway();
    const runner: CommandRunner = async () => {
      throw new Error('openclaw command not found');
    };

    const result = await installThreatFeedCron(
      {
        name: 'agentguard-threat-feed',
        cronExpression: '0 * * * *',
        quiet: false,
        force: false,
        backend: 'auto',
        agentHost: 'openclaw',
        timezone: 'UTC',
      },
      { runCommand: runner, gateway: { request: gateway.request } }
    );

    assert.equal(result.backend, 'openclaw-gateway');
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.add']);
  });

  it('rejects an explicit OpenClaw cron target when the saved agent host is different', async () => {
    await assert.rejects(
      () =>
        installThreatFeedCron({
          name: 'agentguard-threat-feed',
          cronExpression: '0 * * * *',
          quiet: false,
          force: false,
          backend: 'openclaw',
          agentHost: 'codex',
          timezone: 'UTC',
        }),
      /Cron target openclaw conflicts with saved agent host "codex"/
    );
  });

  it('fails fast when OpenClaw Gateway cron.list is unavailable', async () => {
    await assert.rejects(
      () =>
        installOpenClawThreatFeedCron(
          { name: 'agentguard-threat-feed', cronExpression: '0 * * * *', quiet: false, force: false, timezone: 'UTC' },
          {
            async request(method) {
              if (method === 'cron.list') throw new Error('Gateway unavailable');
              return { ok: true };
            },
          }
        ),
      /Gateway unavailable/
    );
  });

  it('leaves an existing cron job untouched unless force is set', async () => {
    const gateway = fakeGateway([{ id: 'job-1', name: 'agentguard-threat-feed' }]);

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', cronExpression: '0 * * * *', quiet: false, force: false, timezone: 'UTC' },
      { request: gateway.request }
    );

    assert.equal(result.created, false);
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list']);
  });

  it('removes an existing cron job by jobId when force is set', async () => {
    const gateway = fakeGateway([{ id: 'job-1', name: 'agentguard-threat-feed' }]);

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', cronExpression: '*/5 * * * *', quiet: true, force: true, timezone: 'UTC' },
      { request: gateway.request }
    );

    assert.equal(result.created, true);
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.remove', 'cron.add']);
    assert.deepEqual(gateway.calls[1].params, { jobId: 'job-1' });
    assert.deepEqual(gateway.calls[2].params.schedule, { kind: 'cron', expr: '*/5 * * * *', tz: 'UTC' });
    assert.equal('agentguard' in gateway.calls[2].params.payload, false);
    assert.match(gateway.calls[2].params.payload.message, /Mode: quiet/);
    assert.deepEqual(gateway.calls[2].params.delivery, { mode: 'none' });
    assert.match(gateway.calls[2].params.payload.message, /Command: `agentguard subscribe --quiet --json --cron-run`/);
    assert.match(gateway.calls[2].params.payload.message, /agentguard subscribe --quiet --json --cron-run/);
  });

  it('does not add a replacement if force removal fails', async () => {
    const calls: RpcCall[] = [];
    await assert.rejects(
      () =>
        installOpenClawThreatFeedCron(
          { name: 'agentguard-threat-feed', cronExpression: '*/5 * * * *', quiet: false, force: true, timezone: 'UTC' },
          {
            async request(method, params) {
              calls.push({ method, params });
              if (method === 'cron.list') return { jobs: [{ id: 'job-1', name: 'agentguard-threat-feed' }] };
              if (method === 'cron.remove') throw new Error('remove failed');
              return { ok: true };
            },
          }
        ),
      /remove failed/
    );
    assert.deepEqual(calls.map((call) => call.method), ['cron.list', 'cron.remove']);
  });

  it('uses the injected request path for OpenClaw Gateway calls', async () => {
    await assert.rejects(
      () =>
        openClawGatewayRequest('cron.list', {}, {
          request: async () => {
            throw new Error('OpenClaw Gateway cron.list request timed out after 25ms');
          },
        }),
      /timed out/
    );
  });

  it('prefers the OpenClaw CLI Gateway call for default local OpenClaw requests', async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const result = await openClawGatewayRequest('sessions.list', { limit: 1 }, {
      timeoutMs: 1234,
      runCommand: async (command, args) => {
        calls.push({ command, args });
        return {
          stdout: JSON.stringify({ sessions: [{ key: 'session-1' }] }),
          stderr: '',
        };
      },
    });

    assert.deepEqual(result, { sessions: [{ key: 'session-1' }] });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.command, 'openclaw');
    assert.deepEqual(calls[0]!.args, [
      'gateway',
      'call',
      'sessions.list',
      '--params',
      '{"limit":1}',
      '--timeout',
      '1234',
      '--json',
    ]);
  });

  it('keeps the default HTTP JSON-RPC Gateway path and legacy cron.add params', async () => {
    let requestBody: any;
    let authorization: string | undefined;
    const server = http.createServer((req, res) => {
      assert.equal(req.method, 'POST');
      assert.equal(req.url, '/');
      authorization = req.headers.authorization;
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        raw += chunk;
      });
      req.on('end', () => {
        requestBody = JSON.parse(raw);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ jsonrpc: '2.0', id: requestBody.id, result: { ok: true } }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await openClawGatewayRequest('cron.add', { name: 'agentguard-threat-feed' }, {
        host: '127.0.0.1',
        port: serverPort(server),
        token: 'gateway-test-token',
        timeoutMs: 1000,
        runCommand: async () => {
          throw new Error('explicit host/port should skip OpenClaw CLI');
        },
      });

      assert.deepEqual(result, { ok: true });
      assert.equal(authorization, 'Bearer gateway-test-token');
      assert.equal(requestBody.method, 'cron.add');
      assert.deepEqual(requestBody.params, [{ name: 'agentguard-threat-feed' }]);
    } finally {
      await closeServer(server);
    }
  });

  it('loads the local OpenClaw Gateway token for direct HTTP fallback requests', async () => {
    const stateDir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-token-state-'));
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    const previousConfigPath = process.env.OPENCLAW_CONFIG_PATH;
    const previousAgentGuardToken = process.env.AGENTGUARD_OPENCLAW_GATEWAY_TOKEN;
    const previousOpenClawToken = process.env.OPENCLAW_GATEWAY_TOKEN;
    let authorization: string | undefined;
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(stateDir, 'openclaw.json'), JSON.stringify({
      gateway: {
        auth: {
          token: 'config-gateway-token',
        },
      },
    }));
    process.env.OPENCLAW_STATE_DIR = stateDir;
    delete process.env.OPENCLAW_CONFIG_PATH;
    delete process.env.AGENTGUARD_OPENCLAW_GATEWAY_TOKEN;
    delete process.env.OPENCLAW_GATEWAY_TOKEN;

    const server = http.createServer((req, res) => {
      authorization = req.headers.authorization;
      let raw = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => {
        raw += chunk;
      });
      req.on('end', () => {
        const requestBody = JSON.parse(raw);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ jsonrpc: '2.0', id: requestBody.id, result: { sessions: [] } }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      await openClawGatewayRequest('sessions.list', {}, {
        host: '127.0.0.1',
        port: serverPort(server),
        timeoutMs: 100,
      });

      assert.equal(authorization, 'Bearer config-gateway-token');
    } finally {
      if (previousStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
      else process.env.OPENCLAW_STATE_DIR = previousStateDir;
      if (previousConfigPath === undefined) delete process.env.OPENCLAW_CONFIG_PATH;
      else process.env.OPENCLAW_CONFIG_PATH = previousConfigPath;
      if (previousAgentGuardToken === undefined) delete process.env.AGENTGUARD_OPENCLAW_GATEWAY_TOKEN;
      else process.env.AGENTGUARD_OPENCLAW_GATEWAY_TOKEN = previousAgentGuardToken;
      if (previousOpenClawToken === undefined) delete process.env.OPENCLAW_GATEWAY_TOKEN;
      else process.env.OPENCLAW_GATEWAY_TOKEN = previousOpenClawToken;
      await closeServer(server);
    }
  });

  it('handles fragmented WebSocket Gateway text responses', async () => {
    const server = net.createServer((socket) => {
      let handshakeComplete = false;
      let buffer = Buffer.alloc(0);
      let clientRequests = 0;

      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!handshakeComplete) {
          const headerEnd = buffer.indexOf('\r\n\r\n');
          if (headerEnd === -1) return;
          const header = buffer.subarray(0, headerEnd + 4).toString('utf8');
          const key = /^Sec-WebSocket-Key:\s*(.+)$/im.exec(header)?.[1]?.trim();
          assert.ok(key);
          const accept = createHash('sha1')
            .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
            .digest('base64');
          socket.write([
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Accept: ${accept}`,
            '',
            '',
          ].join('\r\n'));
          handshakeComplete = true;
          buffer = buffer.subarray(headerEnd + 4);
          socket.write(encodeServerWebSocketFrame(JSON.stringify({ type: 'event', event: 'connect.challenge' })));
        }

        while (true) {
          const parsed = readClientWebSocketFrame(buffer);
          if (!parsed) break;
          buffer = parsed.rest;
          clientRequests += 1;
          const frame = JSON.parse(parsed.payload);
          if (clientRequests === 1) {
            socket.write(encodeServerWebSocketFrame(JSON.stringify({ type: 'res', id: frame.id, ok: true, payload: {} })));
          } else {
            const response = JSON.stringify({
              type: 'res',
              id: frame.id,
              ok: true,
              payload: { jobs: [{ id: 'job-1', name: 'agentguard-threat-feed' }] },
            });
            const splitAt = Math.floor(response.length / 2);
            socket.write(encodeServerWebSocketFrame(response.slice(0, splitAt), 0x1, false));
            socket.write(encodeServerWebSocketFrame(response.slice(splitAt), 0x0, true));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await openClawGatewayRequest('cron.list', {}, {
        url: `ws://127.0.0.1:${serverPort(server)}`,
        timeoutMs: 500,
      });

      assert.deepEqual(result, { jobs: [{ id: 'job-1', name: 'agentguard-threat-feed' }] });
    } finally {
      await closeServer(server);
    }
  });

  it('sends signed device identity during the WebSocket connect handshake when OpenClaw identity exists', async () => {
    const stateDir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-state-'));
    const identity = writeOpenClawIdentity(stateDir);
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_STATE_DIR = stateDir;
    let connectParams: any;

    const server = net.createServer((socket) => {
      let handshakeComplete = false;
      let buffer = Buffer.alloc(0);
      let clientRequests = 0;

      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!handshakeComplete) {
          const headerEnd = buffer.indexOf('\r\n\r\n');
          if (headerEnd === -1) return;
          const header = buffer.subarray(0, headerEnd + 4).toString('utf8');
          const key = /^Sec-WebSocket-Key:\s*(.+)$/im.exec(header)?.[1]?.trim();
          assert.ok(key);
          const accept = createHash('sha1')
            .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
            .digest('base64');
          socket.write([
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Accept: ${accept}`,
            '',
            '',
          ].join('\r\n'));
          handshakeComplete = true;
          buffer = buffer.subarray(headerEnd + 4);
          socket.write(encodeServerWebSocketFrame(JSON.stringify({
            type: 'event',
            event: 'connect.challenge',
            payload: { nonce: 'nonce-1' },
          })));
        }

        while (true) {
          const parsed = readClientWebSocketFrame(buffer);
          if (!parsed) break;
          buffer = parsed.rest;
          clientRequests += 1;
          const frame = JSON.parse(parsed.payload);
          if (clientRequests === 1) {
            connectParams = frame.params;
            socket.write(encodeServerWebSocketFrame(JSON.stringify({ type: 'res', id: frame.id, ok: true, payload: {} })));
          } else {
            socket.write(encodeServerWebSocketFrame(JSON.stringify({
              type: 'res',
              id: frame.id,
              ok: true,
              payload: { jobs: [] },
            })));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await openClawGatewayRequest('cron.list', {}, {
        url: `ws://127.0.0.1:${serverPort(server)}`,
        timeoutMs: 500,
      });

      assert.deepEqual(result, { jobs: [] });
      assert.equal(connectParams.minProtocol, 3);
      assert.equal(connectParams.maxProtocol, 4);
      assert.equal(connectParams.client.id, 'cli');
      assert.equal(connectParams.device.id, identity.deviceId);
      assert.equal(connectParams.device.publicKey, publicKeyRawBase64UrlFromPem(identity.publicKeyPem));
      assert.equal(connectParams.device.nonce, 'nonce-1');
      assert.equal(typeof connectParams.device.signedAt, 'number');
      const signedPayload = [
        'v3',
        identity.deviceId,
        'cli',
        'cli',
        'operator',
        'operator.admin,operator.read,operator.write,operator.approvals,operator.pairing,operator.talk.secrets',
        String(connectParams.device.signedAt),
        '',
        'nonce-1',
        process.platform,
        '',
      ].join('|');
      assert.equal(
        verify(
          null,
          Buffer.from(signedPayload, 'utf8'),
          createPublicKey(identity.publicKeyPem),
          base64UrlDecode(connectParams.device.signature),
        ),
        true,
      );
    } finally {
      if (previousStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
      else process.env.OPENCLAW_STATE_DIR = previousStateDir;
      await closeServer(server);
    }
  });

  it('sends the Gateway token during the WebSocket connect handshake', async () => {
    let connectParams: any;

    const server = net.createServer((socket) => {
      let handshakeComplete = false;
      let buffer = Buffer.alloc(0);
      let clientRequests = 0;

      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!handshakeComplete) {
          const headerEnd = buffer.indexOf('\r\n\r\n');
          if (headerEnd === -1) return;
          const header = buffer.subarray(0, headerEnd + 4).toString('utf8');
          const key = /^Sec-WebSocket-Key:\s*(.+)$/im.exec(header)?.[1]?.trim();
          assert.ok(key);
          const accept = createHash('sha1')
            .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
            .digest('base64');
          socket.write([
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Accept: ${accept}`,
            '',
            '',
          ].join('\r\n'));
          handshakeComplete = true;
          buffer = buffer.subarray(headerEnd + 4);
          socket.write(encodeServerWebSocketFrame(JSON.stringify({
            type: 'event',
            event: 'connect.challenge',
            payload: { nonce: 'nonce-token' },
          })));
        }

        while (true) {
          const parsed = readClientWebSocketFrame(buffer);
          if (!parsed) break;
          buffer = parsed.rest;
          clientRequests += 1;
          const frame = JSON.parse(parsed.payload);
          if (clientRequests === 1) {
            connectParams = frame.params;
            socket.write(encodeServerWebSocketFrame(JSON.stringify({ type: 'res', id: frame.id, ok: true, payload: {} })));
          } else {
            socket.write(encodeServerWebSocketFrame(JSON.stringify({
              type: 'res',
              id: frame.id,
              ok: true,
              payload: { jobs: [] },
            })));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await openClawGatewayRequest('cron.list', {}, {
        url: `ws://127.0.0.1:${serverPort(server)}`,
        token: 'gateway-websocket-token',
        timeoutMs: 500,
      });

      assert.deepEqual(result, { jobs: [] });
      assert.equal(connectParams.auth.token, 'gateway-websocket-token');
    } finally {
      await closeServer(server);
    }
  });

  it('omits device auth instead of failing when OpenClaw identity keys are invalid', async () => {
    const stateDir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-bad-state-'));
    const identityDir = join(stateDir, 'identity');
    mkdirSync(identityDir, { recursive: true });
    writeFileSync(join(identityDir, 'device.json'), JSON.stringify({
      version: 1,
      deviceId: 'bad-device',
      publicKeyPem: 'not a public key',
      privateKeyPem: 'not a private key',
    }));
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_STATE_DIR = stateDir;
    let connectParams: any;

    const server = net.createServer((socket) => {
      let handshakeComplete = false;
      let buffer = Buffer.alloc(0);
      let clientRequests = 0;

      socket.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        if (!handshakeComplete) {
          const headerEnd = buffer.indexOf('\r\n\r\n');
          if (headerEnd === -1) return;
          const header = buffer.subarray(0, headerEnd + 4).toString('utf8');
          const key = /^Sec-WebSocket-Key:\s*(.+)$/im.exec(header)?.[1]?.trim();
          assert.ok(key);
          const accept = createHash('sha1')
            .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
            .digest('base64');
          socket.write([
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            `Sec-WebSocket-Accept: ${accept}`,
            '',
            '',
          ].join('\r\n'));
          handshakeComplete = true;
          buffer = buffer.subarray(headerEnd + 4);
          socket.write(encodeServerWebSocketFrame(JSON.stringify({
            type: 'event',
            event: 'connect.challenge',
            payload: { nonce: 'nonce-bad-identity' },
          })));
        }

        while (true) {
          const parsed = readClientWebSocketFrame(buffer);
          if (!parsed) break;
          buffer = parsed.rest;
          clientRequests += 1;
          const frame = JSON.parse(parsed.payload);
          if (clientRequests === 1) {
            connectParams = frame.params;
            socket.write(encodeServerWebSocketFrame(JSON.stringify({ type: 'res', id: frame.id, ok: true, payload: {} })));
          } else {
            socket.write(encodeServerWebSocketFrame(JSON.stringify({
              type: 'res',
              id: frame.id,
              ok: true,
              payload: { jobs: [] },
            })));
          }
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const result = await openClawGatewayRequest('cron.list', {}, {
        url: `ws://127.0.0.1:${serverPort(server)}`,
        timeoutMs: 500,
      });

      assert.deepEqual(result, { jobs: [] });
      assert.equal(connectParams.client.id, 'cli');
      assert.equal(connectParams.device, undefined);
    } finally {
      if (previousStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
      else process.env.OPENCLAW_STATE_DIR = previousStateDir;
      await closeServer(server);
    }
  });
});
