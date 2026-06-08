import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  installThreatFeedCron,
  installOpenClawThreatFeedCron,
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
  it('validateCronExpression rejects non-five-field values', () => {
    assert.equal(validateCronExpression('0 * * * *'), '0 * * * *');
    assert.equal(validateCronExpression('  */5   * * * *  '), '*/5 * * * *');
    assert.throws(() => validateCronExpression('0 * * *'), /Invalid --cron/);
    assert.throws(() => validateCronExpression('0 * * * * *'), /Invalid --cron/);
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

  it('auto-installs system crontab jobs for Codex and Claude Code agents', async () => {
    const calls: Array<{ command: string; args: string[]; input?: string }> = [];
    const home = mkdtempSync(join(tmpdir(), 'agentguard-system-'));
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
        agentHost: 'codex',
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
