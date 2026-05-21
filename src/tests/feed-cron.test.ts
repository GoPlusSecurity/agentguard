import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  installThreatFeedCron,
  installOpenClawThreatFeedCron,
  openClawGatewayRequest,
  validateCronExpression,
  type CommandRunner,
} from '../feed/cron.js';

type RpcCall = { method: string; params: any };

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

describe('feed/cron', () => {
  it('validateCronExpression rejects non-five-field values', () => {
    assert.equal(validateCronExpression('0 * * * *'), '0 * * * *');
    assert.equal(validateCronExpression('  */5   * * * *  '), '*/5 * * * *');
    assert.throws(() => validateCronExpression('0 * * *'), /Invalid --cron/);
    assert.throws(() => validateCronExpression('0 * * * * *'), /Invalid --cron/);
  });

  it('adds an OpenClaw cron job with silent delivery and cron schedule', async () => {
    const gateway = fakeGateway();

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', cronExpression: '0 * * * *', quiet: false, force: false, timezone: 'Asia/Shanghai' },
      { request: gateway.request }
    );

    assert.equal(result.created, true);
    assert.equal(result.schedule, '0 * * * *');
    assert.equal(result.timezone, 'Asia/Shanghai');
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.add']);
    const job = gateway.calls[1].params[0];
    assert.equal(job.name, 'agentguard-threat-feed');
    assert.deepEqual(job.schedule, { kind: 'cron', expr: '0 * * * *', tz: 'Asia/Shanghai' });
    assert.deepEqual(job.delivery, { mode: 'none' });
    assert.equal(job.sessionTarget, 'isolated');
    assert.equal(job.payload.kind, 'agentTurn');
    assert.deepEqual(job.payload.agentguard, {
      mode: 'manual',
      command: 'agentguard subscribe --json --cron-run',
    });
    assert.match(job.payload.message, /Mode: manual/);
    assert.match(job.payload.message, /Command: `agentguard subscribe --json --cron-run`/);
    assert.match(job.payload.message, /agentguard subscribe --json --cron-run/);
    assert.match(job.payload.message, /hardFailures/);
  });

  it('auto-installs system crontab jobs for Codex and Claude Code agents', async () => {
    const calls: Array<{ command: string; args: string[]; input?: string }> = [];
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
        agentGuardHome: '/tmp/ag-home',
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
    assert.match(calls[1].input ?? '', /agentguard subscribe --quiet --json --cron-run/);
    assert.match(calls[1].input ?? '', /AGENTGUARD_HOME="\/tmp\/ag-home"/);
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
    assert.deepEqual(gateway.calls[2].params[0].schedule, { kind: 'cron', expr: '*/5 * * * *', tz: 'UTC' });
    assert.deepEqual(gateway.calls[2].params[0].payload.agentguard, {
      mode: 'quiet',
      command: 'agentguard subscribe --quiet --json --cron-run',
    });
    assert.match(gateway.calls[2].params[0].payload.message, /Mode: quiet/);
    assert.match(gateway.calls[2].params[0].payload.message, /Command: `agentguard subscribe --quiet --json --cron-run`/);
    assert.match(gateway.calls[2].params[0].payload.message, /agentguard subscribe --quiet --json --cron-run/);
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
});
