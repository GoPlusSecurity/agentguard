import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  installOpenClawThreatFeedCron,
  openClawGatewayRequest,
  validateCronExpression,
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
