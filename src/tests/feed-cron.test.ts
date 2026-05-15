import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  installOpenClawThreatFeedCron,
  openClawGatewayRequest,
  parseIntervalMinutes,
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
  it('parseIntervalMinutes rejects non-numeric and out-of-range values', () => {
    assert.equal(parseIntervalMinutes('15'), 15);
    assert.throws(() => parseIntervalMinutes('5abc'), /Invalid --interval-minutes/);
    assert.throws(() => parseIntervalMinutes('0'), /Invalid --interval-minutes/);
    assert.throws(() => parseIntervalMinutes('60'), /Invalid --interval-minutes/);
  });

  it('adds an OpenClaw cron job with silent delivery and interval schedule', async () => {
    const gateway = fakeGateway();

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', intervalMinutes: 15, force: false },
      { request: gateway.request }
    );

    assert.equal(result.created, true);
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.add']);
    const job = gateway.calls[1].params[0];
    assert.equal(job.name, 'agentguard-threat-feed');
    assert.deepEqual(job.schedule, { kind: 'every', everyMs: 900000 });
    assert.deepEqual(job.delivery, { mode: 'none' });
    assert.equal(job.sessionTarget, 'isolated');
    assert.equal(job.payload.kind, 'agentTurn');
    assert.match(job.payload.message, /hardFailures/);
    assert.equal('timezone' in job, false);
  });

  it('leaves an existing cron job untouched unless force is set', async () => {
    const gateway = fakeGateway([{ id: 'job-1', name: 'agentguard-threat-feed' }]);

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', intervalMinutes: 15, force: false },
      { request: gateway.request }
    );

    assert.equal(result.created, false);
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list']);
  });

  it('removes an existing cron job by jobId when force is set', async () => {
    const gateway = fakeGateway([{ id: 'job-1', name: 'agentguard-threat-feed' }]);

    const result = await installOpenClawThreatFeedCron(
      { name: 'agentguard-threat-feed', intervalMinutes: 5, force: true },
      { request: gateway.request }
    );

    assert.equal(result.created, true);
    assert.deepEqual(gateway.calls.map((call) => call.method), ['cron.list', 'cron.remove', 'cron.add']);
    assert.deepEqual(gateway.calls[1].params, { jobId: 'job-1' });
    assert.deepEqual(gateway.calls[2].params[0].schedule, { kind: 'every', everyMs: 300000 });
  });

  it('does not add a replacement if force removal fails', async () => {
    const calls: RpcCall[] = [];
    await assert.rejects(
      () =>
        installOpenClawThreatFeedCron(
          { name: 'agentguard-threat-feed', intervalMinutes: 5, force: true },
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
