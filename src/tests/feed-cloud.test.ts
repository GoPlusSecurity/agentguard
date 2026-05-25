import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { AgentGuardCloudClient, CloudRequestError } from '../cloud/client.js';

type Handler = (req: any, res: any) => void;

function startServer(handler: Handler): Promise<{ url: string; server: Server }> {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, server });
    });
  });
}

describe('cloud client — feed methods', () => {
  let baseUrl: string;
  let server: Server;
  let lastRequest: { url: string; method: string; headers: Record<string, string | string[] | undefined>; body?: unknown } | null = null;
  let nextResponse: { status: number; body: unknown } = { status: 200, body: {} };

  before(async () => {
    const started = await startServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const raw = Buffer.concat(chunks).toString('utf8');
      lastRequest = { url: req.url, method: req.method, headers: req.headers, body: raw ? JSON.parse(raw) : undefined };
      res.statusCode = nextResponse.status;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(nextResponse.body));
    });
    baseUrl = started.url;
    server = started.server;
  });

  after(() => {
    server.close();
  });

  it('status accepts the public bare status response', async () => {
    nextResponse = {
      status: 200,
      body: {
        ok: true,
        service: 'AgentGuard API',
        version: '1.0.0',
        detectors: 8,
      },
    };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl });
    const result = await client.status();
    assert.equal(result.ok, true);
    assert.equal(result.service, 'AgentGuard API');
    assert.equal(result.version, '1.0.0');
  });

  it('pullAdvisories returns advisories on 200', async () => {
    nextResponse = {
      status: 200,
      body: {
        success: true,
        data: {
          advisories: [
            {
              id: 'AGS-2026-1',
              ecosystem: 'skill',
              severity: 'high',
              summary: 's',
              detailsMd: '',
              affected: [{ namePattern: 'foo' }],
              publishedAt: '2026-05-13T00:00:00Z',
            },
          ],
        },
      },
    };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    const result = await client.pullAdvisories('2026-05-12T00:00:00Z');
    assert.equal(result?.length, 1);
    assert.equal(result?.[0].id, 'AGS-2026-1');
    assert.match(lastRequest!.url, /\/api\/v1\/feed\/advisories\?since=/);
    assert.equal(lastRequest!.headers['x-api-key'], 'ag_live_x');
  });

  it('uses Agent JWT bearer auth before legacy API keys', async () => {
    nextResponse = {
      status: 200,
      body: {
        success: true,
        data: {
          advisories: [],
        },
      },
    };
    const client = new AgentGuardCloudClient({
      cloudUrl: baseUrl,
      apiKey: 'ag_live_x',
      agentJwt: 'agent.jwt.test',
    });
    const result = await client.pullAdvisories();
    assert.deepEqual(result, []);
    assert.equal(lastRequest!.headers.authorization, 'Bearer agent.jwt.test');
    assert.equal(lastRequest!.headers['x-api-key'], undefined);
  });

  it('registerAgent POSTs metadata and returns the activation payload', async () => {
    nextResponse = {
      status: 200,
      body: {
        success: true,
        data: {
          agentId: 'agt_test',
          jwt: 'agent.jwt.created',
          registerUrl: 'https://agentguard.example/activate?token=test',
        },
      },
    };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl });
    const result = await client.registerAgent({ metadata: { agentHost: 'openclaw' } });
    assert.equal(lastRequest!.method, 'POST');
    assert.match(lastRequest!.url, /\/api\/agent\/register$/);
    assert.deepEqual(lastRequest!.body, { metadata: { agentHost: 'openclaw' } });
    assert.deepEqual(result, {
      agentId: 'agt_test',
      jwt: 'agent.jwt.created',
      registerUrl: 'https://agentguard.example/activate?token=test',
    });
  });

  it('pullAdvisories returns null on 404 (older Cloud)', async () => {
    nextResponse = { status: 404, body: { success: false, error: { message: 'Not found' } } };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    const result = await client.pullAdvisories();
    assert.equal(result, null);
  });

  it('pullAdvisories throws on other errors', async () => {
    nextResponse = {
      status: 500,
      body: {
        success: false,
        error: { code: 'CLOUD_DOWN', message: 'boom', details: { retry: true } },
        meta: { requestId: 'req_test' },
      },
    };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    await assert.rejects(
      () => client.pullAdvisories(),
      (err: unknown) =>
        err instanceof CloudRequestError &&
        err.status === 500 &&
        err.code === 'CLOUD_DOWN' &&
        err.message.includes('boom') &&
        err.requestId === 'req_test'
    );
  });

  it('getAdvisory fetches a single advisory by id', async () => {
    nextResponse = {
      status: 200,
      body: {
        success: true,
        data: {
          id: 'AGS-2026-0042',
          ecosystem: 'url',
          severity: 'critical',
          summary: 'bad url',
          detailsMd: '',
          affected: [{ domainExact: 'evil.example' }],
          publishedAt: '2026-05-13T00:00:00Z',
        },
      },
    };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    const result = await client.getAdvisory('AGS-2026-0042');
    assert.equal(result?.id, 'AGS-2026-0042');
    assert.equal(result?.ecosystem, 'url');
    assert.match(lastRequest!.url, /\/api\/v1\/feed\/advisories\/AGS-2026-0042$/);
  });

  it('getAdvisory returns null on 404', async () => {
    nextResponse = { status: 404, body: { success: false, error: { message: 'not found' } } };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    const result = await client.getAdvisory('AGS-missing');
    assert.equal(result, null);
  });

  it('reportSelfCheck POSTs the advisoryId + matches', async () => {
    nextResponse = { status: 200, body: { success: true, data: {} } };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    await client.reportSelfCheck(
      'AGS-2026-1',
      [{ path: '/tmp/skills/bad', matchedBy: 'namePattern' }],
      { elapsedMs: 12 }
    );
    assert.equal(lastRequest!.method, 'POST');
    assert.match(lastRequest!.url, /\/api\/v1\/feed\/self-check-report$/);
    assert.equal((lastRequest!.body as any).advisoryId, 'AGS-2026-1');
    assert.equal((lastRequest!.body as any).matches.length, 1);
  });

  it('reportSelfCheck swallows 404 silently', async () => {
    nextResponse = { status: 404, body: { success: false, error: { message: 'no sink yet' } } };
    const client = new AgentGuardCloudClient({ cloudUrl: baseUrl, apiKey: 'ag_live_x' });
    await assert.doesNotReject(() =>
      client.reportSelfCheck('AGS-x', [{ path: '/tmp/x', matchedBy: 'sha256' }])
    );
  });
});
