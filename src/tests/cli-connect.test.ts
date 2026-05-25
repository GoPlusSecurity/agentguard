import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';

const projectRoot = resolve(__dirname, '..', '..');
const CLI_PATH = join(projectRoot, 'dist', 'cli.js');

function runCli(args: string[], home: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn('node', [CLI_PATH, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        AGENTGUARD_HOME: home,
        HOME: home,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString()));
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('close', (code) => {
      resolvePromise({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

describe('CLI connect Agent JWT mode', () => {
  it('registers a local agent and persists the Agent JWT when no API key is supplied', async () => {
    const requests: Array<{ url?: string; method?: string; body?: unknown }> = [];
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
      });
      req.on('end', () => {
        requests.push({ url: req.url, method: req.method, body: body ? JSON.parse(body) : undefined });
        if (req.method === 'POST' && req.url === '/api/agent/register') {
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({
            success: true,
            data: {
              agentId: 'agt_cli_test',
              jwt: 'agent.jwt.cli-test',
              registerUrl: 'https://agentguard.example/activate?token=cli-test',
            },
          }));
          return;
        }
        res.statusCode = 404;
        res.end(JSON.stringify({ success: false }));
      });
    });
    await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
    try {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const cloudUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-connect-'));
      writeFileSync(join(home, 'config.json'), JSON.stringify({
        version: 1,
        level: 'balanced',
        cloudUrl,
        agentHost: 'openclaw',
        agentHosts: ['openclaw'],
        policyCachePath: join(home, 'policy-cache.json'),
        auditPath: join(home, 'audit.jsonl'),
        eventSpoolPath: join(home, 'events-spool.jsonl'),
      }));

      const result = await runCli(['connect', '--url', cloudUrl], home);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /Registered local AgentGuard agent \(agt_cli_test\)/);
      assert.match(result.stdout, /https:\/\/agentguard\.example\/activate\?token=cli-test/);
      assert.equal(requests[0].url, '/api/agent/register');
      const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
        agentId?: string;
        agentJwt?: string;
        agentRegisterUrl?: string;
        cloudUrl?: string;
      };
      assert.equal(config.cloudUrl, cloudUrl);
      assert.equal(config.agentId, 'agt_cli_test');
      assert.equal(config.agentJwt, 'agent.jwt.cli-test');
      assert.equal(config.agentRegisterUrl, 'https://agentguard.example/activate?token=cli-test');
    } finally {
      await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
    }
  });

  it('reuses an active saved Agent JWT instead of registering again', async () => {
    const requests: Array<{ url?: string; method?: string; authorization?: string }> = [];
    const server = http.createServer((req, res) => {
      requests.push({ url: req.url, method: req.method, authorization: req.headers.authorization });
      if (req.method === 'GET' && req.url === '/api/v1/policies/effective') {
        assert.equal(req.headers.authorization, 'Bearer agent.jwt.active');
        const policy = getDefaultEffectiveRuntimePolicy();
        policy.policyVersion = 'active-jwt-policy';
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ success: true, data: policy }));
        return;
      }
      if (req.method === 'POST' && req.url === '/api/agent/register') {
        res.statusCode = 500;
        res.end(JSON.stringify({ success: false }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ success: false }));
    });
    await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
    try {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const cloudUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-connect-existing-'));
      writeFileSync(join(home, 'config.json'), JSON.stringify({
        version: 1,
        level: 'balanced',
        cloudUrl,
        agentHost: 'openclaw',
        agentHosts: ['openclaw'],
        agentId: 'agt_existing',
        agentJwt: 'agent.jwt.active',
        agentRegisterUrl: 'https://agentguard.example/activate?token=old',
        policyCachePath: join(home, 'policy-cache.json'),
        auditPath: join(home, 'audit.jsonl'),
        eventSpoolPath: join(home, 'events-spool.jsonl'),
      }));

      const result = await runCli(['connect', '--url', cloudUrl], home);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /Agent JWT is active for local agent agt_existing/);
      assert.equal(requests.filter((request) => request.url === '/api/agent/register').length, 0);
      const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
        agentId?: string;
        agentJwt?: string;
      };
      assert.equal(config.agentId, 'agt_existing');
      assert.equal(config.agentJwt, 'agent.jwt.active');
    } finally {
      await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
    }
  });

  it('re-registers a saved Agent JWT only after Cloud rejects it with 401', async () => {
    const requests: Array<{ url?: string; method?: string; authorization?: string }> = [];
    const server = http.createServer((req, res) => {
      requests.push({ url: req.url, method: req.method, authorization: req.headers.authorization });
      if (req.method === 'GET' && req.url === '/api/v1/policies/effective') {
        res.statusCode = 401;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ success: false, error: { message: 'inactive agent jwt' } }));
        return;
      }
      if (req.method === 'POST' && req.url === '/api/agent/register') {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          success: true,
          data: {
            agentId: 'agt_reissued',
            jwt: 'agent.jwt.reissued',
            registerUrl: 'https://agentguard.example/activate?token=reissued',
          },
        }));
        return;
      }
      res.statusCode = 404;
      res.end(JSON.stringify({ success: false }));
    });
    await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
    try {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const cloudUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-connect-reauth-'));
      writeFileSync(join(home, 'config.json'), JSON.stringify({
        version: 1,
        level: 'balanced',
        cloudUrl,
        agentHost: 'openclaw',
        agentHosts: ['openclaw'],
        agentId: 'agt_old',
        agentJwt: 'agent.jwt.old',
        policyCachePath: join(home, 'policy-cache.json'),
        auditPath: join(home, 'audit.jsonl'),
        eventSpoolPath: join(home, 'events-spool.jsonl'),
      }));

      const result = await runCli(['connect', '--url', cloudUrl], home);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /Registered local AgentGuard agent \(agt_reissued\)/);
      assert.equal(requests.filter((request) => request.url === '/api/agent/register').length, 1);
      const config = JSON.parse(readFileSync(join(home, 'config.json'), 'utf8')) as {
        agentId?: string;
        agentJwt?: string;
      };
      assert.equal(config.agentId, 'agt_reissued');
      assert.equal(config.agentJwt, 'agent.jwt.reissued');
    } finally {
      await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
    }
  });

  it('does not use Agent JWT registration before OpenClaw has been initialized', async () => {
    const home = mkdtempSync(join(tmpdir(), 'ag-cli-connect-no-openclaw-'));

    const result = await runCli(['connect', '--url', 'https://agentguard.example'], home);

    assert.equal(result.exitCode, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /init --agent openclaw/);
  });
});
