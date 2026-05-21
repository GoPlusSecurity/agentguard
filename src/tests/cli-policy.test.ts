import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';

const execFileAsync = promisify(execFile);

describe('policy CLI', () => {
  it('shows the cached effective policy as JSON', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-policy-show-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.policyVersion = 'runtime-show-cache';
    policy.mode = 'strict';
    policy.blockedCommandPatterns = ['show-cache-danger'];
    const cachePath = join(home, 'policy-cache.json');
    writeFileSync(join(home, 'config.json'), JSON.stringify({
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      policyCachePath: cachePath,
      auditPath: join(home, 'audit.jsonl'),
      eventSpoolPath: join(home, 'events-spool.jsonl'),
    }));
    writeFileSync(cachePath, JSON.stringify(policy));

    const cliPath = resolve('dist/cli.js');
    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'policy', 'show', '--json'], {
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const result = JSON.parse(stdout) as {
      success: boolean;
      source: string;
      cachePath: string;
      policy: typeof policy;
    };
    assert.equal(result.success, true);
    assert.equal(result.source, 'cache');
    assert.equal(result.cachePath, cachePath);
    assert.equal(result.policy.policyVersion, 'runtime-show-cache');
    assert.deepEqual(result.policy.blockedCommandPatterns, ['show-cache-danger']);
  });

  it('shows the bundled default policy when no cache exists', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-policy-show-default-'));
    const cachePath = join(home, 'policy-cache.json');
    writeFileSync(join(home, 'config.json'), JSON.stringify({
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      policyCachePath: cachePath,
      auditPath: join(home, 'audit.jsonl'),
      eventSpoolPath: join(home, 'events-spool.jsonl'),
    }));

    const cliPath = resolve('dist/cli.js');
    const { stdout } = await execFileAsync(process.execPath, [cliPath, 'policy', 'show', '--json'], {
      env: { ...process.env, AGENTGUARD_HOME: home },
    });

    const result = JSON.parse(stdout) as {
      success: boolean;
      source: string;
      policy: { policyVersion: string };
    };
    assert.equal(result.success, true);
    assert.equal(result.source, 'default');
    assert.equal(result.policy.policyVersion, 'runtime-local-v0.1');
  });

  it('pulls the effective Cloud policy into the local cache', async () => {
    const home = mkdtempSync(join(tmpdir(), 'agentguard-policy-cli-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.policyVersion = 'runtime-cli-test';
    policy.blockedCommandPatterns = ['cli-policy-danger'];
    policy.updatedAt = '2026-05-18T00:00:00.000Z';

    const server = createServer((req, res) => {
      if (req.url === '/api/v1/policies/effective' && req.headers['x-api-key'] === 'ag_live_test_key_123456') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ success: true, data: policy }));
        return;
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: { message: 'not found' } }));
    });

    await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
    try {
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const cloudUrl = `http://127.0.0.1:${address.port}`;
      const cachePath = join(home, 'policy-cache.json');
      writeFileSync(join(home, 'config.json'), JSON.stringify({
        version: 1,
        level: 'balanced',
        cloudUrl,
        apiKey: 'ag_live_test_key_123456',
        policyCachePath: cachePath,
        auditPath: join(home, 'audit.jsonl'),
        eventSpoolPath: join(home, 'events-spool.jsonl'),
      }));

      const cliPath = resolve('dist/cli.js');
      const { stdout } = await execFileAsync(process.execPath, [cliPath, 'policy', 'pull', '--json'], {
        env: { ...process.env, AGENTGUARD_HOME: home },
      });

      const result = JSON.parse(stdout) as { success: boolean; policyVersion: string; cachePath: string };
      assert.equal(result.success, true);
      assert.equal(result.policyVersion, 'runtime-cli-test');
      assert.equal(result.cachePath, cachePath);
      const cached = JSON.parse(readFileSync(cachePath, 'utf8')) as typeof policy;
      assert.equal(cached.policyVersion, 'runtime-cli-test');
      assert.deepEqual(cached.blockedCommandPatterns, ['cli-policy-danger']);
    } finally {
      await new Promise<void>((resolvePromise, reject) => {
        server.close((err) => err ? reject(err) : resolvePromise());
      });
    }
  });
});
