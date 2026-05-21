import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Advisory } from '../feed/types.js';

const projectRoot = resolve(__dirname, '..', '..');
const CLI_PATH = join(projectRoot, 'dist', 'cli.js');

function runCli(args: string[], home: string, cloudUrl: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  writeConfig(home, cloudUrl);
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

function writeConfig(home: string, cloudUrl: string): void {
  mkdirSync(home, { recursive: true });
  writeFileSync(join(home, 'config.json'), JSON.stringify({
    version: 1,
    level: 'balanced',
    cloudUrl,
    apiKey: 'ag_live_test_key_123456',
    policyCachePath: join(home, 'policy-cache.json'),
    auditPath: join(home, 'audit.jsonl'),
    eventSpoolPath: join(home, 'events-spool.jsonl'),
  }));
}

function installMatchingSkill(home: string): void {
  const skillDir = join(home, '.claude', 'skills', 'malicious-demo');
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(join(skillDir, 'SKILL.md'), '# malicious-demo\n');
}

async function withFeedServer<T>(
  advisories: Advisory[],
  fn: (url: string, reports: unknown[]) => Promise<T>
): Promise<T> {
  const reports: unknown[] = [];
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url?.startsWith('/api/v1/feed/advisories')) {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ success: true, data: { advisories } }));
      return;
    }
    if (req.method === 'POST' && req.url === '/api/v1/feed/self-check-report') {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString();
      });
      req.on('end', () => {
        reports.push(JSON.parse(body));
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ success: true, data: { ok: true } }));
      });
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ success: false }));
  });
  await new Promise<void>((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const port = (address as AddressInfo).port;
  const url = `http://127.0.0.1:${port}`;
  try {
    return await fn(url, reports);
  } finally {
    await new Promise<void>((resolvePromise) => server.close(() => resolvePromise()));
  }
}

const advisory: Advisory = {
  id: 'AGS-2026-subscribe',
  ecosystem: 'skill',
  severity: 'high',
  summary: 'Demo malicious skill',
  detailsMd: 'Demo advisory',
  affected: [{ namePattern: 'malicious-*' }],
  publishedAt: '2026-05-20T00:00:00.000Z',
};

describe('CLI subscribe command modes', () => {
  it('without --quiet notifies about new advisories without reporting self-check matches', async () => {
    await withFeedServer([advisory], async (cloudUrl, reports) => {
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-subscribe-'));
      installMatchingSkill(home);

      const result = await runCli(['subscribe'], home, cloudUrl);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /New threat-feed advisories found/);
      assert.match(result.stdout, /AGS-2026-subscribe/);
      assert.doesNotMatch(result.stdout, /Self-check found/);
      assert.equal(reports.length, 0);
    });
  });

  it('--quiet runs self-checks and reports local matches', async () => {
    await withFeedServer([advisory], async (cloudUrl, reports) => {
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-subscribe-'));
      installMatchingSkill(home);

      const result = await runCli(['subscribe', '--quiet'], home, cloudUrl);

      assert.equal(result.exitCode, 2);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /Self-check found 1 match/);
      assert.equal(reports.length, 1);
      assert.deepEqual((reports[0] as { advisoryId: string }).advisoryId, 'AGS-2026-subscribe');
    });
  });

  it('--cron-notify-run prints only the manual notification body when new advisories exist', async () => {
    await withFeedServer([advisory], async (cloudUrl) => {
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-subscribe-'));

      const result = await runCli(['subscribe', '--cron-notify-run'], home, cloudUrl);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /^AgentGuard found new threat-feed advisories/m);
      assert.match(result.stdout, /AGS-2026-subscribe/);
      assert.doesNotMatch(result.stdout, /Pulled \d+ advisory/);
    });
  });

  it('--cron-notify-run prints NO_REPLY when nothing should notify', async () => {
    await withFeedServer([], async (cloudUrl) => {
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-subscribe-'));

      const result = await runCli(['subscribe', '--cron-notify-run'], home, cloudUrl);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.equal(result.stdout, 'NO_REPLY\n');
    });
  });

  it('--quiet --cron-notify-run prints only the match notification body and exits zero', async () => {
    await withFeedServer([advisory], async (cloudUrl, reports) => {
      const home = mkdtempSync(join(tmpdir(), 'ag-cli-subscribe-'));
      installMatchingSkill(home);

      const result = await runCli(['subscribe', '--quiet', '--cron-notify-run'], home, cloudUrl);

      assert.equal(result.exitCode, 0);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /^AgentGuard threat-feed self-check found local matches:/m);
      assert.match(result.stdout, /AGS-2026-subscribe: 1 match/);
      assert.doesNotMatch(result.stdout, /Self-check found/);
      assert.equal(reports.length, 1);
    });
  });
});
