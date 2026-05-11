import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { evaluateLocalAction } from '../runtime/evaluator.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { redactText } from '../runtime/redaction.js';
import { flushEventSpool, spoolEvent } from '../runtime/audit.js';
import { protectAction } from '../runtime/protect.js';
import type { AgentGuardConfig } from '../config.js';
import type { RuntimeAuditEvent } from '../runtime/types.js';

describe('Runtime Cloud bridge', () => {
  it('redacts API keys, bearer tokens, private keys, and URL secrets', () => {
    const privateKey = '-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----';
    const redacted = redactText(
      `Authorization: Bearer sk-test-secret-value url=https://api.example.com?a=1&token=secret-value ${privateKey}`
    );

    assert.ok(redacted.includes('[REDACTED]'));
    assert.ok(!redacted.includes('sk-test-secret-value'));
    assert.ok(!redacted.includes('secret-value'));
    assert.ok(!redacted.includes('abc123'));
  });

  it('evaluates local action with cached Cloud policy shape', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.policyVersion = 'runtime-test';
    policy.blockedCommandPatterns = ['custom-danger'];

    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'codex',
      actionType: 'shell',
      toolName: 'Bash',
      input: 'custom-danger --token=secret-value',
    });

    assert.equal(decision.decision, 'block');
    assert.equal(decision.policyVersion, 'runtime-test');
    assert.ok(JSON.stringify(decision).includes('[REDACTED]') || !JSON.stringify(decision).includes('secret-value'));
  });

  it('keeps spooled audit events when Cloud ingest fails', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-spool-'));
    const spool = join(dir, 'events.jsonl');
    const event = sampleEvent();

    spoolEvent(spool, event);
    const result = await flushEventSpool(spool, async () => {
      throw new Error('network down');
    });

    assert.deepEqual(result, { flushed: 0, remaining: 1 });
    assert.ok(readFileSync(spool, 'utf8').includes('act_test'));
  });

  it('flushes spooled audit events when Cloud ingest succeeds', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-spool-ok-'));
    const spool = join(dir, 'events.jsonl');
    const event = sampleEvent();
    const batches: RuntimeAuditEvent[][] = [];

    spoolEvent(spool, event);
    const result = await flushEventSpool(spool, async (events) => {
      batches.push(events);
    });

    assert.deepEqual(result, { flushed: 1, remaining: 0 });
    assert.equal(batches[0][0].actionId, 'act_test');
  });

  it('protectAction falls back to cached policy and writes local audit', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-protect-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.blockedCommandPatterns = ['cached-danger'];

    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      cloudUrl: 'http://127.0.0.1:9',
      apiKey: 'ag_live_test_key',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(policy));

    const result = await protectAction({
      config,
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'cached-danger --api_key=secret-value' },
        session_id: 'sess_test',
      }),
    });

    assert.ok(result);
    assert.equal(result?.decision.decision, 'block');
    const audit = readFileSync(config.auditPath, 'utf8');
    assert.ok(audit.includes('[REDACTED]'));
    assert.ok(!audit.includes('secret-value'));
  });

  it('syncs redacted audit events and creates Cloud approval on require_approval', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-cloud-ok-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.protectedPaths = ['/workspace/.env'];
    policy.decisions.secretAccess = 'require_approval';
    const requests: Array<{ url: string; body?: string }> = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, body: typeof init?.body === 'string' ? init.body : undefined });
      if (url.endsWith('/api/v1/policies/effective')) {
        return jsonResponse({ success: true, data: policy });
      }
      if (url.endsWith('/api/v1/events/ingest')) {
        return jsonResponse({ success: true, data: { accepted: 1, rejected: 0 } }, 202);
      }
      if (url.endsWith('/api/v1/approvals')) {
        return jsonResponse({
          success: true,
          data: {
            approvalId: 'apr_test',
            actionId: 'act_test',
            sessionId: 'sess_test',
            status: 'pending',
          },
        }, 202);
      }
      return jsonResponse({ success: false, error: { message: 'not found' } }, 404);
    }) as typeof fetch;

    try {
      const config: AgentGuardConfig = {
        version: 1,
        level: 'balanced',
        cloudUrl: 'https://agentguard.example',
        apiKey: 'ag_live_test_key',
        policyCachePath: join(dir, 'policy.json'),
        auditPath: join(dir, 'audit.jsonl'),
        eventSpoolPath: join(dir, 'spool.jsonl'),
      };

      const result = await protectAction({
        config,
        stdinText: JSON.stringify({
          tool_name: 'Read',
          tool_input: { file_path: '/workspace/.env?token=secret-value' },
          session_id: 'sess_test',
        }),
      });

      assert.equal(result?.decision.decision, 'require_approval');
      assert.equal(result?.approvalId, 'apr_test');
      assert.ok(requests.some((request) => request.url.endsWith('/api/v1/events/ingest')));
      assert.ok(requests.some((request) => request.url.endsWith('/api/v1/approvals')));
      assert.ok(!requests.map((request) => request.body || '').join('\n').includes('secret-value'));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

function sampleEvent(): RuntimeAuditEvent {
  return {
    actionId: 'act_test',
    sessionId: 'sess_test',
    agentHost: 'codex',
    actionType: 'shell',
    toolName: 'Bash',
    input: 'echo ok',
    decision: 'allow',
    riskScore: 0,
    riskLevel: 'safe',
    reasons: [],
    policyVersion: 'runtime-test',
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
