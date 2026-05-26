import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { evaluateLocalAction } from '../runtime/evaluator.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { redactText } from '../runtime/redaction.js';
import { flushEventSpool, spoolEvent } from '../runtime/audit.js';
import { exitCodeForDecision, formatProtectResult, protectAction } from '../runtime/protect.js';
import type { ProtectResult } from '../runtime/protect.js';
import { connectAgentJwt, connectCloud, disconnectCloud, getAgentGuardPaths } from '../config.js';
import { AgentGuardCloudClient } from '../cloud/client.js';
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

  it('requires approval for shell commands reading SSH keys by absolute home path', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const sshPublicKeyPath = `${homedir()}/.ssh/id_ed25519.pub`;
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'shell',
      toolName: 'exec',
      input: `cat ${sshPublicKeyPath}`,
    });

    assert.equal(decision.decision, 'require_approval');
    assert.ok(decision.reasons.some((reason) => reason.code === 'SECRET_ACCESS'));
  });

  it('matches protected paths against absolute home paths for file reads', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const sshPublicKeyPath = `${homedir()}/.ssh/id_ed25519.pub`;
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'file_read',
      toolName: 'read',
      input: sshPublicKeyPath,
    });

    assert.equal(decision.decision, 'require_approval');
    assert.ok(decision.reasons.some((reason) => reason.code === 'SECRET_ACCESS'));
  });

  it('rejects malformed keys and non-HTTPS Cloud URLs', () => {
    const previousHome = process.env.AGENTGUARD_HOME;
    process.env.AGENTGUARD_HOME = mkdtempSync(join(tmpdir(), 'agentguard-config-'));
    try {
      assert.throws(
        () => connectCloud({ apiKey: 'not-a-key', cloudUrl: 'https://agentguard.example' }),
        /Invalid AgentGuard API key format/
      );
      // Loopback http:// is now allowed (needed for local dev + tests). Test
      // the rejection on a non-loopback http URL instead.
      assert.throws(
        () => connectCloud({ apiKey: 'ag_live_test_key_123456', cloudUrl: 'http://agentguard.example' }),
        /must use https/
      );
      const config = connectCloud({
        apiKey: 'ag_live_test_key_123456',
        cloudUrl: 'https://agentguard.example',
      });
      assert.equal(config.cloudUrl, 'https://agentguard.example');
      assert.equal(statSync(getAgentGuardPaths().configPath).mode & 0o777, 0o600);
      assert.throws(
        () => new AgentGuardCloudClient({ cloudUrl: 'http://agentguard.example', apiKey: 'ag_live_test_key_123456' }),
        /must use https/
      );
      // Loopback http:// should construct fine — confirms the new exception.
      assert.doesNotThrow(
        () => new AgentGuardCloudClient({ cloudUrl: 'http://127.0.0.1:9', apiKey: 'ag_live_test_key_123456' })
      );
    } finally {
      if (previousHome === undefined) delete process.env.AGENTGUARD_HOME;
      else process.env.AGENTGUARD_HOME = previousHome;
    }
  });

  it('disconnects Cloud without deleting the local audit log', () => {
    const previousHome = process.env.AGENTGUARD_HOME;
    process.env.AGENTGUARD_HOME = mkdtempSync(join(tmpdir(), 'agentguard-disconnect-'));
    try {
      const config = connectCloud({
        apiKey: 'ag_live_test_key_123456',
        cloudUrl: 'https://agentguard.example',
      });
      connectAgentJwt({
        agentId: 'agt_disconnect_test',
        agentJwt: 'agent.jwt.disconnect',
        agentRegisterUrl: 'https://agentguard.example/activate?token=test',
        cloudUrl: 'https://agentguard.example',
      });
      writeFileSync(config.eventSpoolPath, `${JSON.stringify(sampleEvent())}\n`);
      writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
      writeFileSync(config.auditPath, `${JSON.stringify(sampleEvent())}\n`);

      const disconnected = disconnectCloud();
      const saved = JSON.parse(readFileSync(getAgentGuardPaths().configPath, 'utf8')) as AgentGuardConfig;

      assert.equal(disconnected.apiKey, undefined);
      assert.equal(disconnected.agentId, undefined);
      assert.equal(disconnected.agentJwt, undefined);
      assert.equal(disconnected.agentRegisterUrl, undefined);
      assert.equal(disconnected.connectedAt, undefined);
      assert.equal(disconnected.cloudUrl, 'https://agentguard.example');
      assert.equal(saved.apiKey, undefined);
      assert.equal(saved.agentId, undefined);
      assert.equal(saved.agentJwt, undefined);
      assert.equal(saved.agentRegisterUrl, undefined);
      assert.equal(saved.connectedAt, undefined);
      assert.equal(saved.cloudUrl, 'https://agentguard.example');
      assert.equal(existsSync(config.eventSpoolPath), false);
      assert.equal(existsSync(config.policyCachePath), false);
      assert.equal(existsSync(config.auditPath), true);
    } finally {
      if (previousHome === undefined) delete process.env.AGENTGUARD_HOME;
      else process.env.AGENTGUARD_HOME = previousHome;
    }
  });

  it('clears Agent JWT credentials when connecting with an explicit API key', () => {
    const previousHome = process.env.AGENTGUARD_HOME;
    process.env.AGENTGUARD_HOME = mkdtempSync(join(tmpdir(), 'agentguard-connect-key-'));
    try {
      connectAgentJwt({
        agentId: 'agt_key_shadow_test',
        agentJwt: 'agent.jwt.shadow',
        agentRegisterUrl: 'https://agentguard.example/activate?token=shadow',
        cloudUrl: 'https://agentguard.example',
      });

      const config = connectCloud({
        apiKey: 'ag_live_test_key_123456',
        cloudUrl: 'https://agentguard.example',
      });

      assert.equal(config.apiKey, 'ag_live_test_key_123456');
      assert.equal(config.agentId, undefined);
      assert.equal(config.agentJwt, undefined);
      assert.equal(config.agentRegisterUrl, undefined);
      assert.equal(config.agentRegisteredAt, undefined);
    } finally {
      if (previousHome === undefined) delete process.env.AGENTGUARD_HOME;
      else process.env.AGENTGUARD_HOME = previousHome;
    }
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
    const spoolContent = readFileSync(spool, 'utf8');
    assert.ok(spoolContent.includes('act_test'));
    assert.ok(!spoolContent.includes('metadata-secret'));
    assert.ok(!spoolContent.includes('cwd-secret'));
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
      cloudUrl: 'https://127.0.0.1:9',
      apiKey: 'ag_live_test_key_123456',
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

  it('protectAction still returns policy decision when local audit write fails', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-audit-fail-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.blockedCommandPatterns = ['cached-danger'];

    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://127.0.0.1:9',
      apiKey: 'ag_live_test_key_123456',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: dir,
      eventSpoolPath: join(dir, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(policy));

    const result = await protectAction({
      config,
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'cached-danger' },
        session_id: 'sess_test',
      }),
    });

    assert.equal(result?.decision.decision, 'block');
  });

  it('syncs redacted audit events and uses agent approval by default on require_approval', async () => {
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
      return jsonResponse({ success: false, error: { message: 'not found' } }, 404);
    }) as typeof fetch;

    try {
      const config: AgentGuardConfig = {
        version: 1,
        level: 'balanced',
        cloudUrl: 'https://agentguard.example',
        apiKey: 'ag_live_test_key_123456',
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
          sourceSkill: 'skill?api_key=secret-value',
          metadata: { nested: { token: 'secret-value' } },
        }),
      });

      assert.equal(result?.decision.decision, 'require_approval');
      assert.equal(result?.approvalChannel, 'agent');
      assert.ok(requests.some((request) => request.url.endsWith('/api/v1/events/ingest')));
      assert.equal(requests.some((request) => request.url.endsWith('/api/v1/approvals')), false);
      assert.ok(!requests.map((request) => request.body || '').join('\n').includes('secret-value'));
      assert.ok(requests.map((request) => request.body || '').join('\n').includes('[REDACTED]'));
      assert.equal(exitCodeForDecision(result!.decision, result!), 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('formats Claude Code agent approval as a PreToolUse ask response', () => {
    const result: ProtectResult = {
      policySource: 'cloud',
      approvalChannel: 'agent',
      event: { ...sampleEvent(), agentHost: 'claude-code' as const },
      decision: {
        actionId: 'act_confirm',
        decision: 'require_approval' as const,
        riskScore: 70,
        riskLevel: 'high' as const,
        policyVersion: 'runtime-test',
        reasons: [
          {
            code: 'SECRET_ACCESS',
            severity: 'high' as const,
            title: 'Protected path',
            description: 'Protected path access requires approval.',
          },
        ],
      },
    };

    const formatted = JSON.parse(formatProtectResult(result, false));
    assert.equal(formatted.hookSpecificOutput.permissionDecision, 'ask');
    assert.match(formatted.hookSpecificOutput.permissionDecisionReason, /Protected path/);
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
    cwd: '/tmp/project?token=cwd-secret',
    sourceSkill: 'skill?api_key=source-secret',
    metadata: { token: 'metadata-secret', nested: { authorization: 'Bearer metadata-secret' } },
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
