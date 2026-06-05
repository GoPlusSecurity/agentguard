import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { evaluateLocalAction } from '../runtime/evaluator.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { redactText } from '../runtime/redaction.js';
import { flushEventSpool, spoolEvent } from '../runtime/audit.js';
import { actionFingerprint, approvePendingApproval, cleanupExpiredApprovals, listPendingApprovals } from '../runtime/approvals.js';
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

  it('allows ordinary web search queries without treating them as URLs', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'web_search',
      toolName: 'web_search',
      input: 'MiniMax model list 2026',
    });

    assert.equal(decision.decision, 'allow');
    assert.equal(decision.riskLevel, 'safe');
    assert.equal(decision.reasons.length, 0);
  });

  it('warns but does not require approval for ordinary GET web fetches', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'https://example.com/models',
      metadata: { method: 'GET' },
    });

    assert.equal(decision.decision, 'warn');
    assert.ok(decision.reasons.some((reason) => reason.code === 'NETWORK_OUTBOUND'));
    assert.ok(!decision.reasons.some((reason) => reason.code === 'NETWORK_RISK'));
  });

  it('requires approval for DELETE network requests', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'https://api.example.com/models/1',
      metadata: { method: 'DELETE' },
    });

    assert.equal(decision.decision, 'require_approval');
    assert.ok(decision.reasons.some((reason) => reason.code === 'DESTRUCTIVE_HTTP_METHOD'));
  });

  it('enforces defaultOutbound block for direct network fetches', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.network.defaultOutbound = 'block';
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'https://example.com/models',
      metadata: { method: 'GET' },
    });

    assert.equal(decision.decision, 'block');
    assert.ok(decision.reasons.some((reason) => reason.code === 'NETWORK_OUTBOUND'));
  });

  it('enforces blocked domains for direct network fetches', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.network.blockedDomains = ['example.com/models'];
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'https://example.com/models/latest',
      metadata: { method: 'GET' },
    });

    assert.equal(decision.decision, 'block');
    assert.ok(decision.reasons.some((reason) => reason.code === 'CUSTOM_BLOCKED_DOMAIN'));
  });

  it('matches blocked network domains structurally instead of by substring', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.network.blockedDomains = ['example.com'];
    const clean = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'https://notexample.com/models/latest',
      metadata: { method: 'GET' },
    });
    const blocked = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'https://example.com/models/latest',
      metadata: { method: 'GET' },
    });

    assert.ok(!clean.reasons.some((reason) => reason.code === 'CUSTOM_BLOCKED_DOMAIN'));
    assert.equal(blocked.decision, 'block');
    assert.ok(blocked.reasons.some((reason) => reason.code === 'CUSTOM_BLOCKED_DOMAIN'));
  });

  it('matches blocked host/path prefixes in shell network references without substring false positives', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.network.blockedDomains = ['example.com/models'];
    const clean = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'shell',
      toolName: 'exec',
      input: 'curl https://notexample.com/models/latest',
    });
    const blocked = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'shell',
      toolName: 'exec',
      input: 'curl https://example.com/models/latest',
    });

    assert.ok(!clean.reasons.some((reason) => reason.code === 'CUSTOM_BLOCKED_DOMAIN'));
    assert.equal(blocked.decision, 'block');
    assert.ok(blocked.reasons.some((reason) => reason.code === 'CUSTOM_BLOCKED_DOMAIN'));
  });

  it('does not downgrade scanner-denied network requests to outbound warnings', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'network',
      toolName: 'web_fetch',
      input: 'not-a-url',
      metadata: { method: 'GET' },
    });

    assert.equal(decision.decision, 'require_approval');
    assert.ok(decision.reasons.some((reason) => reason.code === 'INVALID_URL'));
  });

  it('does not apply defaultOutbound block to web search queries', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.network.defaultOutbound = 'block';
    const decision = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'web_search',
      toolName: 'web_search',
      input: 'MiniMax model list 2026',
    });

    assert.equal(decision.decision, 'allow');
    assert.equal(decision.reasons.length, 0);
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

  it('clears API key credentials when connecting with an Agent JWT', () => {
    const previousHome = process.env.AGENTGUARD_HOME;
    process.env.AGENTGUARD_HOME = mkdtempSync(join(tmpdir(), 'agentguard-connect-jwt-'));
    try {
      connectCloud({
        apiKey: 'ag_live_test_key_123456',
        cloudUrl: 'https://agentguard.example',
      });

      const config = connectAgentJwt({
        agentId: 'agt_jwt_shadow_test',
        agentJwt: 'agent.jwt.shadow',
        agentRegisterUrl: 'https://agentguard.example/activate?token=shadow',
        cloudUrl: 'https://agentguard.example',
      });

      assert.equal(config.apiKey, undefined);
      assert.equal(config.agentId, 'agt_jwt_shadow_test');
      assert.equal(config.agentJwt, 'agent.jwt.shadow');
      assert.equal(config.agentRegisterUrl, 'https://agentguard.example/activate?token=shadow');
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

  it('skips AgentGuard CLI commands before local audit or Cloud reporting', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-self-cli-'));
    const requests: string[] = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      requests.push(String(input));
      throw new Error('unexpected cloud request');
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
          tool_name: 'Bash',
          tool_input: { command: 'AGENTGUARD_AGENT_HOST=codex agentguard protect --json' },
          session_id: 'sess_test',
        }),
      });

      assert.equal(result, null);
      assert.deepEqual(requests, []);
      assert.equal(existsSync(config.auditPath), false);
      assert.equal(existsSync(config.eventSpoolPath), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('skips AgentGuard CLI commands from alternate tool argument shapes', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-self-cli-args-'));
    const requests: string[] = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      requests.push(String(input));
      throw new Error('unexpected cloud request');
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
        actionType: 'shell',
        stdinText: JSON.stringify({
          toolName: 'terminal',
          args: { cmd: 'agentguard disconnect' },
          sessionId: 'sess_test',
        }),
      });

      assert.equal(result, null);
      assert.deepEqual(requests, []);
      assert.equal(existsSync(config.auditPath), false);
      assert.equal(existsSync(config.eventSpoolPath), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('honors allowed command patterns without allowing compound shell commands', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.blockedCommandPatterns = ['agentguard'];
    policy.allowedCommandPatterns = ['agentguard'];

    const allowed = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'shell',
      toolName: 'exec',
      input: 'agentguard disconnect',
    });
    assert.equal(allowed.decision, 'allow');
    assert.equal(allowed.riskScore, 0);
    assert.deepEqual(allowed.reasons, []);

    const compound = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'shell',
      toolName: 'exec',
      input: 'agentguard status; rm -rf /',
    });
    assert.equal(compound.decision, 'block');

    const multiline = await evaluateLocalAction(policy, {
      sessionId: 'sess_test',
      agentHost: 'openclaw',
      actionType: 'shell',
      toolName: 'exec',
      input: 'agentguard status\nrm -rf /',
    });
    assert.equal(multiline.decision, 'block');
  });

  it('scores shell metacharacters below the approval threshold', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();

    for (const command of ['echo a>b', 'echo a&b', 'echo test!', 'echo a^b']) {
      const decision = await evaluateLocalAction(policy, {
        sessionId: 'sess_metachar_score',
        agentHost: 'codex',
        actionType: 'shell',
        toolName: 'Bash',
        input: command,
      });

      assert.equal(decision.decision, 'allow', command);
      assert.equal(decision.riskScore, 10, command);
      assert.equal(decision.riskLevel, 'low', command);
      assert.ok(decision.reasons.some((reason) => reason.code === 'SHELL_INJECTION_RISK'), command);
    }
  });

  it('skips supported agent CLI commands before local audit or Cloud reporting', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-agent-cli-'));
    const requests: string[] = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      requests.push(String(input));
      throw new Error('unexpected cloud request');
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

      for (const command of [
        'openclaw gateway restart',
        'qclaw gateway restart',
        'hermes config reload',
        'codex --version',
        'claude mcp list',
        'claude-code --version',
        'cursor-agent --version',
        'cursor --version',
        'gemini --version',
        'copilot --version',
        'gh copilot explain "git status"',
        'env AGENTGUARD_AGENT_HOST=openclaw openclaw gateway restart',
        'command codex --version',
      ]) {
        const result = await protectAction({
          config,
          stdinText: JSON.stringify({
            tool_name: 'Bash',
            tool_input: { command },
            session_id: 'sess_test',
          }),
        });

        assert.equal(result, null);
      }

      assert.deepEqual(requests, []);
      assert.equal(existsSync(config.auditPath), false);
      assert.equal(existsSync(config.eventSpoolPath), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('does not skip compound shell commands just because they mention agentguard', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-compound-cli-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
    };

    const result = await protectAction({
      config,
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'agentguard status; rm -rf /' },
        session_id: 'sess_test',
      }),
    });

    assert.ok(result);
    assert.equal(result.decision.decision, 'block');
    assert.equal(existsSync(config.auditPath), true);
  });

  it('does not skip multiline shell commands just because they start with agent CLIs', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-agent-multiline-cli-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
    };

    const result = await protectAction({
      config,
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'openclaw gateway status\nrm -rf /' },
        session_id: 'sess_test',
      }),
    });

    assert.ok(result);
    assert.equal(result.decision.decision, 'block');
    assert.equal(existsSync(config.auditPath), true);
  });

  it('does not skip compound shell commands just because they mention agent CLIs', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-agent-compound-cli-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      cloudUrl: 'https://agentguard.example',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
    };

    const result = await protectAction({
      config,
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'openclaw gateway status; rm -rf /' },
        session_id: 'sess_test',
      }),
    });

    assert.ok(result);
    assert.equal(result.decision.decision, 'block');
    assert.equal(existsSync(config.auditPath), true);
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

  it('does not audit or sync empty safe local runtime decisions', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-safe-noop-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    const requests: string[] = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      requests.push(url);
      if (url.endsWith('/api/v1/policies/effective')) {
        return jsonResponse({ success: true, data: policy });
      }
      if (url.endsWith('/api/v1/events/ingest')) {
        throw new Error('safe decisions should not be synced');
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
          tool_name: 'Bash',
          tool_input: { command: 'echo hello' },
          session_id: 'sess_safe',
        }),
      });

      assert.equal(result, null);
      assert.deepEqual(requests, ['https://agentguard.example/api/v1/policies/effective']);
      assert.equal(existsSync(config.auditPath), false);
      assert.equal(existsSync(config.eventSpoolPath), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('does not audit, sync, or request approval for low-risk metacharacter-only commands', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-metachar-low-'));
    const policy = getDefaultEffectiveRuntimePolicy();
    const requests: string[] = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      requests.push(url);
      if (url.endsWith('/api/v1/policies/effective')) {
        return jsonResponse({ success: true, data: policy });
      }
      if (url.endsWith('/api/v1/events/ingest')) {
        throw new Error('low-risk metacharacter decisions should not be synced');
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
        approvalStorePath: join(dir, 'approvals.json'),
      };

      for (const command of ['echo a>b', 'echo a&b', 'echo test!', 'echo a^b']) {
        const result = await protectAction({
          config,
          agentHost: 'codex',
          stdinText: JSON.stringify({
            tool_name: 'Bash',
            tool_input: { command },
            session_id: 'sess_metachar_low',
          }),
        });

        assert.equal(result, null, command);
      }

      assert.deepEqual(requests, Array(4).fill('https://agentguard.example/api/v1/policies/effective'));
      assert.equal(existsSync(config.auditPath), false);
      assert.equal(existsSync(config.eventSpoolPath), false);
      assert.equal(existsSync(config.approvalStorePath!), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('does not intercept empty safe Cloud require_approval decisions', async () => {
    const originalFetch = globalThis.fetch;
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-cloud-safe-noop-'));
    const requests: string[] = [];

    globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      requests.push(url);
      if (url.endsWith('/api/v1/actions/evaluate')) {
        return jsonResponse({
          success: true,
          data: {
            actionId: 'act_cloud_empty_safe',
            decision: 'require_approval',
            riskScore: 0,
            riskLevel: 'safe',
            reasons: [],
            policyVersion: 'cloud-test',
          },
        });
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
        decisionMode: 'cloud',
        stdinText: JSON.stringify({
          tool_name: 'Bash',
          tool_input: { command: 'echo hello' },
          session_id: 'sess_cloud_safe',
        }),
      });

      assert.equal(result, null);
      assert.deepEqual(requests, ['https://agentguard.example/api/v1/actions/evaluate']);
      assert.equal(existsSync(config.auditPath), false);
      assert.equal(existsSync(config.eventSpoolPath), false);
    } finally {
      globalThis.fetch = originalFetch;
    }
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

  it('stores pending approvals with expiration and cleans expired records', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-approval-expiry-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
      approvalStorePath: join(dir, 'approvals.json'),
    };

    const result = await protectAction({
      config,
      agentHost: 'codex',
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: 'cat ~/.ssh/id_rsa.pub' },
        session_id: 'sess_approval_expiry',
      }),
    });

    assert.equal(result?.decision.decision, 'require_approval');
    assert.equal(result?.pendingApproval?.status, 'pending');
    assert.ok(result?.pendingApproval?.expiresAt);
    assert.equal(listPendingApprovals(config.approvalStorePath!).length, 1);

    const removed = cleanupExpiredApprovals(
      config.approvalStorePath!,
      new Date(Date.parse(result!.pendingApproval!.expiresAt) + 1)
    );

    assert.equal(removed, 1);
    assert.equal(listPendingApprovals(config.approvalStorePath!).length, 0);
  });

  it('reuses pending approval ids for repeated matching actions', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-approval-dedupe-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
      approvalStorePath: join(dir, 'approvals.json'),
    };
    const firstStdinText = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'cat ~/.ssh/id_rsa.pub' },
      session_id: 'sess_approval_dedupe_first',
    });
    const retryStdinText = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'cat ~/.ssh/id_rsa.pub' },
      session_id: 'sess_approval_dedupe_first',
    });

    const first = await protectAction({ config, agentHost: 'codex', stdinText: firstStdinText });
    const retry = await protectAction({ config, agentHost: 'codex', stdinText: retryStdinText });

    assert.equal(first?.decision.decision, 'require_approval');
    assert.equal(retry?.decision.decision, 'require_approval');
    assert.equal(retry?.pendingApproval?.actionId, first?.pendingApproval?.actionId);
    assert.equal(listPendingApprovals(config.approvalStorePath!).length, 1);
  });

  it('approves one pending action once and consumes the grant on retry', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-approval-once-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
      approvalStorePath: join(dir, 'approvals.json'),
    };
    const stdinText = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'cat ~/.ssh/id_rsa.pub' },
      session_id: 'sess_approval_once',
    });
    const retryStdinText = JSON.stringify({
      tool_name: 'Bash',
      tool_input: { command: 'cat ~/.ssh/id_rsa.pub' },
      session_id: 'sess_approval_once',
    });

    const blocked = await protectAction({ config, agentHost: 'codex', stdinText });
    assert.equal(blocked?.decision.decision, 'require_approval');

    const approved = approvePendingApproval(config.approvalStorePath!, {
      actionId: blocked!.decision.actionId,
      once: true,
    });
    assert.equal(approved.status, 'approved');

    const allowedRetry = await protectAction({ config, agentHost: 'codex', stdinText: retryStdinText });
    assert.equal(allowedRetry?.decision.decision, 'allow');
    assert.equal(allowedRetry?.event.decision, 'allow');
    assert.equal(allowedRetry?.event.metadata?.approvedByLocalGrant, true);
    assert.match(readFileSync(config.auditPath, 'utf8'), /approvedByLocalGrant/);

    const blockedAgain = await protectAction({ config, agentHost: 'codex', stdinText: retryStdinText });
    assert.equal(blockedAgain?.decision.decision, 'require_approval');
  });

  it('does not protect AgentGuard approval commands wrapped by a shell', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-approval-self-command-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
      approvalStorePath: join(dir, 'approvals.json'),
    };

    const result = await protectAction({
      config,
      agentHost: 'codex',
      stdinText: JSON.stringify({
        tool_name: 'Bash',
        tool_input: { command: "/bin/zsh -lc 'agentguard approve --action-id act_local_1 --once'" },
        session_id: 'sess_approval_self_command',
      }),
    });

    assert.equal(result, null);
  });

  it('does not collapse internal whitespace when fingerprinting approved actions', () => {
    const base = {
      sessionId: 'sess_fingerprint',
      agentHost: 'codex' as const,
      actionType: 'shell' as const,
      toolName: 'Bash',
      cwd: '/workspace',
    };

    assert.notEqual(
      actionFingerprint({ ...base, input: 'printf "a  b"' }),
      actionFingerprint({ ...base, input: 'printf "a b"' })
    );
  });

  it('scopes approval fingerprints to the runtime session', () => {
    const base = {
      agentHost: 'codex' as const,
      actionType: 'shell' as const,
      toolName: 'Bash',
      input: 'cat ~/.ssh/id_rsa.pub',
      cwd: '/workspace',
    };

    assert.notEqual(
      actionFingerprint({ ...base, sessionId: 'sess_first' }),
      actionFingerprint({ ...base, sessionId: 'sess_retry' })
    );
  });

  it('ignores generated OpenClaw session ids when fingerprinting approval retries', () => {
    const base = {
      agentHost: 'openclaw' as const,
      actionType: 'shell' as const,
      toolName: 'exec',
      input: 'cat ~/.ssh/id_rsa.pub',
      cwd: '/workspace',
    };

    assert.equal(
      actionFingerprint({ ...base, sessionId: 'sess_local_1' }),
      actionFingerprint({ ...base, sessionId: 'sess_local_2' })
    );
    assert.notEqual(
      actionFingerprint({ ...base, sessionId: 'sess_openclaw_first' }),
      actionFingerprint({ ...base, sessionId: 'sess_openclaw_retry' })
    );
  });

  it('formats Claude Code agent approval as a PreToolUse ask response', () => {
    const result: ProtectResult = {
      policySource: 'cloud',
      approvalChannel: 'agent',
      event: { ...sampleEvent(), agentHost: 'claude-code' as const },
      pendingApproval: {
        actionId: 'act_confirm',
        status: 'pending',
        once: true,
        actionFingerprint: 'fingerprint',
        sessionId: 'sess_test',
        agentHost: 'claude-code',
        actionType: 'shell',
        toolName: 'Bash',
        inputPreview: 'cat ~/.ssh/id_rsa.pub',
        cwd: '/tmp/project',
        reasonTitles: ['Protected path'],
        riskScore: 70,
        riskLevel: 'high',
        policyVersion: 'runtime-test',
        createdAt: new Date(0).toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
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
    assert.match(formatted.hookSpecificOutput.permissionDecisionReason, /explicit user approval/);
    assert.match(formatted.hookSpecificOutput.permissionDecisionReason, /Do not run this approval command yourself/);
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
