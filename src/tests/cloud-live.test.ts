import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AgentGuardCloudClient } from '../cloud/client.js';
import type { AgentGuardConfig } from '../config.js';
import type { RuntimeAuditEvent } from '../runtime/types.js';

const apiKey = process.env.AGENTGUARD_API_KEY;
const cloudUrl = process.env.AGENTGUARD_CLOUD_URL || 'https://agentguard.gopluslabs.io';
const runLive = Boolean(apiKey);

describe('Cloud live integration', { skip: !runLive }, () => {
  const config: AgentGuardConfig = {
    version: 1,
    level: 'balanced',
    cloudUrl,
    apiKey,
    policyCachePath: '',
    auditPath: '',
    eventSpoolPath: '',
  };
  const client = new AgentGuardCloudClient(config);

  it('fetches effective policy from the configured Cloud', async () => {
    const policy = await client.fetchEffectivePolicy();
    assert.ok(policy.policyVersion);
    assert.ok(policy.decisions);
  });

  it('ingests a redacted runtime audit event', async () => {
    const event = sampleEvent('warn');
    event.input = 'echo safe --api_key=live-secret-that-must-be-redacted';

    await client.ingestEvents([event]);
  });

});

function sampleEvent(decision: RuntimeAuditEvent['decision']): RuntimeAuditEvent {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2)}`;
  return {
    actionId: `act_live_${suffix}`,
    sessionId: `sess_live_${suffix}`,
    agentHost: 'codex',
    actionType: 'shell',
    toolName: 'Bash',
    input: 'echo safe',
    decision,
    riskScore: decision === 'allow' ? 0 : 20,
    riskLevel: decision === 'allow' ? 'safe' : 'medium',
    reasons: [],
    policyVersion: 'live-test',
    metadata: { test: 'cloud-live' },
  };
}
