import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { AgentGuardConfig } from '../config.js';
import { describePrivacyMode, resolvePrivacyMode } from '../privacy/resolve.js';

const baseConfig = (privacy?: AgentGuardConfig['privacy']): AgentGuardConfig => ({
  version: 1,
  level: 'balanced',
  policyCachePath: '/tmp/policy.json',
  auditPath: '/tmp/audit.jsonl',
  eventSpoolPath: '/tmp/spool.jsonl',
  privacy,
});

function withoutEnvKey<T>(run: () => T): T {
  const saved = process.env.TYPESAFE_API_KEY;
  delete process.env.TYPESAFE_API_KEY;
  try {
    return run();
  } finally {
    if (saved !== undefined) process.env.TYPESAFE_API_KEY = saved;
  }
}

describe('Privacy enhancement mode', () => {
  it('stays local when unconfigured', () => {
    withoutEnvKey(() => {
      const resolved = resolvePrivacyMode(baseConfig());
      assert.equal(resolved.requestedMode, 'off');
      assert.equal(resolved.adjudicator.name, 'offline');
      assert.equal(resolved.warning, undefined);
    });
  });

  it('activates Jev once enabled with a key', () => {
    const resolved = resolvePrivacyMode(baseConfig({ mode: 'jev', apiKey: 'test-key' }));
    assert.equal(resolved.adjudicator.name, 'jev');
    assert.equal(resolved.warning, undefined);
  });

  it('prefers the environment key over the stored one', () => {
    const saved = process.env.TYPESAFE_API_KEY;
    process.env.TYPESAFE_API_KEY = 'env-key';
    try {
      assert.equal(resolvePrivacyMode(baseConfig({ mode: 'jev' })).adjudicator.name, 'jev');
    } finally {
      if (saved === undefined) delete process.env.TYPESAFE_API_KEY;
      else process.env.TYPESAFE_API_KEY = saved;
    }
  });

  /**
   * A user who enabled enhancement and is silently getting local-only coverage
   * would read a clean result as a cleared one. The fallback must be loud.
   */
  it('warns instead of silently degrading when enabled without a key', () => {
    withoutEnvKey(() => {
      const resolved = resolvePrivacyMode(baseConfig({ mode: 'jev' }));
      assert.equal(resolved.requestedMode, 'jev', 'the request must be preserved');
      assert.equal(resolved.adjudicator.name, 'offline', 'must not pretend to be active');
      assert.ok(resolved.warning, 'a silent fallback is not acceptable');
      assert.match(describePrivacyMode(baseConfig({ mode: 'jev' })), /INACTIVE/);
    });
  });

  it('carries the configured threshold through to adjudication', () => {
    assert.equal(resolvePrivacyMode(baseConfig({ mode: 'off', threshold: 0.8 })).options.threshold, 0.8);
    assert.equal(resolvePrivacyMode(baseConfig()).options.threshold, 0.5);
  });

  it('names the destination in the status line so the boundary is visible', () => {
    const description = describePrivacyMode(baseConfig({ mode: 'jev', apiKey: 'k' }));
    assert.match(description, /typesafe\.ai/);
    assert.match(describePrivacyMode(baseConfig()), /local rules only/);
  });
});
