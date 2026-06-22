import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { evaluateLocalAction } from '../runtime/evaluator.js';
import { getDefaultEffectiveRuntimePolicy, resolveRuntimePolicy } from '../runtime/policy.js';
import { loadSkillCapabilityManifest } from '../runtime/capabilities.js';
import type { CapabilityModel } from '../types/skill.js';
import type { EffectiveRuntimePolicy, RuntimeAction } from '../runtime/types.js';

function policyWithScopes(
  scopes: Record<string, Partial<CapabilityModel>>,
  overrides: Partial<EffectiveRuntimePolicy> = {}
): EffectiveRuntimePolicy {
  return { ...getDefaultEffectiveRuntimePolicy(), skillCapabilities: scopes, ...overrides };
}

function action(partial: Partial<RuntimeAction>): RuntimeAction {
  return {
    sessionId: 'sess_caps',
    agentHost: 'openclaw',
    actionType: 'shell',
    toolName: 'exec',
    input: '',
    ...partial,
  };
}

describe('Per-skill capability scopes', () => {
  it('leaves undeclared skills unconfined', async () => {
    const policy = policyWithScopes({ 'other-skill': { exec: 'deny' } });
    const decision = await evaluateLocalAction(
      policy,
      action({ sourceSkill: 'my-skill', input: 'echo hello' })
    );

    assert.equal(decision.decision, 'allow');
    assert.ok(!decision.reasons.some((r) => r.code.startsWith('CAPABILITY_')));
  });

  it('does not confine when the policy declares no scopes at all', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const decision = await evaluateLocalAction(
      policy,
      action({ sourceSkill: 'my-skill', input: 'echo hello' })
    );

    assert.ok(!decision.reasons.some((r) => r.code.startsWith('CAPABILITY_')));
  });

  it('denies exec for a declared skill without the exec capability', async () => {
    const policy = policyWithScopes({ 'confined-skill': { exec: 'deny' } });
    const decision = await evaluateLocalAction(
      policy,
      action({ sourceSkill: 'confined-skill', input: 'echo hello' })
    );

    assert.equal(decision.decision, 'require_approval');
    assert.ok(decision.reasons.some((r) => r.code === 'CAPABILITY_EXEC_DENIED'));
  });

  it('blocks exec under strict mode for a confined skill', async () => {
    const policy = policyWithScopes({ 'confined-skill': { exec: 'deny' } }, { mode: 'strict' });
    const decision = await evaluateLocalAction(
      policy,
      action({ sourceSkill: 'confined-skill', input: 'echo hello' })
    );

    assert.equal(decision.decision, 'block');
    assert.ok(decision.reasons.some((r) => r.code === 'CAPABILITY_EXEC_DENIED'));
  });

  it('allows exec when the declared scope grants it', async () => {
    const policy = policyWithScopes({ 'confined-skill': { exec: 'allow' } });
    const decision = await evaluateLocalAction(
      policy,
      action({ sourceSkill: 'confined-skill', input: 'echo hello' })
    );

    assert.ok(!decision.reasons.some((r) => r.code === 'CAPABILITY_EXEC_DENIED'));
  });

  it('denies network destinations outside the skill allowlist', async () => {
    const policy = policyWithScopes({
      'net-skill': { network_allowlist: ['api.allowed.com'] },
    });
    const decision = await evaluateLocalAction(
      policy,
      action({
        sourceSkill: 'net-skill',
        actionType: 'network',
        toolName: 'fetch',
        input: 'https://evil.example.com/exfil',
      })
    );

    assert.ok(['require_approval', 'block'].includes(decision.decision));
    assert.ok(decision.reasons.some((r) => r.code === 'CAPABILITY_NETWORK_DENIED'));
  });

  it('permits network destinations inside the skill allowlist', async () => {
    const policy = policyWithScopes({
      'net-skill': { network_allowlist: ['api.allowed.com'] },
    });
    const decision = await evaluateLocalAction(
      policy,
      action({
        sourceSkill: 'net-skill',
        actionType: 'network',
        toolName: 'fetch',
        input: 'https://api.allowed.com/v1/data',
      })
    );

    assert.ok(!decision.reasons.some((r) => r.code === 'CAPABILITY_NETWORK_DENIED'));
  });

  it('denies file paths outside the skill filesystem allowlist', async () => {
    const policy = policyWithScopes({
      'fs-skill': { filesystem_allowlist: ['/workspace/**'] },
    });
    const decision = await evaluateLocalAction(
      policy,
      action({
        sourceSkill: 'fs-skill',
        actionType: 'file_read',
        toolName: 'read',
        input: '/home/other/notes.txt',
      })
    );

    assert.equal(decision.decision, 'require_approval');
    assert.ok(decision.reasons.some((r) => r.code === 'CAPABILITY_FILE_DENIED'));
  });

  it('permits file paths inside the skill filesystem allowlist', async () => {
    const policy = policyWithScopes({
      'fs-skill': { filesystem_allowlist: ['/workspace/**'] },
    });
    const decision = await evaluateLocalAction(
      policy,
      action({
        sourceSkill: 'fs-skill',
        actionType: 'file_read',
        toolName: 'read',
        input: '/workspace/project/notes.txt',
      })
    );

    assert.ok(!decision.reasons.some((r) => r.code === 'CAPABILITY_FILE_DENIED'));
  });

  it('applies the wildcard scope to any declared-but-unmatched skill', async () => {
    const policy = policyWithScopes({ '*': { exec: 'deny' } });
    const decision = await evaluateLocalAction(
      policy,
      action({ sourceSkill: 'whatever-skill', input: 'echo hello' })
    );

    assert.ok(decision.reasons.some((r) => r.code === 'CAPABILITY_EXEC_DENIED'));
  });
});

describe('Capability manifest loading', () => {
  it('reads a manifest file and normalizes entries', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-caps-'));
    const path = join(dir, 'capabilities.json');
    writeFileSync(
      path,
      JSON.stringify({
        'skill-a': { exec: 'deny', network_allowlist: ['api.good.com'], bogus: 1 },
        'skill-b': 'not-an-object',
      })
    );

    const manifest = loadSkillCapabilityManifest(path);
    assert.deepEqual(manifest['skill-a'], { exec: 'deny', network_allowlist: ['api.good.com'] });
    assert.ok(!('skill-b' in manifest));
  });

  it('returns an empty manifest for a missing file', () => {
    assert.deepEqual(loadSkillCapabilityManifest(join(tmpdir(), 'does-not-exist-caps.json')), {});
  });

  it('overlays the local manifest onto the resolved policy with local precedence', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-caps-resolve-'));
    const manifestPath = join(dir, 'capabilities.json');
    writeFileSync(manifestPath, JSON.stringify({ 'skill-a': { exec: 'deny' } }));
    const prev = process.env.AGENTGUARD_CAPABILITIES_PATH;
    process.env.AGENTGUARD_CAPABILITIES_PATH = manifestPath;

    try {
      const cloudPolicy: EffectiveRuntimePolicy = {
        ...getDefaultEffectiveRuntimePolicy(),
        skillCapabilities: {
          'skill-a': { exec: 'allow' },
          'skill-b': { exec: 'allow' },
        },
      };
      const { policy } = await resolveRuntimePolicy({
        cachePath: join(dir, 'policy-cache.json'),
        fetchPolicy: async () => cloudPolicy,
      });

      assert.equal(policy.skillCapabilities?.['skill-a']?.exec, 'deny');
      assert.equal(policy.skillCapabilities?.['skill-b']?.exec, 'allow');
    } finally {
      if (prev === undefined) delete process.env.AGENTGUARD_CAPABILITIES_PATH;
      else process.env.AGENTGUARD_CAPABILITIES_PATH = prev;
    }
  });
});
