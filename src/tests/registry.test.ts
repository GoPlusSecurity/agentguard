import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { SkillRegistry } from '../registry/index.js';
import { CAPABILITY_PRESETS } from '../policy/default.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('SkillRegistry', () => {
  let registry: SkillRegistry;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'agentguard-test-'));
    registry = new SkillRegistry({
      filePath: join(tempDir, 'registry.json'),
    });
  });

  const testSkill = {
    id: 'test-skill',
    source: '/path/to/test-skill',
    version_ref: '1.0.0',
    artifact_hash: 'abc123',
  };

  it('should return untrusted for unknown skills', async () => {
    const result = await registry.lookup(testSkill);
    assert.equal(result.effective_trust_level, 'untrusted');
    assert.equal(result.record, null);
  });

  it('should attest and lookup a skill', async () => {
    const attestResult = await registry.forceAttest({
      skill: testSkill,
      trust_level: 'trusted',
      capabilities: CAPABILITY_PRESETS.read_only,
      review: { reviewed_by: 'test', evidence_refs: [], notes: 'test attestation' },
    });
    assert.ok(attestResult.success, 'Attestation should succeed');

    const lookupResult = await registry.lookup(testSkill);
    assert.equal(lookupResult.effective_trust_level, 'trusted');
    assert.ok(lookupResult.record, 'Should find the attested skill');
  });

  it('should revoke a skill', async () => {
    await registry.forceAttest({
      skill: testSkill,
      trust_level: 'trusted',
      capabilities: CAPABILITY_PRESETS.read_only,
      review: { reviewed_by: 'test', evidence_refs: [], notes: '' },
    });

    const revokedCount = await registry.revoke(
      { source: testSkill.source },
      'test revocation'
    );
    assert.ok(revokedCount > 0, 'Should revoke at least one record');

    const lookupResult = await registry.lookup(testSkill);
    assert.equal(lookupResult.effective_trust_level, 'untrusted',
      'Revoked skill should be untrusted');
  });

  it('should list skills with filters', async () => {
    await registry.forceAttest({
      skill: testSkill,
      trust_level: 'trusted',
      capabilities: CAPABILITY_PRESETS.read_only,
      review: { reviewed_by: 'test', evidence_refs: [], notes: '' },
    });

    await registry.forceAttest({
      skill: { ...testSkill, id: 'skill-2', source: '/path/to/skill-2' },
      trust_level: 'restricted',
      capabilities: CAPABILITY_PRESETS.none,
      review: { reviewed_by: 'test', evidence_refs: [], notes: '' },
    });

    const all = await registry.list({});
    assert.ok(all.length >= 2, 'Should list all records');

    const trusted = await registry.list({ trust_level: 'trusted' });
    assert.ok(trusted.length >= 1, 'Should filter trusted skills');
    assert.ok(trusted.every((r) => r.trust_level === 'trusted'));
  });

  it('should downgrade trust on hash change', async () => {
    await registry.forceAttest({
      skill: testSkill,
      trust_level: 'trusted',
      capabilities: CAPABILITY_PRESETS.read_only,
      review: { reviewed_by: 'test', evidence_refs: [], notes: '' },
    });

    // Lookup with different hash
    const result = await registry.lookup({
      ...testSkill,
      artifact_hash: 'different-hash',
    });
    assert.equal(result.effective_trust_level, 'untrusted',
      'Should downgrade on hash change');
  });

  it('should use trading_bot preset capabilities', async () => {
    await registry.forceAttest({
      skill: testSkill,
      trust_level: 'trusted',
      capabilities: CAPABILITY_PRESETS.trading_bot,
      review: { reviewed_by: 'test', evidence_refs: [], notes: '' },
    });

    const result = await registry.lookup(testSkill);
    assert.ok(result.effective_capabilities, 'Should have capabilities');
    assert.ok(result.effective_capabilities.network_allowlist.length > 0,
      'Trading bot preset should have network allowlist');
  });

  // Cleanup
  it('cleanup temp dir', () => {
    try {
      rmSync(tempDir, { recursive: true });
    } catch { /* ignore */ }
  });
});
