import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ALL_RULES, getRuleById, getRulesBySeverity, getRulesForExtension } from '../scanner/rules/index.js';

describe('Scanner Rules', () => {
  it('should have 20 detection rules', () => {
    // Each RiskTag should map to at least one rule
    const ruleIds = new Set(ALL_RULES.map((r) => r.id));
    assert.ok(ruleIds.size >= 20, `Expected at least 20 unique rules, got ${ruleIds.size}`);
  });

  it('should find rule by ID', () => {
    const rule = getRuleById('SHELL_EXEC');
    assert.ok(rule, 'SHELL_EXEC rule should exist');
    assert.equal(rule.severity, 'high');
  });

  it('should filter rules by severity', () => {
    const critical = getRulesBySeverity('critical');
    assert.ok(critical.length > 0, 'Should have critical rules');
    assert.ok(critical.every((r) => r.severity === 'critical'));

    const high = getRulesBySeverity('high');
    assert.ok(high.length > 0, 'Should have high rules');
    assert.ok(high.every((r) => r.severity === 'high'));
  });

  it('should filter rules for .ts extension', () => {
    const tsRules = getRulesForExtension('.ts');
    assert.ok(tsRules.length > 0, 'Should have rules for .ts files');
  });

  it('should filter rules for .sol extension', () => {
    const solRules = getRulesForExtension('.sol');
    assert.ok(solRules.length > 0, 'Should have rules for .sol files');
    const solRuleIds = solRules.map((r) => r.id);
    assert.ok(solRuleIds.includes('WALLET_DRAINING') || solRuleIds.includes('REENTRANCY_PATTERN'),
      'Solidity rules should include Web3-specific rules');
  });

  it('should have CRITICAL rules for key security threats', () => {
    const criticalIds = ['AUTO_UPDATE', 'REMOTE_LOADER', 'READ_SSH_KEYS', 'READ_KEYCHAIN',
      'PRIVATE_KEY_PATTERN', 'MNEMONIC_PATTERN', 'WALLET_DRAINING', 'PROMPT_INJECTION', 'WEBHOOK_EXFIL'];

    for (const id of criticalIds) {
      const rule = getRuleById(id as any);
      assert.ok(rule, `Rule ${id} should exist`);
      assert.equal(rule.severity, 'critical', `Rule ${id} should be CRITICAL`);
    }
  });

  it('all rules should have required fields', () => {
    for (const rule of ALL_RULES) {
      assert.ok(rule.id, `Rule should have an id`);
      assert.ok(rule.severity, `Rule ${rule.id} should have severity`);
      assert.ok(rule.patterns && rule.patterns.length > 0, `Rule ${rule.id} should have patterns`);
      assert.ok(rule.file_patterns && rule.file_patterns.length > 0, `Rule ${rule.id} should have file_patterns`);
      assert.ok(rule.description, `Rule ${rule.id} should have description`);
    }
  });
});
