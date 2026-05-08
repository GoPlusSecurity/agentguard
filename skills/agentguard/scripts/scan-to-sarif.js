#!/usr/bin/env node
/**
 * scan-to-sarif.js — convert AgentGuard scan findings to SARIF 2.1.0
 *
 * Usage:
 *   node scripts/scan-to-sarif.js --file <findings.json>
 *   cat findings.json | node scripts/scan-to-sarif.js
 *
 * Input schema (findings.json):
 * {
 *   "target": "<scanned path>",
 *   "scanned_at": "<ISO 8601>",
 *   "files_scanned": <number>,
 *   "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
 *   "findings": [
 *     {
 *       "rule_id": "SHELL_EXEC",
 *       "severity": "CRITICAL|HIGH|MEDIUM|LOW",
 *       "file": "relative/path/to/file.js",
 *       "line": 42,
 *       "evidence": "matched content snippet"
 *     }
 *   ]
 * }
 *
 * Output: SARIF 2.1.0 JSON to stdout
 */

import { readFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Rule definitions (all 24 AgentGuard rules)
// ---------------------------------------------------------------------------

const RULES = [
  { id: 'SHELL_EXEC',             name: 'Shell Command Execution',        severity: 'HIGH',     description: 'Detects capabilities to execute shell commands (child_process, subprocess, os.system).' },
  { id: 'AUTO_UPDATE',            name: 'Auto-Update / Download-Execute', severity: 'CRITICAL', description: 'Detects scheduled self-update or download-and-execute patterns (curl|bash, wget|sh).' },
  { id: 'REMOTE_LOADER',          name: 'Remote Code Loader',             severity: 'CRITICAL', description: 'Detects dynamic code loading from remote sources (dynamic import, eval(fetch(...))).' },
  { id: 'READ_ENV_SECRETS',       name: 'Environment Secret Access',      severity: 'MEDIUM',   description: 'Detects access to environment variables that may contain secrets (process.env, os.environ).' },
  { id: 'READ_SSH_KEYS',          name: 'SSH Key Access',                 severity: 'CRITICAL', description: 'Detects references to SSH key files (~/.ssh/id_rsa, authorized_keys, etc.).' },
  { id: 'READ_KEYCHAIN',          name: 'System Keychain Access',         severity: 'CRITICAL', description: 'Detects access to system keychains, browser credential stores, or Windows Credential Manager.' },
  { id: 'PRIVATE_KEY_PATTERN',    name: 'Hardcoded Private Key',          severity: 'CRITICAL', description: 'Detects hardcoded Ethereum private keys or PEM private key headers in source code.' },
  { id: 'MNEMONIC_PATTERN',       name: 'Hardcoded Mnemonic Phrase',      severity: 'CRITICAL', description: 'Detects hardcoded BIP-39 mnemonic seed phrases in source code.' },
  { id: 'WALLET_DRAINING',        name: 'Wallet Draining Pattern',        severity: 'CRITICAL', description: 'Detects approve+transferFrom or permit patterns that can drain wallets.' },
  { id: 'UNLIMITED_APPROVAL',     name: 'Unlimited Token Approval',       severity: 'HIGH',     description: 'Detects ERC-20 approve(MaxUint256) or setApprovalForAll(true) patterns.' },
  { id: 'DANGEROUS_SELFDESTRUCT', name: 'Dangerous selfdestruct',         severity: 'HIGH',     description: 'Detects selfdestruct() or suicide() calls in Solidity contracts.' },
  { id: 'HIDDEN_TRANSFER',        name: 'Hidden Transfer',                severity: 'MEDIUM',   description: 'Detects ETH transfers hidden inside non-transfer functions.' },
  { id: 'PROXY_UPGRADE',          name: 'Proxy Upgrade Pattern',          severity: 'MEDIUM',   description: 'Detects upgradeable proxy patterns that may allow unauthorized logic replacement.' },
  { id: 'FLASH_LOAN_RISK',        name: 'Flash Loan Risk',                severity: 'MEDIUM',   description: 'Detects flash loan usage that may enable price manipulation or reentrancy attacks.' },
  { id: 'REENTRANCY_PATTERN',     name: 'Reentrancy Vulnerability',       severity: 'HIGH',     description: 'Detects external calls followed by state changes, violating Checks-Effects-Interactions.' },
  { id: 'SIGNATURE_REPLAY',       name: 'Signature Replay Risk',          severity: 'HIGH',     description: 'Detects ecrecover usage without nonce protection, enabling signature replay attacks.' },
  { id: 'OBFUSCATION',            name: 'Code Obfuscation',               severity: 'HIGH',     description: 'Detects obfuscated code patterns (eval, hex escape sequences, packed JS, etc.).' },
  { id: 'PROMPT_INJECTION',       name: 'Prompt Injection Attempt',       severity: 'CRITICAL', description: 'Detects instructions that attempt to override AI agent behavior or bypass safety controls.' },
  { id: 'NET_EXFIL_UNRESTRICTED', name: 'Unrestricted Network Exfiltration', severity: 'HIGH', description: 'Detects unrestricted POST requests or file uploads that may exfiltrate data.' },
  { id: 'WEBHOOK_EXFIL',          name: 'Webhook Exfiltration',           severity: 'CRITICAL', description: 'Detects hardcoded webhook URLs (Discord, Telegram, Slack, ngrok) used for data exfiltration.' },
  { id: 'TROJAN_DISTRIBUTION',    name: 'Trojan Binary Distribution',     severity: 'CRITICAL', description: 'Detects trojanized binary download patterns (URL + password + execute instructions).' },
  { id: 'SUSPICIOUS_PASTE_URL',   name: 'Suspicious Paste Site URL',      severity: 'HIGH',     description: 'Detects URLs pointing to paste sites (Pastebin, Hastebin, etc.) used for payload delivery.' },
  { id: 'SUSPICIOUS_IP',          name: 'Hardcoded Public IP Address',    severity: 'MEDIUM',   description: 'Detects hardcoded public IPv4 addresses that may point to attacker-controlled infrastructure.' },
  { id: 'SOCIAL_ENGINEERING',     name: 'Social Engineering Pressure',    severity: 'HIGH',     description: 'Detects manipulative language combined with execution instructions targeting agent users.' },
];

const RULE_INDEX = new Map(RULES.map(r => [r.id, r]));

// ---------------------------------------------------------------------------
// Severity mapping: AgentGuard → SARIF
// ---------------------------------------------------------------------------

function toSarifLevel(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL': return 'error';
    case 'HIGH':     return 'warning';
    case 'MEDIUM':   return 'note';
    default:         return 'none';
  }
}

// Map AgentGuard severity to SARIF security-severity score (CVSS-like, 0.0–10.0)
function toSecuritySeverity(severity) {
  switch ((severity || '').toUpperCase()) {
    case 'CRITICAL': return '9.0';
    case 'HIGH':     return '7.0';
    case 'MEDIUM':   return '4.0';
    default:         return '1.0';
  }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

function readInput() {
  const fileIdx = process.argv.indexOf('--file');
  if (fileIdx !== -1 && process.argv[fileIdx + 1]) {
    return JSON.parse(readFileSync(process.argv[fileIdx + 1], 'utf-8'));
  }
  return JSON.parse(readFileSync('/dev/stdin', 'utf-8'));
}

// ---------------------------------------------------------------------------
// Build SARIF
// ---------------------------------------------------------------------------

function buildSarif(input) {
  const findings = input.findings || [];

  // Collect which rules actually fired (for the driver.rules array)
  const firedRuleIds = new Set(findings.map(f => f.rule_id));

  // Build driver rules — include all fired rules, plus any referenced ones
  const driverRules = RULES
    .filter(r => firedRuleIds.has(r.id))
    .map(r => ({
      id: r.id,
      name: r.name,
      shortDescription: { text: r.name },
      fullDescription: { text: r.description },
      defaultConfiguration: {
        level: toSarifLevel(r.severity),
      },
      properties: {
        tags: ['security'],
        'security-severity': toSecuritySeverity(r.severity),
        'problem.severity': r.severity.toLowerCase(),
      },
      helpUri: 'https://github.com/GoPlusSecurity/agentguard',
    }));

  // Build results
  const results = findings.map(f => {
    const rule = RULE_INDEX.get(f.rule_id) || { severity: f.severity || 'MEDIUM' };
    const level = toSarifLevel(f.severity || rule.severity);

    const result = {
      ruleId: f.rule_id,
      level,
      message: {
        text: f.evidence
          ? `${f.rule_id}: ${f.evidence}`
          : (rule.description || f.rule_id),
      },
    };

    if (f.file) {
      result.locations = [{
        physicalLocation: {
          artifactLocation: {
            uri: f.file.replace(/\\/g, '/'),
            uriBaseId: '%SRCROOT%',
          },
          ...(f.line ? { region: { startLine: Number(f.line) } } : {}),
        },
      }];
    }

    return result;
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'GoPlus AgentGuard',
          version: '1.1',
          informationUri: 'https://github.com/GoPlusSecurity/agentguard',
          rules: driverRules,
        },
      },
      invocations: [{
        executionSuccessful: true,
        commandLine: `agentguard scan ${input.target || ''}`,
        startTimeUtc: input.scanned_at || new Date().toISOString(),
      }],
      artifacts: input.target ? [{
        location: { uri: input.target, uriBaseId: '%SRCROOT%' },
        description: { text: 'Scanned path' },
      }] : [],
      results,
      properties: {
        riskLevel: input.risk_level || 'UNKNOWN',
        filesScanned: input.files_scanned || 0,
        totalFindings: findings.length,
      },
    }],
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const input = readInput();
const sarif = buildSarif(input);
process.stdout.write(JSON.stringify(sarif, null, 2) + '\n');
