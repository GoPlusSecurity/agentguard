#!/usr/bin/env node
/**
 * checkup-score.js — deterministic scoring engine for /agentguard checkup
 *
 * Accepts raw check facts collected by the LLM and computes all dimension
 * scores, the composite score, and tier assignment without any LLM arithmetic.
 *
 * Usage:
 *   node scripts/checkup-score.js --file <raw-facts.json>
 *   cat raw-facts.json | node scripts/checkup-score.js
 *
 * Input schema (raw-facts.json):
 * {
 *   "skills": [
 *     { "name": "skill-name", "risk_level": "low|medium|high|critical", "findings": [
 *       { "rule": "RULE_ID", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "file": "...", "line": 0 }
 *     ]}
 *   ],
 *   "credential_files": {
 *     "ssh_dir":       { "exists": true,  "permissions": "700" },
 *     "gnupg_dir":     { "exists": false },
 *     "openclaw_config": { "exists": false }
 *   },
 *   "dlp": {
 *     "private_keys_found": false,
 *     "mnemonics_found":    false,
 *     "api_keys_found":     false
 *   },
 *   "network": {
 *     "dangerous_ports":  [],
 *     "suspicious_crons": [],
 *     "sensitive_env_vars": []
 *   },
 *   "runtime": {
 *     "hooks_installed":     false,
 *     "audit_log_exists":    false,
 *     "skills_ever_scanned": false
 *   },
 *   "web3": {
 *     "detected":                 false,
 *     "wallet_draining_found":    false,
 *     "unlimited_approval_found": false,
 *     "goplus_configured":        false
 *   }
 * }
 *
 * Output: JSON with computed scores, findings, composite, and tier.
 */

import { readFileSync } from 'node:fs';

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
// Dimension 1: Skill & Code Safety (weight 25%)
// ---------------------------------------------------------------------------

function scoreCodeSafety(skills) {
  const findings = [];

  if (!skills || skills.length === 0) {
    findings.push({ severity: 'LOW', text: 'No third-party skills installed — no code to audit' });
    return { score: 70, findings };
  }

  let score = 100;

  for (const skill of skills) {
    const isAgentGuard = (skill.name || '').toLowerCase().includes('agentguard');

    for (const f of (skill.findings || [])) {
      // Suppress READ_ENV_SECRETS for agentguard itself
      if (isAgentGuard && f.rule === 'READ_ENV_SECRETS') continue;

      const sev = (f.severity || '').toUpperCase();
      if (sev === 'CRITICAL') {
        score -= 15;
        findings.push({ severity: 'CRITICAL', text: `${f.rule} in ${skill.name}:${f.file || '?'}:${f.line || '?'}` });
      } else if (sev === 'HIGH') {
        score -= 8;
        findings.push({ severity: 'HIGH', text: `${f.rule} in ${skill.name}:${f.file || '?'}:${f.line || '?'}` });
      } else if (sev === 'MEDIUM') {
        score -= 3;
        findings.push({ severity: 'MEDIUM', text: `${f.rule} in ${skill.name}:${f.file || '?'}:${f.line || '?'}` });
      }
    }
  }

  return { score: Math.max(0, score), findings };
}

// ---------------------------------------------------------------------------
// Dimension 2: Credential & Secret Safety (weight 25%)
// ---------------------------------------------------------------------------

function scoreCredentialSafety(credentialFiles, dlp) {
  const findings = [];
  let score = 0;

  const cf = credentialFiles || {};
  const dlpData = dlp || {};

  // ~/.ssh/ permissions (25 pts)
  const ssh = cf.ssh_dir;
  if (!ssh || !ssh.exists) {
    score += 25; // N/A — dir doesn't exist
  } else {
    const perms = parseInt(ssh.permissions || '0', 8);
    if (perms <= 0o700) {
      score += 25;
    } else {
      findings.push({ severity: 'HIGH', text: `~/.ssh/ permissions too open (${ssh.permissions}) — should be 700` });
    }
  }

  // ~/.gnupg/ permissions (15 pts)
  const gnupg = cf.gnupg_dir;
  if (!gnupg || !gnupg.exists) {
    score += 15; // N/A
  } else {
    const perms = parseInt(gnupg.permissions || '0', 8);
    if (perms <= 0o700) {
      score += 15;
    } else {
      findings.push({ severity: 'MEDIUM', text: `~/.gnupg/ permissions too open (${gnupg.permissions}) — should be 700` });
    }
  }

  // No private keys (25 pts)
  if (!dlpData.private_keys_found) {
    score += 25;
  } else {
    findings.push({ severity: 'CRITICAL', text: 'Plaintext private key found in skill code or workspace' });
  }

  // No mnemonics (20 pts)
  if (!dlpData.mnemonics_found) {
    score += 20;
  } else {
    findings.push({ severity: 'CRITICAL', text: 'Plaintext mnemonic found in skill code or workspace' });
  }

  // No API keys (15 pts)
  if (!dlpData.api_keys_found) {
    score += 15;
  } else {
    findings.push({ severity: 'HIGH', text: 'API key/token found in skill code or workspace' });
  }

  return { score: Math.min(100, score), findings };
}

// ---------------------------------------------------------------------------
// Dimension 3: Network & System Exposure (weight 20%)
// ---------------------------------------------------------------------------

function scoreNetworkExposure(network) {
  const findings = [];
  let score = 0;

  const net = network || {};
  const ports = net.dangerous_ports || [];
  const crons = net.suspicious_crons || [];
  const envVars = net.sensitive_env_vars || [];

  // No dangerous ports (35 pts)
  if (ports.length === 0) {
    score += 35;
  } else {
    for (const p of ports) {
      findings.push({ severity: 'HIGH', text: `Dangerous port exposed: ${p}` });
    }
  }

  // No suspicious crons (30 pts)
  if (crons.length === 0) {
    score += 30;
  } else {
    for (const c of crons) {
      findings.push({ severity: 'HIGH', text: `Suspicious cron job: ${c}` });
    }
  }

  // No sensitive env vars (20 pts)
  if (envVars.length === 0) {
    score += 20;
  } else {
    for (const v of envVars) {
      findings.push({ severity: 'MEDIUM', text: `Sensitive env var exposed: ${v}` });
    }
  }

  // OpenClaw config permissions — always award 15 pts if not OpenClaw (N/A)
  const oc = (network || {}).openclaw_config_ok;
  if (oc === undefined || oc === null || oc === true) {
    score += 15; // N/A or passing
  } else {
    findings.push({ severity: 'MEDIUM', text: 'OpenClaw config file permissions too open' });
  }

  return { score: Math.min(100, score), findings };
}

// ---------------------------------------------------------------------------
// Dimension 4: Runtime Protection (weight 15%)
// ---------------------------------------------------------------------------

function scoreRuntimeProtection(runtime) {
  const findings = [];
  let score = 0;

  const rt = runtime || {};

  // Hooks installed (40 pts)
  if (rt.hooks_installed) {
    score += 40;
  } else {
    findings.push({ severity: 'HIGH', text: 'No security hooks installed — actions are unmonitored' });
  }

  // Audit log exists (30 pts)
  if (rt.audit_log_exists) {
    score += 30;
  } else {
    findings.push({ severity: 'MEDIUM', text: 'No security audit log — no threat history available' });
  }

  // Skills ever scanned (30 pts)
  if (rt.skills_ever_scanned) {
    score += 30;
  } else {
    findings.push({ severity: 'MEDIUM', text: 'Installed skills have never been security-scanned' });
  }

  return { score: Math.min(100, score), findings };
}

// ---------------------------------------------------------------------------
// Dimension 5: Web3 Safety (weight 15%, only if detected)
// ---------------------------------------------------------------------------

function scoreWeb3Safety(web3) {
  if (!web3 || !web3.detected) {
    return { score: null, na: true, findings: [] };
  }

  const findings = [];
  let score = 0;

  // No wallet-draining patterns (40 pts)
  if (!web3.wallet_draining_found) {
    score += 40;
  } else {
    findings.push({ severity: 'CRITICAL', text: 'Wallet-draining pattern detected in skill code' });
  }

  // No unlimited approvals (30 pts)
  if (!web3.unlimited_approval_found) {
    score += 30;
  } else {
    findings.push({ severity: 'HIGH', text: 'Unlimited approval pattern detected in skill code' });
  }

  // GoPlus or equivalent configured (30 pts)
  if (web3.goplus_configured) {
    score += 30;
  } else {
    findings.push({ severity: 'MEDIUM', text: 'No transaction security API — Web3 calls are unverified' });
  }

  return { score: Math.min(100, score), na: false, findings };
}

// ---------------------------------------------------------------------------
// Composite score + tier
// ---------------------------------------------------------------------------

function computeComposite(dims) {
  const { code_safety, credential_safety, network_exposure, runtime_protection, web3_safety } = dims;

  let composite;
  if (web3_safety.na) {
    // Redistribute 15% across 4 dimensions
    composite =
      code_safety.score * 0.294 +
      credential_safety.score * 0.294 +
      network_exposure.score * 0.235 +
      runtime_protection.score * 0.176;
  } else {
    composite =
      code_safety.score * 0.25 +
      credential_safety.score * 0.25 +
      network_exposure.score * 0.20 +
      runtime_protection.score * 0.15 +
      web3_safety.score * 0.15;
  }

  return Math.round(composite);
}

function assignTier(score) {
  if (score >= 90) return { tier: 'S', label: 'JACKED' };
  if (score >= 70) return { tier: 'A', label: 'Healthy' };
  if (score >= 50) return { tier: 'B', label: 'Tired' };
  return { tier: 'F', label: 'Critical' };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const raw = readInput();

const dimensions = {
  code_safety:       scoreCodeSafety(raw.skills),
  credential_safety: scoreCredentialSafety(raw.credential_files, raw.dlp),
  network_exposure:  scoreNetworkExposure(raw.network),
  runtime_protection: scoreRuntimeProtection(raw.runtime),
  web3_safety:       scoreWeb3Safety(raw.web3),
};

const composite_score = computeComposite(dimensions);
const { tier, label } = assignTier(composite_score);

const totalFindings = Object.values(dimensions).reduce(
  (acc, d) => acc + (d.findings ? d.findings.length : 0), 0
);

const output = {
  composite_score,
  tier,
  tier_label: label,
  total_findings: totalFindings,
  dimensions: {
    code_safety: {
      score: dimensions.code_safety.score,
      findings: dimensions.code_safety.findings,
    },
    credential_safety: {
      score: dimensions.credential_safety.score,
      findings: dimensions.credential_safety.findings,
    },
    network_exposure: {
      score: dimensions.network_exposure.score,
      findings: dimensions.network_exposure.findings,
    },
    runtime_protection: {
      score: dimensions.runtime_protection.score,
      findings: dimensions.runtime_protection.findings,
    },
    web3_safety: {
      score: dimensions.web3_safety.score,
      na: dimensions.web3_safety.na,
      findings: dimensions.web3_safety.findings,
    },
  },
};

process.stdout.write(JSON.stringify(output, null, 2) + '\n');
