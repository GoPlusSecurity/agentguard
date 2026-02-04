#!/usr/bin/env node

/**
 * GoPlus AgentGuard — SessionStart Auto-Scan Hook
 *
 * Runs on session startup to discover and scan newly installed skills.
 * For each skill in ~/.claude/skills/:
 *   1. Calculate artifact hash
 *   2. Check trust registry — skip if already registered with same hash
 *   3. Run quickScan for new/updated skills
 *   4. Auto-register with trust level based on scan results
 *
 * Exits 0 always (informational only, never blocks session startup).
 */

import { readdirSync, existsSync, readFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// ---------------------------------------------------------------------------
// Load AgentGuard engine
// ---------------------------------------------------------------------------

const agentguardPath = join(
  import.meta.url.replace('file://', ''),
  '..', '..', '..', '..', 'dist', 'index.js'
);

let createAgentGuard, CAPABILITY_PRESETS;
try {
  const gs = await import(agentguardPath);
  createAgentGuard = gs.createAgentGuard || gs.default;
  CAPABILITY_PRESETS = gs.CAPABILITY_PRESETS;
} catch {
  try {
    const gs = await import('@goplus/agentguard');
    createAgentGuard = gs.createAgentGuard || gs.default;
    CAPABILITY_PRESETS = gs.CAPABILITY_PRESETS;
  } catch {
    // Can't load engine — exit silently
    process.exit(0);
  }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const SKILLS_DIR = join(homedir(), '.claude', 'skills');
const AGENTGUARD_DIR = join(homedir(), '.agentguard');
const AUDIT_PATH = join(AGENTGUARD_DIR, 'audit.jsonl');

function ensureDir() {
  if (!existsSync(AGENTGUARD_DIR)) {
    mkdirSync(AGENTGUARD_DIR, { recursive: true });
  }
}

function writeAuditLog(entry) {
  try {
    ensureDir();
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n');
  } catch {
    // Non-critical
  }
}

// ---------------------------------------------------------------------------
// Discover skills
// ---------------------------------------------------------------------------

/**
 * Find all skill directories under ~/.claude/skills/
 * A skill directory is one that contains a SKILL.md file.
 */
function discoverSkills() {
  if (!existsSync(SKILLS_DIR)) return [];

  const skills = [];
  try {
    const entries = readdirSync(SKILLS_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const skillDir = join(SKILLS_DIR, entry.name);
      const skillMd = join(skillDir, 'SKILL.md');
      if (existsSync(skillMd)) {
        skills.push({ name: entry.name, path: skillDir });
      }
    }
  } catch {
    // Can't read skills dir
  }
  return skills;
}

// ---------------------------------------------------------------------------
// Risk level → trust level mapping
// ---------------------------------------------------------------------------

function riskToTrustLevel(riskLevel) {
  switch (riskLevel) {
    case 'low':
      return 'trusted';
    case 'medium':
      return 'restricted';
    case 'high':
    case 'critical':
      return 'untrusted';
    default:
      return 'restricted';
  }
}

function riskToCapabilities(riskLevel) {
  switch (riskLevel) {
    case 'low':
      return CAPABILITY_PRESETS?.read_only || {
        network_allowlist: [],
        filesystem_allowlist: ['./**'],
        exec: 'deny',
        secrets_allowlist: [],
      };
    case 'medium':
      return CAPABILITY_PRESETS?.read_only || {
        network_allowlist: [],
        filesystem_allowlist: ['./**'],
        exec: 'deny',
        secrets_allowlist: [],
      };
    case 'high':
    case 'critical':
    default:
      return CAPABILITY_PRESETS?.none || {
        network_allowlist: [],
        filesystem_allowlist: [],
        exec: 'deny',
        secrets_allowlist: [],
      };
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const skills = discoverSkills();
  if (skills.length === 0) {
    process.exit(0);
  }

  const { scanner, registry } = createAgentGuard();

  let scanned = 0;
  let trusted = 0;
  let restricted = 0;
  let untrusted = 0;
  let skipped = 0;

  for (const skill of skills) {
    // Skip self (agentguard)
    if (skill.name === 'agentguard') {
      skipped++;
      continue;
    }

    try {
      // Calculate hash
      const hash = await scanner.calculateArtifactHash(skill.path);

      // Check registry
      const existing = await registry.lookup({
        id: skill.name,
        source: skill.path,
        version_ref: '0.0.0',
        artifact_hash: hash,
      });

      // Already registered with same hash → skip
      if (existing.record && existing.effective_trust_level !== 'untrusted') {
        skipped++;
        continue;
      }

      // Scan
      const result = await scanner.quickScan(skill.path);
      scanned++;

      // Determine trust level
      const trustLevel = riskToTrustLevel(result.risk_level);
      const capabilities = riskToCapabilities(result.risk_level);

      if (trustLevel === 'trusted') trusted++;
      else if (trustLevel === 'restricted') restricted++;
      else untrusted++;

      // Register
      await registry.forceAttest({
        skill: {
          id: skill.name,
          source: skill.path,
          version_ref: '0.0.0',
          artifact_hash: hash,
        },
        trust_level: trustLevel,
        capabilities,
        review: {
          reviewed_by: 'auto-scan',
          evidence_refs: [`scan:${result.risk_level}:${result.risk_tags.join(',')}`],
          notes: `Auto-scanned on session start. Risk: ${result.risk_level}. Tags: ${result.risk_tags.join(', ') || 'none'}`,
        },
      });

      // Audit log
      writeAuditLog({
        timestamp: new Date().toISOString(),
        event: 'auto_scan',
        skill_name: skill.name,
        skill_path: skill.path,
        risk_level: result.risk_level,
        risk_tags: result.risk_tags,
        trust_level: trustLevel,
        summary: result.summary,
      });
    } catch {
      // Skip skills that fail to scan
      skipped++;
    }
  }

  // Output summary to stderr (shown as status message)
  if (scanned > 0) {
    const parts = [];
    if (trusted > 0) parts.push(`${trusted} trusted`);
    if (restricted > 0) parts.push(`${restricted} restricted`);
    if (untrusted > 0) parts.push(`${untrusted} untrusted`);
    process.stderr.write(
      `GoPlus AgentGuard: scanned ${scanned} new skill(s) — ${parts.join(', ')}\n`
    );
  }

  process.exit(0);
}

main();
