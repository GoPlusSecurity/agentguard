/**
 * Self-check engine — runs a single threat-feed advisory against the locally
 * installed skills / plugins / MCP servers and reports which artifacts match.
 *
 * Designed to be cheap (read-only filesystem ops, hashing only when an
 * advisory actually asks for a hash) and never crash on a single bad artifact.
 */

import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { hashFile } from '../utils/hash.js';
import type {
  Advisory,
  AdvisoryAffected,
  SelfCheckMatch,
  SelfCheckResult,
} from './types.js';

/**
 * Default search locations for each ecosystem.
 *
 * Skill locations cover the four agent frameworks that use the agentskills.io
 * SKILL.md standard: Claude Code, OpenClaw, Hermes Agent, Cursor (project
 * scope only — caller can supply extra roots). MCP server locations cover
 * Claude Code's `~/.claude.json` and Codex's `~/.codex/config.toml` install
 * conventions, but inspection of those is config-aware and lives elsewhere.
 */
export const DEFAULT_SKILL_ROOTS = [
  join(homedir(), '.claude', 'skills'),
  join(homedir(), '.openclaw', 'skills'),
  join(homedir(), '.openclaw', 'workspace', 'skills'),
  join(homedir(), '.hermes', 'skills'),
];

export interface RunSelfCheckOptions {
  /** Override the default per-ecosystem search roots. */
  skillRoots?: string[];
  /** Cap on hashing work: skill dirs beyond this count are skipped. */
  maxArtifacts?: number;
}

/**
 * Run one advisory against the local environment. Never throws — failures
 * become warnings on the result so the caller can keep iterating advisories.
 */
export async function runSelfCheckForAdvisory(
  advisory: Advisory,
  options: RunSelfCheckOptions = {}
): Promise<SelfCheckResult> {
  const startedAt = Date.now();
  const matches: SelfCheckMatch[] = [];
  const warnings: string[] = [];

  if (advisory.withdrawnAt) {
    return { advisoryId: advisory.id, matchedArtifacts: [], elapsedMs: 0, warnings };
  }

  if (advisory.ecosystem !== 'skill') {
    warnings.push(`ecosystem "${advisory.ecosystem}" not implemented; only "skill" is supported in this build`);
    return { advisoryId: advisory.id, matchedArtifacts: [], elapsedMs: Date.now() - startedAt, warnings };
  }

  const roots = options.skillRoots ?? DEFAULT_SKILL_ROOTS;
  const skillDirs = await listSkillDirs(roots);
  const cap = options.maxArtifacts ?? 500;
  const considered = skillDirs.slice(0, cap);
  if (skillDirs.length > cap) {
    warnings.push(`only checked first ${cap} of ${skillDirs.length} skill directories`);
  }

  for (const dir of considered) {
    try {
      const m = await matchSkillDir(dir, advisory.affected);
      if (m) matches.push(m);
    } catch (err) {
      warnings.push(`skipped ${dir}: ${(err as Error).message}`);
    }
  }

  return {
    advisoryId: advisory.id,
    matchedArtifacts: matches,
    elapsedMs: Date.now() - startedAt,
    warnings,
  };
}

/** Enumerate every immediate subdirectory of `roots` that contains a SKILL.md. */
async function listSkillDirs(roots: string[]): Promise<string[]> {
  const found: string[] = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    let entries;
    try {
      entries = await readdir(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const skillPath = join(root, entry.name);
      const manifest = join(skillPath, 'SKILL.md');
      if (existsSync(manifest)) found.push(skillPath);
    }
  }
  return found;
}

/**
 * Match one skill directory against an advisory's affected[] matchers.
 * Returns the first match found (per matcher precedence: hash > regex > name).
 * Returns null when nothing matched.
 */
async function matchSkillDir(
  skillDir: string,
  affected: AdvisoryAffected[]
): Promise<SelfCheckMatch | null> {
  const name = basename(skillDir);
  const manifestPath = join(skillDir, 'SKILL.md');

  // Canonical hash input: the SKILL.md content. The cloud publishes
  // SKILL.md hashes (not directory rollups), so this is the field that
  // must match server-side for `sha256` matchers to be meaningful.
  let localHash: string | null = null;
  const wantsHash = affected.some((m) => m.sha256);
  if (wantsHash && existsSync(manifestPath)) {
    try {
      localHash = await hashFile(manifestPath);
    } catch {
      localHash = null;
    }
  }

  // Regex matching needs the manifest body — only read if some matcher asks.
  let body: string | null = null;
  const wantsBody = affected.some((m) => m.bodyRegex);
  if (wantsBody) {
    try {
      body = await readFile(manifestPath, 'utf8');
      // Cap body length to keep regex evaluation bounded.
      if (body.length > MAX_BODY_BYTES) body = body.slice(0, MAX_BODY_BYTES);
    } catch {
      body = '';
    }
  }

  for (const matcher of affected) {
    if (matcher.sha256 && localHash && matcher.sha256.toLowerCase() === localHash.toLowerCase()) {
      return { path: skillDir, matchedBy: 'sha256', hash: localHash };
    }
    if (matcher.bodyRegex && body !== null) {
      if (safeRegexTest(matcher.bodyRegex, body)) {
        return { path: skillDir, matchedBy: 'bodyRegex' };
      }
    }
    if (matcher.namePattern && globMatch(matcher.namePattern, name)) {
      return { path: skillDir, matchedBy: 'namePattern' };
    }
  }
  return null;
}

/**
 * Defense against catastrophic backtracking and malformed regex coming
 * from upstream advisory data:
 *   - cap the pattern length
 *   - reject patterns with obvious nested-quantifier shapes that explode
 *     under ReDoS (e.g. `(.+)+`, `(a*)*`, `(a|a)*`)
 *   - swallow compile errors silently (treated as "no match")
 *
 * Node's RegExp has no built-in timeout; the cheap-but-effective fix is
 * to bound both the pattern and the body. We accept a slight false-negative
 * rate over freezing on a hostile feed.
 */
const MAX_REGEX_LEN = 256;
const MAX_BODY_BYTES = 256 * 1024;
const CATASTROPHIC = [
  /\([^)]*[+*]\)[+*]/, // nested quantifier: (x+)+
  /\(([^|()]+\|)+\1\)[+*]/, // alternation duplicate: (a|a)*
];

export function safeRegexTest(pattern: string, body: string): boolean {
  if (typeof pattern !== 'string' || pattern.length === 0) return false;
  if (pattern.length > MAX_REGEX_LEN) return false;
  for (const danger of CATASTROPHIC) {
    if (danger.test(pattern)) return false;
  }
  let re: RegExp;
  try {
    re = new RegExp(pattern);
  } catch {
    return false;
  }
  try {
    return re.test(body);
  } catch {
    return false;
  }
}

/**
 * Simple glob match supporting `*` as a single-segment wildcard. Sufficient
 * for `slack-webhook-*` style advisories without pulling in a glob lib.
 */
export function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp(
    '^' +
      pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') +
      '$'
  );
  return re.test(value);
}
