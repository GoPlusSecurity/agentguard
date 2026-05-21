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
  AdvisoryEcosystem,
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

export const DEFAULT_PLUGIN_ROOTS = [
  join(homedir(), '.claude', 'plugins'),
  join(homedir(), '.openclaw', 'plugins'),
  join(homedir(), '.openclaw', 'workspace', 'plugins'),
  join(homedir(), '.codex', 'plugins'),
];

export const DEFAULT_MCP_CONFIG_PATHS = [
  join(homedir(), '.claude.json'),
  join(homedir(), '.claude', 'mcp.json'),
  join(homedir(), '.codex', 'config.toml'),
  join(homedir(), '.cursor', 'mcp.json'),
  join(homedir(), '.openclaw', 'mcp.json'),
  join(homedir(), '.openclaw', 'config.json'),
];

export const DEFAULT_SUPPLY_CHAIN_PATHS = [
  'package.json',
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lockb',
  'requirements.txt',
  'pyproject.toml',
  'Cargo.toml',
  'Cargo.lock',
  'go.mod',
  'go.sum',
];

export const DEFAULT_URL_SCAN_PATHS = [
  join(homedir(), '.agentguard', 'policy-cache.json'),
  join(homedir(), '.agentguard', 'audit.jsonl'),
  join(homedir(), '.claude.json'),
  join(homedir(), '.claude', 'settings.json'),
  join(homedir(), '.codex', 'config.toml'),
  join(homedir(), '.openclaw', 'config.json'),
];

export interface RunSelfCheckOptions {
  /** Override the default per-ecosystem search roots. */
  skillRoots?: string[];
  pluginRoots?: string[];
  mcpConfigPaths?: string[];
  supplyChainPaths?: string[];
  urlScanPaths?: string[];
  promptInjectionRoots?: string[];
  /** Cap on local artifacts checked per advisory. */
  maxArtifacts?: number;
}

interface LocalArtifact {
  path: string;
  name: string;
  bodyPath?: string;
  body?: string;
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

  const artifacts = await listArtifactsForAdvisory(advisory, options, warnings);
  const cap = options.maxArtifacts ?? 500;
  const considered = artifacts.slice(0, cap);
  if (artifacts.length > cap) {
    warnings.push(`only checked first ${cap} of ${artifacts.length} ${advisory.ecosystem} artifact(s)`);
  }

  for (const artifact of considered) {
    try {
      const m = await matchArtifact(artifact, advisory.affected);
      if (m) matches.push(m);
    } catch (err) {
      warnings.push(`skipped ${artifact.path}: ${(err as Error).message}`);
    }
  }

  return {
    advisoryId: advisory.id,
    matchedArtifacts: matches,
    elapsedMs: Date.now() - startedAt,
    warnings,
  };
}

async function listArtifactsForAdvisory(
  advisory: Advisory,
  options: RunSelfCheckOptions,
  warnings: string[]
): Promise<LocalArtifact[]> {
  const overridePaths = advisory.selfCheck?.inspectPaths?.filter((p): p is string => typeof p === 'string') ?? [];
  if (overridePaths.length > 0) {
    return listExplicitArtifacts(overridePaths);
  }

  switch (advisory.ecosystem) {
    case 'skill':
      return (await listSkillDirs(options.skillRoots ?? DEFAULT_SKILL_ROOTS)).map((path) => ({
        path,
        name: basename(path),
        bodyPath: join(path, 'SKILL.md'),
      }));
    case 'plugin':
      return listPluginArtifacts(options.pluginRoots ?? DEFAULT_PLUGIN_ROOTS);
    case 'mcp_server':
      return listFileArtifacts(options.mcpConfigPaths ?? DEFAULT_MCP_CONFIG_PATHS);
    case 'supply_chain':
      return listFileArtifacts(options.supplyChainPaths ?? DEFAULT_SUPPLY_CHAIN_PATHS);
    case 'url':
      return listFileArtifacts(options.urlScanPaths ?? DEFAULT_URL_SCAN_PATHS);
    case 'prompt_injection':
      return listPromptInjectionArtifacts(options);
    default:
      warnings.push(`ecosystem "${(advisory as { ecosystem: AdvisoryEcosystem }).ecosystem}" not implemented`);
      return [];
  }
}

async function listExplicitArtifacts(paths: string[]): Promise<LocalArtifact[]> {
  const artifacts: LocalArtifact[] = [];
  for (const path of paths) {
    if (!existsSync(path)) continue;
    artifacts.push({
      path,
      name: basename(path),
      bodyPath: firstExisting([
        join(path, 'SKILL.md'),
        join(path, 'openclaw.plugin.json'),
        join(path, 'package.json'),
        join(path, 'plugin.json'),
        path,
      ]) ?? path,
    });
  }
  return artifacts;
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

async function listPluginArtifacts(roots: string[]): Promise<LocalArtifact[]> {
  const found: LocalArtifact[] = [];
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
      const pluginDir = join(root, entry.name);
      const manifest = firstExisting([
        join(pluginDir, 'openclaw.plugin.json'),
        join(pluginDir, 'package.json'),
        join(pluginDir, '.claude-plugin', 'plugin.json'),
        join(pluginDir, 'plugin.json'),
        join(pluginDir, 'index.js'),
        join(pluginDir, 'index.ts'),
      ]);
      if (manifest) {
        found.push({ path: pluginDir, name: entry.name, bodyPath: manifest });
      }
    }
  }
  return found;
}

async function listFileArtifacts(paths: string[]): Promise<LocalArtifact[]> {
  const found: LocalArtifact[] = [];
  for (const path of paths) {
    if (!existsSync(path)) continue;
    found.push({ path, name: basename(path), bodyPath: path });
  }
  return found;
}

async function listPromptInjectionArtifacts(options: RunSelfCheckOptions): Promise<LocalArtifact[]> {
  const roots = options.promptInjectionRoots ?? [
    ...(options.skillRoots ?? DEFAULT_SKILL_ROOTS),
    ...(options.pluginRoots ?? DEFAULT_PLUGIN_ROOTS),
  ];
  const skills = (await listSkillDirs(roots)).map((path) => ({
    path,
    name: basename(path),
    bodyPath: join(path, 'SKILL.md'),
  }));
  const plugins = await listPluginArtifacts(roots);
  return dedupeArtifacts([...skills, ...plugins]);
}

function firstExisting(paths: string[]): string | null {
  for (const path of paths) {
    if (existsSync(path)) return path;
  }
  return null;
}

function dedupeArtifacts(artifacts: LocalArtifact[]): LocalArtifact[] {
  const seen = new Set<string>();
  const result: LocalArtifact[] = [];
  for (const artifact of artifacts) {
    if (seen.has(artifact.path)) continue;
    seen.add(artifact.path);
    result.push(artifact);
  }
  return result;
}

/**
 * Match one local artifact against an advisory's affected[] matchers.
 * Returns the first match found (per matcher precedence: hash > regex > name).
 * Returns null when nothing matched.
 */
async function matchArtifact(
  artifact: LocalArtifact,
  affected: AdvisoryAffected[]
): Promise<SelfCheckMatch | null> {
  const bodyPath = artifact.bodyPath ?? artifact.path;
  let localHash: string | null = null;
  const wantsHash = affected.some((m) => m.sha256);
  if (wantsHash && existsSync(bodyPath)) {
    try {
      localHash = await hashFile(bodyPath);
    } catch {
      localHash = null;
    }
  }

  let body: string | null = null;
  const wantsBody = affected.some((m) => m.bodyRegex || m.urlPattern || m.domainExact);
  if (wantsBody) {
    body = await readArtifactBody(artifact, bodyPath);
  }

  for (const matcher of affected) {
    if (matcher.sha256 && localHash && matcher.sha256.toLowerCase() === localHash.toLowerCase()) {
      return { path: artifact.path, matchedBy: 'sha256', hash: localHash };
    }
    if (matcher.bodyRegex && body !== null) {
      if (safeRegexTest(matcher.bodyRegex, body)) {
        return { path: artifact.path, matchedBy: 'bodyRegex' };
      }
    }
    if (matcher.urlPattern && body !== null && bodyContainsUrlPattern(body, matcher.urlPattern)) {
      return { path: artifact.path, matchedBy: 'urlPattern' };
    }
    if (matcher.domainExact && body !== null && bodyContainsDomain(body, matcher.domainExact)) {
      return { path: artifact.path, matchedBy: 'domainExact' };
    }
    if (matcher.namePattern && globMatch(matcher.namePattern, artifact.name)) {
      return { path: artifact.path, matchedBy: 'namePattern' };
    }
  }
  return null;
}

async function readArtifactBody(artifact: LocalArtifact, bodyPath: string): Promise<string> {
  if (typeof artifact.body === 'string') {
    return artifact.body.length > MAX_BODY_BYTES ? artifact.body.slice(0, MAX_BODY_BYTES) : artifact.body;
  }
  try {
    const body = await readFile(bodyPath, 'utf8');
    return body.length > MAX_BODY_BYTES ? body.slice(0, MAX_BODY_BYTES) : body;
  } catch {
    return '';
  }
}

function bodyContainsUrlPattern(body: string, pattern: string): boolean {
  if (safeRegexTest(pattern, body)) return true;
  for (const url of extractUrls(body)) {
    if (globMatch(pattern, url)) return true;
  }
  return false;
}

function bodyContainsDomain(body: string, domain: string): boolean {
  const expected = domain.toLowerCase();
  for (const url of extractUrls(body)) {
    try {
      if (new URL(url).hostname.toLowerCase() === expected) return true;
    } catch {
      // ignore malformed URL-looking text
    }
  }
  return containsBareDomain(body, expected);
}

function extractUrls(body: string): string[] {
  return body.match(/https?:\/\/[^\s"'`<>\\)]+/gi) ?? [];
}

function containsBareDomain(body: string, domain: string): boolean {
  const escaped = domain.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(^|[^A-Za-z0-9.-])${escaped}([^A-Za-z0-9.-]|$)`, 'i');
  return re.test(body);
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
