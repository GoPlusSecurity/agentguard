/**
 * Self-check engine — runs a single threat-feed advisory against the locally
 * installed skills / plugins / MCP servers and reports which artifacts match.
 *
 * Designed to be cheap (read-only filesystem ops, hashing only when an
 * advisory actually asks for a hash) and never crash on a single bad artifact.
 */

import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { glob } from 'glob';
import { homedir } from 'node:os';
import { basename, extname, isAbsolute, join, resolve } from 'node:path';
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

interface PackageCoordinate {
  name: string;
  version?: string;
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

  const matchers = getSelfCheckMatchers(advisory);
  if (matchers.length === 0) {
    return {
      advisoryId: advisory.id,
      matchedArtifacts: [],
      elapsedMs: Date.now() - startedAt,
      warnings,
    };
  }

  const artifacts = await listArtifactsForAdvisory(advisory, options, warnings);
  const cap = options.maxArtifacts ?? 500;
  const considered = artifacts.slice(0, cap);
  if (artifacts.length > cap) {
    warnings.push(`only checked first ${cap} of ${artifacts.length} ${advisory.ecosystem} artifact(s)`);
  }

  for (const artifact of considered) {
    try {
      const m = await matchArtifact(artifact, advisory.ecosystem, matchers);
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
    return listExplicitArtifacts(advisory.ecosystem, overridePaths, options);
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

async function listExplicitArtifacts(
  ecosystem: AdvisoryEcosystem,
  paths: string[],
  options: RunSelfCheckOptions
): Promise<LocalArtifact[]> {
  const expanded = await expandInspectPaths(paths);
  if (expanded.length === 0) return [];

  switch (ecosystem) {
    case 'skill':
      return (await listSkillDirs(expanded)).map((path) => ({
        path,
        name: basename(path),
        bodyPath: join(path, 'SKILL.md'),
      }));
    case 'plugin':
      return listPluginArtifacts(expanded);
    case 'prompt_injection':
      return listPromptInjectionArtifacts({ ...options, promptInjectionRoots: expanded });
    case 'mcp_server':
    case 'supply_chain':
    case 'url':
      return listFileArtifacts(expanded);
    default:
      return [];
  }
}

/** Enumerate every immediate subdirectory of `roots` that contains a SKILL.md. */
async function listSkillDirs(roots: string[]): Promise<string[]> {
  const found: string[] = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    const rootManifest = join(root, 'SKILL.md');
    if (existsSync(rootManifest)) {
      found.push(root);
      continue;
    }
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
    const rootManifest = firstExisting([
      join(root, 'openclaw.plugin.json'),
      join(root, 'package.json'),
      join(root, '.claude-plugin', 'plugin.json'),
      join(root, 'plugin.json'),
      join(root, 'index.js'),
      join(root, 'index.ts'),
    ]);
    if (rootManifest) {
      found.push({ path: root, name: basename(root), bodyPath: rootManifest });
      continue;
    }
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

async function expandInspectPaths(paths: string[]): Promise<string[]> {
  const expanded: string[] = [];
  for (const rawPath of paths) {
    const pattern = expandHomeDir(rawPath);
    if (!pattern) continue;
    if (hasGlobMagic(pattern)) {
      const matches = await glob(pattern, { absolute: true, nodir: false });
      for (const match of matches) {
        if (existsSync(match)) expanded.push(match);
      }
      continue;
    }
    const resolved = isAbsolute(pattern) ? pattern : resolve(pattern);
    if (existsSync(resolved)) expanded.push(resolved);
  }
  return dedupePaths(expanded);
}

function firstExisting(paths: string[]): string | null {
  for (const path of paths) {
    if (existsSync(path)) return path;
  }
  return null;
}

function expandHomeDir(path: string): string {
  if (!path.startsWith('~')) return path;
  if (path === '~') return homedir();
  if (path.startsWith('~/')) return join(homedir(), path.slice(2));
  return path;
}

function hasGlobMagic(path: string): boolean {
  return /[*?[\]{}]/.test(path);
}

function dedupePaths(paths: string[]): string[] {
  return [...new Set(paths)];
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
 * Match one local artifact against an advisory matcher set.
 * Returns the first match found (per matcher precedence: hash > version > regex > name).
 * Returns null when nothing matched.
 */
async function matchArtifact(
  artifact: LocalArtifact,
  ecosystem: AdvisoryEcosystem,
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
  const wantsBody = affected.some((m) => m.bodyRegex || m.urlPattern || m.domainExact || m.namePattern || m.versionRange);
  if (wantsBody) {
    body = await readArtifactBody(artifact, bodyPath);
  }

  const coordinates = body !== null ? extractPackageCoordinates(artifact, ecosystem, body) : [];

  for (const matcher of affected) {
    if (!matcherMatchesCoordinateSet(matcher, artifact, coordinates)) {
      continue;
    }
    if (matcher.sha256 && localHash && matcher.sha256.toLowerCase() === localHash.toLowerCase()) {
      return { path: artifact.path, matchedBy: 'sha256', hash: localHash };
    }
    if (matcher.versionRange && coordinates.some((candidate) => versionSatisfiesRange(candidate.version, matcher.versionRange))) {
      return { path: artifact.path, matchedBy: 'versionRange' };
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
    if (matcher.namePattern) {
      return { path: artifact.path, matchedBy: 'namePattern' };
    }
    if (matcher.sha256 || matcher.versionRange || matcher.bodyRegex || matcher.urlPattern || matcher.domainExact) {
      continue;
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

function getSelfCheckMatchers(advisory: Advisory): AdvisoryAffected[] {
  if (advisory.selfCheck && Array.isArray(advisory.selfCheck.matchers)) {
    return advisory.selfCheck.matchers.filter(isMatcherLike).map((matcher) => ({
      namePattern: matcher.namePattern,
      sha256: matcher.sha256,
      versionRange: matcher.versionRange,
      bodyRegex: matcher.bodyRegex,
      urlPattern: matcher.urlPattern,
      domainExact: matcher.domainExact,
    }));
  }
  return Array.isArray(advisory.affected) ? advisory.affected.filter(isMatcherLike) : [];
}

function isMatcherLike(value: unknown): value is AdvisoryAffected {
  if (!value || typeof value !== 'object') return false;
  const matcher = value as Record<string, unknown>;
  return [
    'namePattern',
    'sha256',
    'versionRange',
    'bodyRegex',
    'urlPattern',
    'domainExact',
  ].some((key) => typeof matcher[key] === 'string' && matcher[key].length > 0);
}

function matcherMatchesCoordinateSet(
  matcher: AdvisoryAffected,
  artifact: LocalArtifact,
  coordinates: PackageCoordinate[]
): boolean {
  const needsCoordinate = Boolean(matcher.namePattern || matcher.versionRange);
  if (!needsCoordinate) return true;

  const candidates = dedupeCoordinates([
    ...coordinates,
    { name: artifact.name, version: undefined },
    { name: stripExtension(artifact.name), version: undefined },
  ]);

  return candidates.some((candidate) => {
    if (matcher.namePattern && !globMatch(matcher.namePattern, candidate.name)) {
      return false;
    }
    if (matcher.versionRange && !versionSatisfiesRange(candidate.version, matcher.versionRange)) {
      return false;
    }
    return true;
  });
}

function extractPackageCoordinates(
  artifact: LocalArtifact,
  ecosystem: AdvisoryEcosystem,
  body: string
): PackageCoordinate[] {
  const coordinates: PackageCoordinate[] = [
    ...extractManifestCoordinate(artifact, body),
    ...extractSupplyChainCoordinates(artifact, ecosystem, body),
  ];
  return dedupeCoordinates(coordinates);
}

function extractManifestCoordinate(artifact: LocalArtifact, body: string): PackageCoordinate[] {
  const json = tryParseJson(body);
  if (json && typeof json === 'object' && !Array.isArray(json)) {
    const name = typeof json.name === 'string' ? json.name : artifact.name;
    const version = typeof json.version === 'string' ? json.version : undefined;
    return [{ name, version }];
  }

  const skillName = body.match(/^\s*name:\s*["']?([^\n"']+)["']?\s*$/im)?.[1]?.trim();
  const skillVersion = body.match(/^\s*version:\s*["']?([^\n"']+)["']?\s*$/im)?.[1]?.trim();
  if (skillName || skillVersion) {
    return [{
      name: skillName || artifact.name,
      version: skillVersion,
    }];
  }

  return [];
}

function extractSupplyChainCoordinates(
  artifact: LocalArtifact,
  ecosystem: AdvisoryEcosystem,
  body: string
): PackageCoordinate[] {
  if (ecosystem !== 'supply_chain') return [];

  const filename = basename(artifact.path);
  switch (filename) {
    case 'package.json':
      return extractPackageJsonDependencies(body);
    case 'package-lock.json':
    case 'npm-shrinkwrap.json':
      return extractPackageLockDependencies(body);
    case 'requirements.txt':
      return extractRequirementsDependencies(body);
    case 'Cargo.toml':
      return extractCargoTomlDependencies(body);
    case 'Cargo.lock':
      return extractCargoLockDependencies(body);
    case 'go.mod':
      return extractGoModDependencies(body);
    case 'go.sum':
      return extractGoSumDependencies(body);
    default:
      return [];
  }
}

function extractPackageJsonDependencies(body: string): PackageCoordinate[] {
  const json = tryParseJson(body);
  if (!json || typeof json !== 'object' || Array.isArray(json)) return [];

  const fields = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'overrides', 'resolutions'];
  const coordinates: PackageCoordinate[] = [];
  for (const field of fields) {
    const deps = (json as Record<string, unknown>)[field];
    if (!deps || typeof deps !== 'object' || Array.isArray(deps)) continue;
    for (const [name, rawVersion] of Object.entries(deps as Record<string, unknown>)) {
      if (typeof rawVersion !== 'string') continue;
      coordinates.push({ name, version: normalizeVersionCandidate(rawVersion) ?? rawVersion.trim() });
    }
  }
  return coordinates;
}

function extractPackageLockDependencies(body: string): PackageCoordinate[] {
  const json = tryParseJson(body);
  if (!json || typeof json !== 'object' || Array.isArray(json)) return [];

  const coordinates: PackageCoordinate[] = [];
  const root = json as Record<string, unknown>;
  collectPackageLockDeps(root.dependencies, coordinates);
  if (root.packages && typeof root.packages === 'object' && !Array.isArray(root.packages)) {
    for (const [packagePath, meta] of Object.entries(root.packages as Record<string, unknown>)) {
      if (!meta || typeof meta !== 'object' || Array.isArray(meta)) continue;
      const pkg = meta as Record<string, unknown>;
      const version = typeof pkg.version === 'string' ? pkg.version : undefined;
      const name = typeof pkg.name === 'string'
        ? pkg.name
        : packagePath.startsWith('node_modules/')
          ? packagePath.slice('node_modules/'.length)
          : '';
      if (name) coordinates.push({ name, version });
    }
  }
  return coordinates;
}

function collectPackageLockDeps(node: unknown, coordinates: PackageCoordinate[]): void {
  if (!node || typeof node !== 'object' || Array.isArray(node)) return;
  for (const [name, meta] of Object.entries(node as Record<string, unknown>)) {
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) continue;
    const pkg = meta as Record<string, unknown>;
    const version = typeof pkg.version === 'string' ? pkg.version : undefined;
    coordinates.push({ name, version });
    collectPackageLockDeps(pkg.dependencies, coordinates);
  }
}

function extractRequirementsDependencies(body: string): PackageCoordinate[] {
  const coordinates: PackageCoordinate[] = [];
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9+_.-]+)/);
    if (match) {
      coordinates.push({ name: match[1], version: normalizeVersionCandidate(match[2]) ?? match[2] });
    }
  }
  return coordinates;
}

function extractCargoTomlDependencies(body: string): PackageCoordinate[] {
  const coordinates: PackageCoordinate[] = [];
  let inDependencies = false;
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('[')) {
      inDependencies = /^\[(?:workspace\.)?(?:target\.[^.\]]+\.)?(?:dev-|build-)?dependencies\]/.test(trimmed);
      continue;
    }
    if (!inDependencies || !trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([A-Za-z0-9_.-]+)\s*=\s*(?:\{\s*version\s*=\s*"([^"]+)"[^}]*\}|"([^"]+)")/);
    if (match) {
      coordinates.push({ name: match[1], version: normalizeVersionCandidate(match[2] || match[3]) ?? (match[2] || match[3]) });
    }
  }
  return coordinates;
}

function extractCargoLockDependencies(body: string): PackageCoordinate[] {
  const coordinates: PackageCoordinate[] = [];
  const re = /\[\[package\]\][\s\S]*?name = "([^"]+)"[\s\S]*?version = "([^"]+)"/g;
  for (const match of body.matchAll(re)) {
    coordinates.push({ name: match[1], version: normalizeVersionCandidate(match[2]) ?? match[2] });
  }
  return coordinates;
}

function extractGoModDependencies(body: string): PackageCoordinate[] {
  const coordinates: PackageCoordinate[] = [];
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    const match = trimmed.match(/^(?:require\s+)?(\S+)\s+v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
    if (match) {
      coordinates.push({ name: match[1], version: normalizeVersionCandidate(match[2]) ?? match[2] });
    }
  }
  return coordinates;
}

function extractGoSumDependencies(body: string): PackageCoordinate[] {
  const coordinates: PackageCoordinate[] = [];
  for (const line of body.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = trimmed.match(/^(\S+)\s+v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
    if (match) {
      coordinates.push({ name: match[1], version: normalizeVersionCandidate(match[2]) ?? match[2] });
    }
  }
  return coordinates;
}

function tryParseJson(body: string): Record<string, unknown> | unknown[] | null {
  try {
    return JSON.parse(body) as Record<string, unknown> | unknown[];
  } catch {
    return null;
  }
}

function stripExtension(name: string): string {
  const extension = extname(name);
  return extension ? name.slice(0, -extension.length) : name;
}

function dedupeCoordinates(coordinates: PackageCoordinate[]): PackageCoordinate[] {
  const seen = new Set<string>();
  const result: PackageCoordinate[] = [];
  for (const coordinate of coordinates) {
    const normalizedName = coordinate.name.trim();
    if (!normalizedName) continue;
    const key = `${normalizedName}\u0000${coordinate.version ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ name: normalizedName, version: coordinate.version?.trim() });
  }
  return result;
}

function versionSatisfiesRange(version: string | undefined, range: string | undefined): boolean {
  if (!range) return true;
  const parsedVersion = parseSemver(version);
  if (!parsedVersion) return false;
  const comparators = parseComparators(range);
  if (comparators.length === 0) return false;
  return comparators.every((comparator) => compareSemver(parsedVersion, comparator.version, comparator.operator));
}

function normalizeVersionCandidate(value: string | undefined): string | null {
  if (!value) return null;
  const exact = value.trim().match(/^v?(\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/);
  return exact ? exact[1] : null;
}

interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
}

interface Comparator {
  operator: '<' | '<=' | '>' | '>=' | '=';
  version: ParsedSemver;
}

function parseSemver(input: string | undefined): ParsedSemver | null {
  if (!input) return null;
  const match = input.trim().match(/^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? '0'),
    patch: Number(match[3] ?? '0'),
    prerelease: match[4],
  };
}

function parseComparators(range: string): Comparator[] {
  const trimmed = range.trim();
  if (!trimmed || trimmed === '*') return [];

  if (trimmed.startsWith('^')) {
    const base = parseSemver(trimmed.slice(1));
    if (!base) return [];
    return [
      { operator: '>=', version: base },
      { operator: '<', version: caretUpperBound(base) },
    ];
  }

  if (trimmed.startsWith('~')) {
    const base = parseSemver(trimmed.slice(1));
    if (!base) return [];
    return [
      { operator: '>=', version: base },
      { operator: '<', version: { major: base.major, minor: base.minor + 1, patch: 0 } },
    ];
  }

  const wildcard = parseWildcardRange(trimmed);
  if (wildcard) return wildcard;

  const tokens = trimmed.split(/[\s,]+/).filter(Boolean);
  const comparators: Comparator[] = [];
  for (const token of tokens) {
    const match = token.match(/^(<=|>=|<|>|=)?(.+)$/);
    if (!match) return [];
    const operator = (match[1] ?? '=') as Comparator['operator'];
    const version = parseSemver(match[2]);
    if (!version) return [];
    comparators.push({ operator, version });
  }
  return comparators;
}

function parseWildcardRange(range: string): Comparator[] | null {
  const match = range.match(/^v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/i);
  if (!match) return null;
  if (![match[2], match[3]].some((part) => part && /^(x|\*)$/i.test(part))) {
    return null;
  }

  const major = Number(match[1]);
  const minorPart = match[2];
  const patchPart = match[3];
  if (!minorPart || /^(x|\*)$/i.test(minorPart)) {
    return [
      { operator: '>=', version: { major, minor: 0, patch: 0 } },
      { operator: '<', version: { major: major + 1, minor: 0, patch: 0 } },
    ];
  }

  const minor = Number(minorPart);
  if (!patchPart || /^(x|\*)$/i.test(patchPart)) {
    return [
      { operator: '>=', version: { major, minor, patch: 0 } },
      { operator: '<', version: { major, minor: minor + 1, patch: 0 } },
    ];
  }

  return null;
}

function caretUpperBound(version: ParsedSemver): ParsedSemver {
  if (version.major > 0) {
    return { major: version.major + 1, minor: 0, patch: 0 };
  }
  if (version.minor > 0) {
    return { major: 0, minor: version.minor + 1, patch: 0 };
  }
  return { major: 0, minor: 0, patch: version.patch + 1 };
}

function compareSemver(left: ParsedSemver, right: ParsedSemver, operator: Comparator['operator']): boolean {
  const order = semverCompare(left, right);
  switch (operator) {
    case '<':
      return order < 0;
    case '<=':
      return order <= 0;
    case '>':
      return order > 0;
    case '>=':
      return order >= 0;
    case '=':
      return order === 0;
  }
}

function semverCompare(left: ParsedSemver, right: ParsedSemver): number {
  for (const key of ['major', 'minor', 'patch'] as const) {
    const delta = left[key] - right[key];
    if (delta !== 0) return delta;
  }
  if (!left.prerelease && !right.prerelease) return 0;
  if (!left.prerelease) return 1;
  if (!right.prerelease) return -1;
  return left.prerelease.localeCompare(right.prerelease);
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
