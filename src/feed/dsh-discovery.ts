import { existsSync, type Dirent } from 'node:fs';
import { readFile, readdir, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { parseCordisConfigs } from '../dsh/parse-cordis-patch.js';

const MAX_PROFILE_MANIFEST_BYTES = 1_000_000;
const MAX_BUNDLE_DEPTH = 32;
const MAX_BUNDLE_PLUGINS = 1_000;
const CORDIS_PATCH_FILENAMES = ['cordis.patch.yml', 'cordis.patch.yaml'] as const;

export interface DshSelfCheckRoots {
  skillRoots: string[];
  pluginRoots: string[];
  installedPluginDirs: string[];
  supplyChainPaths: string[];
  urlScanPaths: string[];
}

export interface DiscoverDshSelfCheckRootsOptions {
  dshHome?: string;
  cwd?: string;
}

/**
 * Discover DSH-owned self-check inputs, following only dependency edges named
 * by installed bundle patches. Environment defaults are resolved per call.
 */
export async function discoverDshSelfCheckRoots(
  options: DiscoverDshSelfCheckRootsOptions = {},
): Promise<DshSelfCheckRoots> {
  const configuredHome = options.dshHome ?? process.env.DSH_HOME?.trim() ?? '';
  const dshHome = resolve(configuredHome || join(homedir(), '.dsh'));
  const cwd = resolve(options.cwd ?? process.cwd());
  const skillRoots = existingPaths([
    join(dshHome, 'skills'),
    join(cwd, '.dsh', 'skills'),
  ]);
  const pluginRoots: string[] = [];
  const installedPluginDirs: string[] = [];
  const supplyChainPaths: string[] = [];
  const urlScanPaths: string[] = [];
  const directDependencyPaths = new Set<string>();

  addCordisPatches(dshHome, pluginRoots, urlScanPaths);
  const profilesRoot = join(dshHome, 'profiles');
  let profiles: Dirent[];
  try {
    profiles = await readdir(profilesRoot, { withFileTypes: true });
  } catch {
    profiles = [];
  }

  for (const entry of profiles.sort((left, right) => left.name.localeCompare(right.name))) {
    if (!entry.isDirectory()) continue;
    const profileRoot = join(profilesRoot, entry.name);
    addCordisPatches(profileRoot, pluginRoots, urlScanPaths);
    const manifestPath = join(profileRoot, 'package.json');
    if (!existsSync(manifestPath)) continue;
    pluginRoots.push(manifestPath);
    supplyChainPaths.push(manifestPath);
    urlScanPaths.push(manifestPath);

    const dependencyNames = await readDirectDependencyNames(manifestPath);
    for (const dependencyName of dependencyNames) {
      const dependencyRoot = join(profileRoot, 'node_modules', ...dependencyName.split('/'));
      if (!existsSync(dependencyRoot)) continue;
      directDependencyPaths.add(dependencyRoot);
      pluginRoots.push(dependencyRoot);
      if (dependencyName !== '@goplus/agentguard') {
        installedPluginDirs.push(dependencyRoot);
        const bundlePlugins = await discoverReferencedBundlePlugins(dependencyRoot, profileRoot);
        for (const pluginRoot of bundlePlugins) {
          pluginRoots.push(pluginRoot);
          installedPluginDirs.push(pluginRoot);
          supplyChainPaths.push(pluginRoot);
          const pluginManifest = join(pluginRoot, 'package.json');
          if (existsSync(pluginManifest)) urlScanPaths.push(pluginManifest);
        }
      }
      supplyChainPaths.push(dependencyRoot);
      const dependencyManifest = join(dependencyRoot, 'package.json');
      if (existsSync(dependencyManifest)) {
        directDependencyPaths.add(dependencyManifest);
        urlScanPaths.push(dependencyManifest);
      }
    }
  }

  return {
    skillRoots: sortedUnique(skillRoots),
    pluginRoots: await canonicalSortedUnique(pluginRoots, directDependencyPaths),
    installedPluginDirs: await canonicalSortedUnique(installedPluginDirs, directDependencyPaths),
    supplyChainPaths: await canonicalSortedUnique(supplyChainPaths, directDependencyPaths),
    urlScanPaths: await canonicalSortedUnique(urlScanPaths, directDependencyPaths),
  };
}

async function canonicalSortedUnique(paths: string[], preferredPaths: Set<string>): Promise<string[]> {
  const selected = new Map<string, string>();
  for (const path of paths) {
    const identity = await realpath(path).catch(() => resolve(path));
    const current = selected.get(identity);
    if (!current || (preferredPaths.has(path) && !preferredPaths.has(current))) {
      selected.set(identity, path);
    }
  }
  return [...selected.values()].sort();
}

async function discoverReferencedBundlePlugins(bundleRoot: string, profileRoot: string): Promise<string[]> {
  const discovered: string[] = [];
  const visited = new Set<string>();

  async function visit(packageRoot: string, depth: number, isRoot = false): Promise<void> {
    if (depth > MAX_BUNDLE_DEPTH || (!isRoot && discovered.length >= MAX_BUNDLE_PLUGINS)) return;
    const identity = await realpath(packageRoot).catch(() => resolve(packageRoot));
    if (visited.has(identity)) return;
    visited.add(identity);
    if (!isRoot) discovered.push(packageRoot);

    const manifest = await readPackageManifest(join(packageRoot, 'package.json'));
    if (!manifest?.bundlePatch) return;
    const patchPath = normalizeBundlePatchPath(manifest.bundlePatch);
    if (!patchPath) return;
    const cordis = await parseCordisConfigs(identity);
    const referencedNames = sortedUnique(cordis.rows
      .filter(row => row.file.replace(/\\/g, '/') === patchPath)
      .flatMap(row => {
        const name = packageNameFromSpecifier(row.name);
        return name && manifest.dependencyNames.includes(name) ? [name] : [];
      }));

    for (const name of referencedNames) {
      if (name === '@goplus/agentguard') continue;
      const childRoot = await resolveInstalledDependency(packageRoot, profileRoot, name);
      if (!childRoot) continue;
      await visit(childRoot, depth + 1);
    }
  }

  await visit(bundleRoot, 0, true);
  return sortedUnique(discovered);
}

async function resolveInstalledDependency(
  packageRoot: string,
  profileRoot: string,
  name: string,
): Promise<string | undefined> {
  const packageSegments = name.split('/');
  const boundary = await realpath(profileRoot).catch(() => resolve(profileRoot));
  let current = await realpath(packageRoot).catch(() => resolve(packageRoot));
  while (isWithinBoundary(current, boundary)) {
    const candidate = join(current, 'node_modules', ...packageSegments);
    if (existsSync(candidate)) {
      const physicalCandidate = await realpath(candidate).catch(() => resolve(candidate));
      if (isWithinBoundary(physicalCandidate, boundary)) {
        const manifest = await readPackageManifest(join(physicalCandidate, 'package.json'));
        if (manifest?.name === name) return await mapToProfilePath(physicalCandidate, profileRoot);
      }
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return undefined;
}

function isWithinBoundary(path: string, boundary: string): boolean {
  return path === boundary || path.startsWith(`${boundary}${sep}`);
}

async function mapToProfilePath(path: string, profileRoot: string): Promise<string> {
  const physicalProfileRoot = await realpath(profileRoot).catch(() => resolve(profileRoot));
  if (path === physicalProfileRoot) return resolve(profileRoot);
  if (path.startsWith(`${physicalProfileRoot}${sep}`)) {
    return join(resolve(profileRoot), relative(physicalProfileRoot, path));
  }
  return path;
}

function normalizeBundlePatchPath(path: string): string | undefined {
  if (isAbsolute(path)) return undefined;
  const normalized = path.replace(/\\/g, '/').replace(/^\.\//, '');
  if (!normalized || normalized.split('/').some(segment => segment === '..')) return undefined;
  return normalized;
}

function packageNameFromSpecifier(specifier: unknown): string | undefined {
  if (typeof specifier !== 'string' || specifier.startsWith('.') || specifier.startsWith('/')) return undefined;
  const parts = specifier.split('/');
  const name = specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  return name && isSafePackageName(name) ? name : undefined;
}

function addCordisPatches(root: string, pluginRoots: string[], urlScanPaths: string[]): void {
  for (const filename of CORDIS_PATCH_FILENAMES) {
    const path = join(root, filename);
    if (!existsSync(path)) continue;
    pluginRoots.push(path);
    urlScanPaths.push(path);
  }
}

async function readDirectDependencyNames(manifestPath: string): Promise<string[]> {
  return (await readPackageManifest(manifestPath))?.dependencyNames ?? [];
}

interface PackageManifestInfo {
  name?: string;
  dependencyNames: string[];
  bundlePatch?: string;
}

async function readPackageManifest(manifestPath: string): Promise<PackageManifestInfo | undefined> {
  try {
    const info = await stat(manifestPath);
    if (!info.isFile() || info.size > MAX_PROFILE_MANIFEST_BYTES) return undefined;
    const parsed: unknown = JSON.parse(await readFile(manifestPath, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    const manifest = parsed as Record<string, unknown>;
    const names: string[] = [];
    for (const field of ['dependencies', 'optionalDependencies']) {
      const dependencies = manifest[field];
      if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) continue;
      for (const name of Object.keys(dependencies as Record<string, unknown>)) {
        if (isSafePackageName(name)) names.push(name);
      }
    }
    const dsh = manifest.dsh && typeof manifest.dsh === 'object' && !Array.isArray(manifest.dsh)
      ? manifest.dsh as Record<string, unknown>
      : undefined;
    const bundle = dsh?.bundle;
    const bundlePatch = typeof bundle === 'string'
      ? bundle
      : bundle && typeof bundle === 'object' && !Array.isArray(bundle)
        ? (bundle as Record<string, unknown>).patch
        : undefined;
    return {
      name: typeof manifest.name === 'string' ? manifest.name : undefined,
      dependencyNames: sortedUnique(names),
      bundlePatch: typeof bundlePatch === 'string' ? bundlePatch : undefined,
    };
  } catch {
    return undefined;
  }
}

function isSafePackageName(name: string): boolean {
  if (name.length === 0 || name.length > 214 || name.includes('\\')) return false;
  const parts = name.split('/');
  if (name.startsWith('@')) {
    if (parts.length !== 2 || !parts[0]?.startsWith('@')) return false;
    return isSafePackageSegment(parts[0].slice(1)) && isSafePackageSegment(parts[1] ?? '');
  }
  return parts.length === 1 && isSafePackageSegment(parts[0] ?? '');
}

function isSafePackageSegment(value: string): boolean {
  return value.length > 0
    && value !== '.'
    && value !== '..'
    && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
}

function existingPaths(paths: string[]): string[] {
  return paths.filter(path => existsSync(path));
}

function sortedUnique(paths: string[]): string[] {
  return [...new Set(paths)].sort((left, right) => left.localeCompare(right));
}
