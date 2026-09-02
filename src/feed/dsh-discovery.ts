import { existsSync, type Dirent } from 'node:fs';
import { readFile, readdir, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

const MAX_PROFILE_MANIFEST_BYTES = 1_000_000;
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
 * Discover DSH-owned self-check inputs without recursively walking profile
 * dependency trees. Environment defaults are intentionally resolved per call.
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
      pluginRoots.push(dependencyRoot);
      installedPluginDirs.push(dependencyRoot);
      supplyChainPaths.push(dependencyRoot);
      const dependencyManifest = join(dependencyRoot, 'package.json');
      if (existsSync(dependencyManifest)) urlScanPaths.push(dependencyManifest);
    }
  }

  return {
    skillRoots: sortedUnique(skillRoots),
    pluginRoots: sortedUnique(pluginRoots),
    installedPluginDirs: sortedUnique(installedPluginDirs),
    supplyChainPaths: sortedUnique(supplyChainPaths),
    urlScanPaths: sortedUnique(urlScanPaths),
  };
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
  try {
    const info = await stat(manifestPath);
    if (!info.isFile() || info.size > MAX_PROFILE_MANIFEST_BYTES) return [];
    const parsed: unknown = JSON.parse(await readFile(manifestPath, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
    const manifest = parsed as Record<string, unknown>;
    const names: string[] = [];
    for (const field of ['dependencies', 'optionalDependencies']) {
      const dependencies = manifest[field];
      if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) continue;
      for (const name of Object.keys(dependencies as Record<string, unknown>)) {
        if (isSafePackageName(name)) names.push(name);
      }
    }
    return sortedUnique(names);
  } catch {
    return [];
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
