import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { DshPackageMetadata } from './types.js';
import { MAX_SCANNABLE_FILE_BYTES } from '../scanner/file-walker.js';

const EMPTY_METADATA: DshPackageMetadata = {
  profileBundles: [],
  hasClientExtension: false,
  scripts: {},
  dependencies: [],
};

function stringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === 'string'),
  );
}

function repositoryUrl(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && typeof (value as { url?: unknown }).url === 'string') {
    return (value as { url: string }).url;
  }
  return undefined;
}

/** Parse the DSH-relevant subset of a package manifest without executing package code. */
export async function parseDshPackage(rootDir: string): Promise<DshPackageMetadata> {
  try {
    const path = join(rootDir, 'package.json');
    if ((await stat(path)).size > MAX_SCANNABLE_FILE_BYTES) return { ...EMPTY_METADATA };
    const raw = await readFile(path, 'utf8');
    const manifest = JSON.parse(raw) as Record<string, unknown>;
    const dsh = manifest.dsh && typeof manifest.dsh === 'object'
      ? manifest.dsh as Record<string, unknown>
      : {};
    const bundle = dsh.bundle && typeof dsh.bundle === 'object'
      ? dsh.bundle as Record<string, unknown>
      : {};
    const profile = dsh.profile && typeof dsh.profile === 'object'
      ? dsh.profile as Record<string, unknown>
      : {};
    const client = dsh.client && typeof dsh.client === 'object'
      ? dsh.client as Record<string, unknown>
      : undefined;
    const dependencies = {
      ...stringRecord(manifest.dependencies),
      ...stringRecord(manifest.peerDependencies),
      ...stringRecord(manifest.optionalDependencies),
    };

    return {
      name: typeof manifest.name === 'string' ? manifest.name : undefined,
      description: typeof manifest.description === 'string' ? manifest.description : undefined,
      version: typeof manifest.version === 'string' ? manifest.version : undefined,
      repositoryUrl: repositoryUrl(manifest.repository),
      bundlePatch: typeof bundle.patch === 'string'
        ? bundle.patch
        : typeof dsh.bundle === 'string' ? dsh.bundle : undefined,
      profileBundles: Array.isArray(profile.bundles)
        ? profile.bundles.filter((value): value is string => typeof value === 'string')
        : [],
      hasClientExtension: Boolean(client),
      clientPlatform: client && typeof client.platform === 'string' ? client.platform : undefined,
      scripts: stringRecord(manifest.scripts),
      dependencies: Object.keys(dependencies).sort(),
    };
  } catch {
    return { ...EMPTY_METADATA };
  }
}
