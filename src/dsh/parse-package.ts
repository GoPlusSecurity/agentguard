import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { DshPackageMetadata } from './types.js';
import { MAX_SCANNABLE_FILE_BYTES } from '../scanner/file-walker.js';
import { inspectRegularFileWithinRoot } from '../scanner/safe-file.js';

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
  const path = join(rootDir, 'package.json');
  let raw: string;
  try {
    const safeFile = await inspectRegularFileWithinRoot(rootDir, path);
    if (safeFile.size > MAX_SCANNABLE_FILE_BYTES) {
      return { ...EMPTY_METADATA, parseError: `package.json exceeds ${MAX_SCANNABLE_FILE_BYTES} byte scan limit` };
    }
    raw = await readFile(safeFile.path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { ...EMPTY_METADATA };
    return { ...EMPTY_METADATA, parseError: (error as Error).message };
  }

  try {
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
    const clientValue = dsh.client;
    const clientObject = clientValue && typeof clientValue === 'object' && !Array.isArray(clientValue)
      ? clientValue as Record<string, unknown>
      : undefined;
    const clientPlatform = clientObject?.platform;
    const clientInject = clientObject?.inject;
    const validClient = clientObject !== undefined
      && typeof clientPlatform === 'string'
      && clientPlatform.trim().length > 0
      && (clientInject === undefined
        || (Array.isArray(clientInject) && clientInject.every(value => typeof value === 'string')));
    const clientError = clientValue !== undefined && !validClient
      ? 'Invalid dsh.client: expected a non-empty platform string and an optional string-array inject field'
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
      hasClientExtension: validClient,
      clientPlatform: validClient ? clientPlatform : undefined,
      scripts: stringRecord(manifest.scripts),
      dependencies: Object.keys(dependencies).sort(),
      parseError: clientError,
    };
  } catch (error) {
    return { ...EMPTY_METADATA, parseError: `Invalid package.json: ${(error as Error).message}` };
  }
}
