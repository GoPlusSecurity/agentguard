import { lstat, realpath, stat } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';

export interface SafeRegularFile {
  path: string;
  size: number;
}

export class UnsafeScanPathError extends Error {}

/** Resolve a regular file while allowing only symlinks whose final target remains inside the scan root. */
export async function inspectRegularFileWithinRoot(rootDir: string, filePath: string): Promise<SafeRegularFile> {
  const absoluteRoot = await realpath(resolve(rootDir));
  const absoluteInput = resolve(filePath);
  const inputInfo = await lstat(absoluteInput);
  let resolvedFile: string;
  try {
    resolvedFile = await realpath(absoluteInput);
  } catch (error) {
    if (inputInfo.isSymbolicLink()) throw new UnsafeScanPathError('symbolic link target cannot be resolved');
    throw error;
  }
  const pathFromRoot = relative(absoluteRoot, resolvedFile);
  if (pathFromRoot === '..' || pathFromRoot.startsWith(`..${sep}`) || resolve(absoluteRoot, pathFromRoot) !== resolvedFile) {
    throw new UnsafeScanPathError('file resolves outside the scan root');
  }
  const resolvedInfo = await stat(resolvedFile);
  if (!resolvedInfo.isFile()) throw new Error('path is not a regular file');
  return { path: resolvedFile, size: resolvedInfo.size };
}
