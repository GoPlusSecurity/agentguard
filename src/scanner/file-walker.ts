import { glob } from 'glob';
import * as fs from 'fs/promises';
import * as path from 'path';
import { inspectRegularFileWithinRoot, UnsafeScanPathError } from './safe-file.js';
import type { ScanCoverage } from '../types/scanner.js';

/**
 * File info for scanning
 */
export interface FileInfo {
  /** Absolute path */
  path: string;
  /** Relative path from root */
  relativePath: string;
  /** File content */
  content: string;
  /** File extension */
  extension: string;
}

/**
 * Supported file extensions for scanning
 */
export const SCANNABLE_EXTENSIONS = [
  // JavaScript/TypeScript
  '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
  // Python
  '.py',
  // Configuration
  '.json', '.yaml', '.yml', '.toml',
  // Solidity
  '.sol',
  // Shell
  '.sh', '.bash',
  // Markdown (for prompt injection)
  '.md',
];

/**
 * Files to skip
 */
export const SKIP_PATTERNS = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/coverage/**',
  '**/__pycache__/**',
  '**/*.min.js',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
];

/** Limits keep untrusted repositories from exhausting scanner memory. */
export const MAX_SCANNABLE_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_SCANNABLE_FILES = 10_000;

export interface DirectoryScanSnapshot {
  files: FileInfo[];
  coverage: ScanCoverage;
}

export interface FileWalkerOptions {
  maxFiles?: number;
  maxFileBytes?: number;
  inspectFile?: typeof inspectRegularFileWithinRoot;
  readFile?: (filePath: string) => Promise<string>;
}

/**
 * Walk directory and collect scannable files
 */
export async function walkDirectory(rootDir: string): Promise<FileInfo[]> {
  return (await walkDirectoryWithCoverage(rootDir)).files;
}

/** Walk a directory and retain structured evidence for every skipped file. */
export async function walkDirectoryWithCoverage(
  rootDir: string,
  options: FileWalkerOptions = {},
): Promise<DirectoryScanSnapshot> {
  const files: FileInfo[] = [];
  const maxFiles = options.maxFiles ?? MAX_SCANNABLE_FILES;
  const maxFileBytes = options.maxFileBytes ?? MAX_SCANNABLE_FILE_BYTES;
  if (!Number.isInteger(maxFiles) || maxFiles < 1) throw new Error('maxFiles must be a positive integer');
  if (!Number.isInteger(maxFileBytes) || maxFileBytes < 1) throw new Error('maxFileBytes must be a positive integer');
  const inspectFile = options.inspectFile ?? inspectRegularFileWithinRoot;
  const readFile = options.readFile ?? ((filePath: string) => fs.readFile(filePath, 'utf-8'));

  // Build glob pattern for all scannable extensions
  const extensions = SCANNABLE_EXTENSIONS.map(e => e.slice(1)).join(',');
  const pattern = `**/*.{${extensions}}`;

  // Find all matching files
  const allMatches = await glob(pattern, {
    cwd: rootDir,
    ignore: SKIP_PATTERNS,
    nodir: true,
    absolute: true,
  });
  const matches = allMatches.sort().slice(0, maxFiles);
  const skippedByReason: ScanCoverage['skippedByReason'] = {
    fileLimit: Math.max(0, allMatches.length - matches.length),
    oversized: 0,
    unreadable: 0,
  };
  if (skippedByReason.fileLimit > 0) {
    console.warn(`Scanner file limit reached: scanning at most ${maxFiles} of ${allMatches.length} files`);
  }

  // Read file contents
  for (const filePath of matches) {
    try {
      const safeFile = await inspectFile(rootDir, filePath);
      if (safeFile.size > maxFileBytes) {
        skippedByReason.oversized++;
        console.warn(`Skipping oversized scan file: ${filePath} (${safeFile.size} bytes)`);
        continue;
      }
      const content = await readFile(safeFile.path);
      const relativePath = path.relative(rootDir, filePath);
      const extension = path.extname(filePath);

      files.push({
        path: filePath,
        relativePath,
        content,
        extension,
      });
    } catch (err) {
      if (err instanceof UnsafeScanPathError) {
        throw new Error(`Unsafe scan path ${path.relative(rootDir, filePath)}: ${err.message}`);
      }
      // Skip unreadable files
      skippedByReason.unreadable++;
      console.warn(`Failed to read file: ${filePath}`);
    }
  }

  const skipped = skippedByReason.fileLimit + skippedByReason.oversized + skippedByReason.unreadable;
  return {
    files,
    coverage: {
      discovered: allMatches.length,
      scanned: files.length,
      skipped,
      skippedByReason,
      complete: skipped === 0,
    },
  };
}

/**
 * Check if a path is a directory
 */
export async function isDirectory(dirPath: string): Promise<boolean> {
  try {
    const stat = await fs.stat(dirPath);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

/**
 * Check if a path exists
 */
export async function pathExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}
