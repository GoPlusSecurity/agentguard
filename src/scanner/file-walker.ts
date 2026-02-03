import { glob } from 'glob';
import * as fs from 'fs/promises';
import * as path from 'path';

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

/**
 * Walk directory and collect scannable files
 */
export async function walkDirectory(rootDir: string): Promise<FileInfo[]> {
  const files: FileInfo[] = [];

  // Build glob pattern for all scannable extensions
  const extensions = SCANNABLE_EXTENSIONS.map(e => e.slice(1)).join(',');
  const pattern = `**/*.{${extensions}}`;

  // Find all matching files
  const matches = await glob(pattern, {
    cwd: rootDir,
    ignore: SKIP_PATTERNS,
    nodir: true,
    absolute: true,
  });

  // Read file contents
  for (const filePath of matches) {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const relativePath = path.relative(rootDir, filePath);
      const extension = path.extname(filePath);

      files.push({
        path: filePath,
        relativePath,
        content,
        extension,
      });
    } catch (err) {
      // Skip unreadable files
      console.warn(`Failed to read file: ${filePath}`);
    }
  }

  return files;
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
