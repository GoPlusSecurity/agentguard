import * as crypto from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * Calculate SHA256 hash of a string
 */
export function sha256(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Calculate SHA256 hash of a file
 */
export async function hashFile(filePath: string): Promise<string> {
  const content = await fs.readFile(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Calculate SHA256 hash of a directory (deterministic)
 */
export async function hashDirectory(dirPath: string): Promise<string> {
  const hash = crypto.createHash('sha256');
  const files: { path: string; content: Buffer }[] = [];

  // Recursively collect all files
  async function collectFiles(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Skip common non-content directories
      if (
        entry.name === 'node_modules' ||
        entry.name === '.git' ||
        entry.name === 'dist' ||
        entry.name === '__pycache__'
      ) {
        continue;
      }

      if (entry.isDirectory()) {
        await collectFiles(fullPath);
      } else if (entry.isFile()) {
        const content = await fs.readFile(fullPath);
        files.push({
          path: path.relative(dirPath, fullPath),
          content,
        });
      }
    }
  }

  await collectFiles(dirPath);

  // Sort files by path for deterministic hashing
  files.sort((a, b) => a.path.localeCompare(b.path));

  // Hash each file path and content
  for (const file of files) {
    hash.update(file.path);
    hash.update(file.content);
  }

  return `sha256:${hash.digest('hex')}`;
}

/**
 * Generate a short hash for display
 */
export function shortHash(hash: string, length: number = 8): string {
  const cleanHash = hash.replace(/^sha256:/, '');
  return cleanHash.slice(0, length);
}

/**
 * Verify a hash matches content
 */
export function verifyHash(content: string, expectedHash: string): boolean {
  const actualHash = sha256(content);
  const cleanExpected = expectedHash.replace(/^sha256:/, '');
  return actualHash === cleanExpected;
}
