import { execFile } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const GITHUB_REPO = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/;

export interface ResolvedDshSource {
  rootDir: string;
  kind: 'local' | 'github';
  input: string;
  repositoryUrl?: string;
  revision?: string;
  lastCommitAt?: string;
  cleanup(): Promise<void>;
}

async function gitMetadata(rootDir: string): Promise<{ revision?: string; lastCommitAt?: string }> {
  try {
    const [{ stdout: revision }, { stdout: lastCommitAt }] = await Promise.all([
      execFileAsync('git', ['-C', rootDir, 'rev-parse', 'HEAD'], { timeout: 10_000 }),
      execFileAsync('git', ['-C', rootDir, 'show', '-s', '--format=%cI', 'HEAD'], { timeout: 10_000 }),
    ]);
    return { revision: revision.trim(), lastCommitAt: lastCommitAt.trim() };
  } catch {
    return {};
  }
}

/** Resolve a local directory or HTTPS GitHub repository into a scan directory. */
export async function resolveDshSource(input: string): Promise<ResolvedDshSource> {
  const github = input.match(GITHUB_REPO);
  if (github) {
    const tempRoot = await mkdtemp(join(tmpdir(), 'agentguard-dsh-'));
    const rootDir = join(tempRoot, 'repo');
    try {
      await execFileAsync('git', [
        '-c', 'core.hooksPath=/dev/null',
        'clone', '--depth', '1', '--single-branch', '--no-recurse-submodules', '--', input, rootDir,
      ], { timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
      const metadata = await gitMetadata(rootDir);
      return {
        rootDir,
        kind: 'github',
        input,
        repositoryUrl: input,
        ...metadata,
        cleanup: () => rm(tempRoot, { recursive: true, force: true }),
      };
    } catch (error) {
      await rm(tempRoot, { recursive: true, force: true });
      throw new Error(`Failed to clone GitHub repository: ${(error as Error).message}`);
    }
  }

  if (/^https?:\/\//i.test(input)) {
    throw new Error('Only HTTPS GitHub repository URLs are supported in Phase 1.');
  }
  const rootDir = resolve(input);
  try {
    const info = await stat(rootDir);
    if (!info.isDirectory()) throw new Error('not a directory');
  } catch {
    throw new Error(`Local plugin directory not found: ${rootDir}`);
  }
  const metadata = await gitMetadata(rootDir);
  return {
    rootDir,
    kind: 'local',
    input,
    ...metadata,
    cleanup: async () => undefined,
  };
}
