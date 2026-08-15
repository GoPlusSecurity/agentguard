import { execFile } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const GITHUB_REPO = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/;

/** Normalize the exact HTTPS GitHub repository forms supported by Phase 1. */
export function normalizeGithubRepositoryUrl(input: string): string | undefined {
  const match = input.match(GITHUB_REPO);
  return match ? `https://github.com/${match[1]}/${match[2]}.git` : undefined;
}

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

async function resolveGithubHead(repositoryUrl: string): Promise<string> {
  const { stdout } = await execFileAsync('git', [
    '-c', 'core.hooksPath=/dev/null',
    'ls-remote', '--exit-code', '--', repositoryUrl, 'HEAD',
  ], { timeout: 30_000, maxBuffer: 1024 * 1024 });
  const revision = stdout.trim().split(/\s+/)[0];
  if (!revision || !/^[0-9a-f]{40,64}$/i.test(revision)) {
    throw new Error('GitHub repository did not advertise a valid HEAD revision');
  }
  return revision.toLowerCase();
}

async function requireGitForGithubScan(): Promise<void> {
  try {
    await execFileAsync('git', ['--version'], { timeout: 10_000, maxBuffer: 1024 * 1024 });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      throw new Error('GitHub repository scans require git, but no git executable was found in PATH');
    }
    throw new Error(`Unable to run git for GitHub repository scan: ${(error as Error).message}`);
  }
}

/** Resolve a local directory or HTTPS GitHub repository into a scan directory. */
export async function resolveDshSource(input: string): Promise<ResolvedDshSource> {
  const repositoryUrl = normalizeGithubRepositoryUrl(input);
  if (repositoryUrl) {
    const tempRoot = await mkdtemp(join(tmpdir(), 'agentguard-dsh-'));
    const rootDir = join(tempRoot, 'repo');
    try {
      await requireGitForGithubScan();
      const expectedRevision = await resolveGithubHead(repositoryUrl);
      await execFileAsync('git', ['-c', 'core.hooksPath=/dev/null', 'init', rootDir], { timeout: 10_000 });
      await execFileAsync('git', ['-C', rootDir, 'remote', 'add', 'origin', repositoryUrl], { timeout: 10_000 });
      await execFileAsync('git', [
        '-c', 'core.hooksPath=/dev/null',
        '-C', rootDir,
        'fetch', '--depth', '1', '--no-tags', 'origin', expectedRevision,
      ], { timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
      await execFileAsync('git', [
        '-c', 'core.hooksPath=/dev/null',
        '-C', rootDir,
        'checkout', '--detach', expectedRevision,
      ], { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
      const metadata = await gitMetadata(rootDir);
      if (metadata.revision?.toLowerCase() !== expectedRevision) {
        throw new Error(`Checked out ${metadata.revision ?? 'no revision'} instead of resolved HEAD ${expectedRevision}`);
      }
      return {
        rootDir,
        kind: 'github',
        input,
        repositoryUrl,
        ...metadata,
        cleanup: () => rm(tempRoot, { recursive: true, force: true }),
      };
    } catch (error) {
      await rm(tempRoot, { recursive: true, force: true });
      throw new Error(`Failed to fetch GitHub repository: ${(error as Error).message}`);
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
