import { execFile } from 'node:child_process';
import { lstat, mkdtemp, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const GITHUB_REPO = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/;
export const MAX_GITHUB_ACQUISITION_BYTES = 256 * 1024 * 1024;
export const MAX_GITHUB_OBJECTS = 100_000;
const ACQUISITION_POLL_MS = 100;

async function directoryBytesWithinBudget(rootDir: string, maxBytes: number): Promise<number> {
  const pending = [rootDir];
  let bytes = 0;
  while (pending.length > 0) {
    const directory = pending.pop()!;
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw error;
    }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const info = await lstat(path);
      if (info.isSymbolicLink()) continue;
      if (info.isDirectory()) pending.push(path);
      else if (info.isFile()) {
        bytes += info.size;
        if (bytes > maxBytes) return bytes;
      }
    }
  }
  return bytes;
}

export async function assertDshAcquisitionByteBudget(
  rootDir: string,
  maxBytes = MAX_GITHUB_ACQUISITION_BYTES,
): Promise<void> {
  const bytes = await directoryBytesWithinBudget(rootDir, maxBytes);
  if (bytes > maxBytes) {
    throw new Error(`GitHub repository exceeds ${maxBytes} byte acquisition limit`);
  }
}

function execBoundedGit(args: string[], rootDir: string, timeout: number): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    let budgetError: Error | undefined;
    let checking = false;
    const child = execFile('git', args, {
      timeout,
      maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
    }, (error, stdout, stderr) => {
      clearInterval(monitor);
      if (budgetError) reject(budgetError);
      else if (error) reject(error);
      else resolvePromise({ stdout, stderr });
    });
    const monitor = setInterval(() => {
      if (checking || child.killed) return;
      checking = true;
      void assertDshAcquisitionByteBudget(rootDir).catch(error => {
        budgetError = error as Error;
        child.kill('SIGKILL');
      }).finally(() => {
        checking = false;
      });
    }, ACQUISITION_POLL_MS);
  });
}

async function assertGitObjectBudget(rootDir: string): Promise<void> {
  await assertDshAcquisitionByteBudget(rootDir);
  const { stdout } = await execFileAsync('git', ['-C', rootDir, 'count-objects', '-v'], {
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
  });
  const values = Object.fromEntries(stdout.trim().split('\n').map(line => {
    const [key, value] = line.split(':', 2);
    return [key, Number(value?.trim())];
  }));
  const objects = (values.count || 0) + (values['in-pack'] || 0);
  if (objects > MAX_GITHUB_OBJECTS) {
    throw new Error(`GitHub repository exceeds ${MAX_GITHUB_OBJECTS} Git object acquisition limit`);
  }
}

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
      await execBoundedGit([
        '-c', 'core.hooksPath=/dev/null',
        '-C', rootDir,
        'fetch', '--depth', '1', '--no-tags', '--filter=blob:none', 'origin', expectedRevision,
      ], rootDir, 120_000);
      await assertGitObjectBudget(rootDir);
      await execBoundedGit([
        '-c', 'core.hooksPath=/dev/null',
        '-C', rootDir,
        'checkout', '--detach', expectedRevision,
      ], rootDir, 30_000);
      await assertGitObjectBudget(rootDir);
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
