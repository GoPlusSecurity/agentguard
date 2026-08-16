import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dshBin = resolve(process.env.DSH_PACKAGE_BIN ?? join(repoRoot, '.dsh-runtime/node_modules/.bin/dsh'));
const safeFixture = join(repoRoot, 'src/tests/fixtures/dsh-eval/safe-theme');
const tempRoot = await mkdtemp(join(tmpdir(), 'agentguard-dsh-package-'));
const dshHome = join(tempRoot, 'dsh-home');
const profileDir = join(dshHome, 'profiles/web');
const npmCache = join(tempRoot, 'npm-cache');
const env = {
  ...process.env,
  AGENTGUARD_HOME: join(tempRoot, 'agentguard-home'),
  AGENTGUARD_SKIP_PACKAGE_NEXT_STEPS: '1',
  DSH_HOME: dshHome,
  DSH_TELEMETRY_MODE: 'DISABLED',
  npm_config_cache: npmCache,
};

async function run(file, args, options = {}) {
  return execFileAsync(file, args, {
    cwd: repoRoot,
    env,
    timeout: 120_000,
    maxBuffer: 8 * 1024 * 1024,
    ...options,
  });
}

async function dsh(args) {
  return run(dshBin, args, { timeout: 180_000 });
}

try {
  await Promise.all([access(dshBin), access(safeFixture)]);

  const { stdout: packOutput } = await run('npm', ['pack', '--pack-destination', tempRoot, '--json']);
  const packResult = JSON.parse(packOutput);
  assert.equal(packResult.length, 1);
  const tarball = join(tempRoot, packResult[0].filename);
  await access(tarball);

  const { stdout: archiveOutput } = await run('tar', ['-tzf', tarball]);
  const archiveFiles = new Set(archiveOutput.trim().split('\n'));
  const required = [
    'package/package.json',
    'package/dsh.cordis.patch.yml',
    'package/dist/index.js',
    'package/dist/index.d.ts',
    'package/dist/dsh/plugin.js',
    'package/dist/dsh/plugin.d.ts',
    'package/dist/dsh/scan.js',
    'package/dist/dsh/metadata.js',
    'package/dist/reports/dsh-report.js',
    'package/docs/dsh.md',
  ];
  for (const path of required) assert.ok(archiveFiles.has(path), `tarball is missing ${path}`);
  assert.ok(![...archiveFiles].some(path => path.startsWith('package/dist/tests/')), 'tarball contains compiled tests');

  await dsh(['plugin', '--profile', 'web', 'add', tarball]);
  const installedManifest = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'));
  assert.ok(installedManifest.dependencies?.['@goplus/agentguard']);
  assert.ok(installedManifest.dsh?.profile?.bundles?.includes('@goplus/agentguard'));

  const { stdout: composed } = await dsh(['web', '--dump-config']);
  assert.match(composed, /id:\s*agentguard-dsh-plugin/);
  const installedPlugin = join(profileDir, 'node_modules/@goplus/agentguard/dist/dsh/plugin.js');
  const plugin = await import(`${pathToFileURL(installedPlugin).href}?package=${Date.now()}`);
  const registeredTools = [];
  plugin.apply({ tools: { register(tool) { registeredTools.push(tool); } } });
  const registered = registeredTools.find(tool => tool.name === 'agentguard_dsh_scan');
  const registeredBatch = registeredTools.find(tool => tool.name === 'agentguard_dsh_scan_batch');
  const registeredCompare = registeredTools.find(tool => tool.name === 'agentguard_dsh_compare');
  assert.ok(registered);
  assert.ok(registeredBatch);
  assert.ok(registeredCompare);
  const result = await registered.execute({ target: safeFixture, format: 'json' });
  assert.equal(result.runtimeSurfaceRiskLevel, 'low');
  assert.equal(result.phase, 'phase1-rc2');
  const batchResult = await registeredBatch.execute({ targets: [{ target: safeFixture }], format: 'json' });
  assert.equal(batchResult.succeeded, 1);

  await dsh(['plugin', '--profile', 'web', 'update', tarball]);
  const updatedManifest = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'));
  assert.ok(updatedManifest.dependencies?.['@goplus/agentguard']);
  assert.ok(updatedManifest.dsh?.profile?.bundles?.includes('@goplus/agentguard'));

  await dsh(['plugin', '--profile', 'web', 'remove', '@goplus/agentguard']);
  const removedManifest = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'));
  assert.equal(removedManifest.dependencies?.['@goplus/agentguard'], undefined);
  assert.ok(!removedManifest.dsh?.profile?.bundles?.includes('@goplus/agentguard'));

  console.log(JSON.stringify({
    tarball: packResult[0].filename,
    packedBytes: packResult[0].size,
    unpackedBytes: packResult[0].unpackedSize,
    entryCount: packResult[0].entryCount,
    requiredAssets: required.length,
    compiledTestsExcluded: true,
    installComposed: true,
    scanExecuted: true,
    updatePreservedComposition: true,
    uninstallRemoved: true,
    scannerVersion: result.scannerVersion,
    rulesBaseline: result.rulesBaseline,
  }));
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
