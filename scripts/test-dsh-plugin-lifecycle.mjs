import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dshBin = resolve(process.env.DSH_LIFECYCLE_BIN ?? join(repoRoot, '.dsh-runtime/node_modules/.bin/dsh'));
const safeFixture = join(repoRoot, 'src/tests/fixtures/dsh-eval/safe-theme');
const dshHome = await mkdtemp(join(tmpdir(), 'agentguard-dsh-lifecycle-'));
const profileDir = join(dshHome, 'profiles/web');
const env = { ...process.env, DSH_HOME: dshHome, DSH_TELEMETRY_MODE: 'DISABLED' };

async function dsh(args) {
  return execFileAsync(dshBin, args, {
    cwd: repoRoot,
    env,
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
}

try {
  await Promise.all([access(dshBin), access(safeFixture)]);

  await dsh(['plugin', '--profile', 'web', 'add', `link:${repoRoot}`]);
  const installedManifest = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'));
  assert.equal(installedManifest.dependencies?.['@goplus/agentguard'], `link:${repoRoot}`);
  assert.ok(installedManifest.dsh?.profile?.bundles?.includes('@goplus/agentguard'));

  const { stdout: composed } = await dsh(['web', '--dump-config']);
  assert.match(composed, /id:\s*agentguard-dsh-plugin/);
  assert.match(composed, /@goplus\/agentguard\/dist\/dsh\/plugin\.js/);

  const installedPlugin = join(profileDir, 'node_modules/@goplus/agentguard/dist/dsh/plugin.js');
  await access(installedPlugin);
  const plugin = await import(`${pathToFileURL(installedPlugin).href}?lifecycle=${Date.now()}`);
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
  assert.match(result.scannerVersion, /^\d+\.\d+\.\d+/);
  assert.match(result.rulesBaseline, /^[0-9a-f]{40}$/);
  const batchResult = await registeredBatch.execute({ targets: [{ target: safeFixture }] });
  assert.equal(batchResult.succeeded, 1);

  await dsh(['plugin', '--profile', 'web', 'remove', '@goplus/agentguard']);
  const removedManifest = JSON.parse(await readFile(join(profileDir, 'package.json'), 'utf8'));
  assert.equal(removedManifest.dependencies?.['@goplus/agentguard'], undefined);
  assert.ok(!removedManifest.dsh?.profile?.bundles?.includes('@goplus/agentguard'));
  const { stdout: removedComposition } = await dsh(['web', '--dump-config']);
  assert.doesNotMatch(removedComposition, /agentguard-dsh-plugin/);

  console.log(JSON.stringify({
    cleanProfile: true,
    installComposed: true,
    scanExecuted: true,
    uninstallRemoved: true,
    scannerVersion: result.scannerVersion,
    phase: result.phase,
    rulesBaseline: result.rulesBaseline,
  }));
} finally {
  await rm(dshHome, { recursive: true, force: true });
}
