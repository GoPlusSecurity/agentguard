import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { access } from 'node:fs/promises';
import { createServer } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dshBin = resolve(process.env.DSH_E2E_BIN ?? join(repoRoot, '.dsh-runtime/node_modules/.bin/dsh'));
const dshHome = resolve(process.env.DSH_E2E_HOME ?? join(repoRoot, '.dsh-home'));
const profileDir = join(dshHome, 'profiles/web');
const installedPlugin = join(profileDir, 'node_modules/@goplus/agentguard/dist/dsh/plugin.js');
const safeFixture = join(repoRoot, 'src/tests/fixtures/dsh-eval/safe-theme');
const localLoaderFixture = join(repoRoot, 'src/tests/fixtures/dsh-eval/data-local-loader');
const vendoredLibraryFixture = join(repoRoot, 'src/tests/fixtures/dsh-eval/vendored-static-library');
const generatedRuntimeFixture = join(repoRoot, 'src/tests/fixtures/dsh-eval/generated-runtime');

await Promise.all([
  access(dshBin),
  access(installedPlugin),
  access(safeFixture),
  access(localLoaderFixture),
  access(vendoredLibraryFixture),
  access(generatedRuntimeFixture),
]);

const env = { ...process.env, DSH_HOME: dshHome, DSH_TELEMETRY_MODE: 'DISABLED' };
const dumped = spawnSync(dshBin, ['web', '--dump-config'], {
  cwd: repoRoot,
  env,
  encoding: 'utf8',
});
assert.equal(dumped.status, 0, dumped.stderr || dumped.stdout);
assert.match(dumped.stdout, /id:\s*agentguard-dsh-plugin/);
assert.match(dumped.stdout, /@goplus\/agentguard\/dist\/dsh\/plugin\.js/);

const plugin = await import(`${pathToFileURL(installedPlugin).href}?e2e=${Date.now()}`);
const registeredTools = [];
plugin.apply({ tools: { register(tool) { registeredTools.push(tool); } } });
const registered = registeredTools.find(tool => tool.name === 'agentguard_dsh_scan');
const registeredBatch = registeredTools.find(tool => tool.name === 'agentguard_dsh_scan_batch');
assert.ok(registered);
assert.ok(registeredBatch);
const scan = await registered.execute({ target: safeFixture, format: 'json' });
assert.match(scan.scannerVersion, /^\d+\.\d+\.\d+/);
assert.equal(scan.rulesBaseline, '367227cc2b8bc064af369bf41e4490f6c4d3ea8b');
assert.equal(scan.phase, 'phase1-rc2');
assert.equal(scan.riskLevel, 'low');
assert.equal(scan.installRecommendation, 'safe-to-try');
assert.equal(scan.runtimeSurfaceRiskLevel, 'low');
assert.equal(scan.runtimeSurfaceRecommendation, 'safe-to-try');
assert.equal(scan.reviewPriority, 'routine');
const safeReport = JSON.parse(scan.content);
assert.equal(safeReport.schemaVersion, 1);
assert.equal(safeReport.scanner.version, scan.scannerVersion);
assert.equal(safeReport.scanner.rulesBaseline, scan.rulesBaseline);

const localLoaderScan = await registered.execute({ target: localLoaderFixture, format: 'json' });
const localLoaderReport = JSON.parse(localLoaderScan.content);
assert.equal(localLoaderScan.riskLevel, 'high');
assert.equal(localLoaderScan.runtimeSurfaceRiskLevel, 'high');
assert.ok(localLoaderReport.runtimeSurfaceRiskTags.includes('DYNAMIC_MODULE_LOADING'));
assert.ok(!localLoaderReport.runtimeSurfaceRiskTags.includes('REMOTE_LOADER'));

const vendoredLibraryScan = await registered.execute({ target: vendoredLibraryFixture, format: 'json' });
const vendoredLibraryReport = JSON.parse(vendoredLibraryScan.content);
assert.equal(vendoredLibraryScan.riskLevel, 'high');
assert.equal(vendoredLibraryScan.runtimeSurfaceRiskLevel, 'high');
assert.ok(!vendoredLibraryReport.riskTags.includes('AUTO_UPDATE'));

const generatedRuntimeScan = await registered.execute({ target: generatedRuntimeFixture, format: 'json' });
const generatedRuntimeReport = JSON.parse(generatedRuntimeScan.content);
assert.ok(generatedRuntimeReport.runtimeSurfaceRiskTags.includes('DYNAMIC_CODE_EXECUTION'));
assert.ok(!generatedRuntimeReport.runtimeSurfaceRiskTags.includes('OBFUSCATION'));
assert.ok(generatedRuntimeReport.findings.some(finding =>
  finding.ruleId === 'DYNAMIC_CODE_EXECUTION' && finding.occurrenceCount === 1 && finding.likelyGenerated));
const batchScan = await registeredBatch.execute({ targets: [{ target: safeFixture }, { target: localLoaderFixture }] });
assert.equal(batchScan.succeeded, 2);
assert.equal(batchScan.highestRuntimeSurfaceRisk, 'high');

const port = await new Promise((resolvePort, reject) => {
  const server = createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => {
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const selected = address.port;
    server.close(error => error ? reject(error) : resolvePort(selected));
  });
});

const child = spawn(dshBin, ['web', '--host', '127.0.0.1', '--port', String(port)], {
  cwd: repoRoot,
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let output = '';
child.stdout.on('data', chunk => { output += chunk; });
child.stderr.on('data', chunk => { output += chunk; });

try {
  const deadline = Date.now() + 20_000;
  let status;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`DSH exited before readiness (${child.exitCode})\n${output}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      if (response.ok) {
        status = response.status;
        break;
      }
    } catch {
      // DSH is still booting.
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 100));
  }
  assert.equal(status, 200, `DSH did not become ready\n${output}`);
  console.log(JSON.stringify({
    profileComposed: true,
    runtimeHttpStatus: status,
    tool: registered.name,
    batchTool: registeredBatch.name,
    scanRisk: scan.riskLevel,
    runtimeSurfaceRisk: scan.runtimeSurfaceRiskLevel,
    scanRecommendation: scan.installRecommendation,
    reviewPriority: scan.reviewPriority,
    localDynamicLoadingRisk: localLoaderScan.runtimeSurfaceRiskLevel,
    vendoredLibraryAutoUpdate: vendoredLibraryReport.riskTags.includes('AUTO_UPDATE'),
    generatedRuntimeTag: generatedRuntimeReport.runtimeSurfaceRiskTags.includes('DYNAMIC_CODE_EXECUTION'),
  }));
} finally {
  child.kill('SIGTERM');
  await Promise.race([
    new Promise(resolveExit => child.once('exit', resolveExit)),
    new Promise(resolveWait => setTimeout(resolveWait, 2_000)),
  ]);
  if (child.exitCode === null) child.kill('SIGKILL');
}
