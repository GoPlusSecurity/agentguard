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

await Promise.all([access(dshBin), access(installedPlugin), access(safeFixture)]);

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
let registered;
plugin.apply({ tools: { register(tool) { registered = tool; } } });
assert.equal(registered?.name, 'agentguard_dsh_scan');
const scan = await registered.execute({ target: safeFixture, format: 'json' });
assert.equal(scan.riskLevel, 'low');
assert.equal(scan.installRecommendation, 'safe-to-try');
assert.equal(scan.runtimeSurfaceRiskLevel, 'low');
assert.equal(scan.runtimeSurfaceRecommendation, 'safe-to-try');
assert.equal(scan.reviewPriority, 'routine');
assert.equal(JSON.parse(scan.content).schemaVersion, 1);

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
    scanRisk: scan.riskLevel,
    runtimeSurfaceRisk: scan.runtimeSurfaceRiskLevel,
    scanRecommendation: scan.installRecommendation,
    reviewPriority: scan.reviewPriority,
  }));
} finally {
  child.kill('SIGTERM');
  await Promise.race([
    new Promise(resolveExit => child.once('exit', resolveExit)),
    new Promise(resolveWait => setTimeout(resolveWait, 2_000)),
  ]);
  if (child.exitCode === null) child.kill('SIGKILL');
}
