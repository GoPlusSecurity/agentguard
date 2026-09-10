import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { it } from 'node:test';
import assert from 'node:assert/strict';
import {
  execCommand,
  inspectWindowsThreatFeedTask,
  installThreatFeedCron,
  removeThreatFeedCron,
} from '../feed/cron.js';

const WINDOWS_INTEGRATION_ENABLED =
  process.platform === 'win32' && process.env.AGENTGUARD_WINDOWS_SCHEDULER_INTEGRATION === '1';

async function waitForFile(path: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${path}`);
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

it('creates, queries, runs, ends, and deletes a real current-user Windows scheduled task', {
  skip: WINDOWS_INTEGRATION_ENABLED
    ? false
    : 'set AGENTGUARD_WINDOWS_SCHEDULER_INTEGRATION=1 on Windows to run',
}, async () => {
  const name = `agentguard-test-${randomUUID()}`;
  const home = mkdtempSync(join(tmpdir(), 'agentguard-windows-integration-'));
  const helperPath = join(home, 'long-running-runner.mjs');
  const processMarkerPath = join(home, 'runner-processes.json');
  const cronModuleUrl = pathToFileURL(join(process.cwd(), 'dist', 'feed', 'cron.js')).href;
  writeFileSync(helperPath, [
    "import { spawn } from 'node:child_process';",
    "import { writeFileSync } from 'node:fs';",
    `import { runWindowsCronTick } from ${JSON.stringify(cronModuleUrl)};`,
    `const markerPath = ${JSON.stringify(processMarkerPath)};`,
    "if (process.argv[2] === 'windows-cron-run') {",
    "  const index = process.argv.indexOf('--config');",
    "  await runWindowsCronTick(process.argv[index + 1]);",
    "} else if (process.argv[2] === 'subscribe') {",
    "  const grandchild = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });",
    "  writeFileSync(markerPath, JSON.stringify({ childPid: process.pid, grandchildPid: grandchild.pid }));",
    "  setInterval(() => {}, 1000);",
    "}",
    '',
  ].join('\n'));
  let spawnedPids: number[] = [];
  try {
    const installed = await installThreatFeedCron({
      name,
      cronExpression: '* * * * *',
      quiet: true,
      force: false,
      backend: 'windows',
      agentHost: 'codex',
      agentGuardHome: home,
      timezone: 'UTC',
    }, {
      nodeExecutable: process.execPath,
      cliEntrypoint: helperPath,
    });
    assert.equal(installed.backend, 'windows-task-scheduler');
    assert.equal(installed.created, true);

    const status = await inspectWindowsThreatFeedTask({ name, agentGuardHome: home });
    assert.equal(status.installed, true);
    assert.equal(status.cronExpression, '* * * * *');

    await execCommand('schtasks.exe', ['/Run', '/TN', `AgentGuard-${name}`]);
    await waitForFile(processMarkerPath);
    const marker = JSON.parse(readFileSync(processMarkerPath, 'utf8')) as {
      childPid: number;
      grandchildPid: number;
    };
    spawnedPids = [marker.childPid, marker.grandchildPid];
    assert.equal(spawnedPids.every(processIsAlive), true);
  } finally {
    const removal = await removeThreatFeedCron({
      name,
      backend: 'windows',
      agentGuardHome: home,
    });
    assert.equal(removal[0]?.error, undefined);
  }
  assert.equal(spawnedPids.length, 2);
  assert.equal(spawnedPids.some(processIsAlive), false);
});
