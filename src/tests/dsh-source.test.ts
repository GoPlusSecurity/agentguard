import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  removeDshTempRoot,
  runWithDshCleanup,
  startDshAcquisitionMonitor,
} from '../dsh/source.js';
import { scanDshPlugin } from '../dsh/scan.js';
import { renderDshHtml, renderDshMarkdown } from '../reports/dsh-report.js';

function busyError(): NodeJS.ErrnoException {
  const error = new Error('resource busy or locked') as NodeJS.ErrnoException;
  error.code = 'EBUSY';
  return error;
}

describe('DSH GitHub source cleanup', () => {
  it('enables retries when requesting recursive temporary directory removal', async () => {
    let receivedOptions: Parameters<typeof rm>[1];
    await removeDshTempRoot('temporary-checkout', async (_path, options) => {
      receivedOptions = options;
    });

    assert.equal(receivedOptions!.recursive, true);
    assert.equal(receivedOptions!.force, true);
    assert.ok((receivedOptions!.maxRetries ?? 0) > 0);
    assert.ok((receivedOptions!.retryDelay ?? 0) > 0);
  });

  it('waits for an in-flight acquisition budget check before stopping', async () => {
    let markStarted!: () => void;
    const started = new Promise<void>(resolve => { markStarted = resolve; });
    let releaseCheck!: () => void;
    const release = new Promise<void>(resolve => { releaseCheck = resolve; });
    const child = { killed: false, kill: () => true };
    const monitor = startDshAcquisitionMonitor(child, async () => {
      markStarted();
      await release;
    }, 1);
    await started;

    let stopped = false;
    const stopping = monitor.stop().then(error => {
      stopped = true;
      return error;
    });
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(stopped, false);

    releaseCheck();
    assert.equal(await stopping, undefined);
    assert.equal(stopped, true);
  });

  it('removes a temporary GitHub checkout tree', async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), 'agentguard-dsh-cleanup-test-'));
    await writeFile(join(tempRoot, 'pack-file.pack'), 'pack');

    await removeDshTempRoot(tempRoot);

    await assert.rejects(() => access(tempRoot), { code: 'ENOENT' });
  });

  it('returns a completed operation when temporary cleanup remains busy', async () => {
    const result = await runWithDshCleanup(
      async () => ({ report: 'complete' }),
      async () => { throw busyError(); },
    );

    assert.deepEqual(result.value, { report: 'complete' });
    assert.match(result.cleanupWarning ?? '', /EBUSY/);
  });

  it('preserves the operation failure when temporary cleanup also fails', async () => {
    await assert.rejects(
      () => runWithDshCleanup(
        async () => { throw new Error('scan failed'); },
        async () => { throw busyError(); },
      ),
      error => {
        assert.match((error as Error).message, /^scan failed/);
        assert.match((error as Error).message, /cleanup failed \(EBUSY\)/);
        return true;
      },
    );
  });

  it('renders a non-fatal temporary cleanup warning in scan reports', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentguard-dsh-cleanup-report-test-'));
    try {
      await writeFile(join(root, 'package.json'), JSON.stringify({ name: 'cleanup-report-test' }));
      const report = await scanDshPlugin(root);
      report.diagnostics.cleanupWarning = 'Temporary GitHub checkout cleanup failed (EBUSY)';

      assert.match(renderDshMarkdown(report), /Cleanup warning:.*EBUSY/);
      assert.match(renderDshHtml(report), /Cleanup warning.*EBUSY/);
      assert.equal(report.riskLevel, 'low');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
