import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  dshThreatFeedSubscriptionPath,
  loadDshThreatFeedSubscription,
  removeDshThreatFeedSubscription,
  saveDshThreatFeedSubscription,
  type DshThreatFeedSubscription,
} from '../feed/dsh-subscription.js';

const roots: string[] = [];

const subscription: DshThreatFeedSubscription = {
  version: 1,
  subscriptionId: 'sub-test-1',
  agentId: 'dsh-agent-1',
  cronName: 'agentguard-threat-feed',
  cronExpression: '0 * * * *',
  selfCheck: false,
  createdAt: '2026-08-25T00:00:00.000Z',
  updatedAt: '2026-08-25T00:00:00.000Z',
};

afterEach(async () => {
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

async function temporaryHome(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agentguard-dsh-subscription-'));
  roots.push(root);
  return root;
}

describe('DSH threat-feed subscription state', () => {
  it('returns null when no subscription exists', async () => {
    const home = await temporaryHome();

    assert.equal(await loadDshThreatFeedSubscription(home), null);
  });

  it('atomically persists and reloads a private versioned subscription', async () => {
    const home = await temporaryHome();

    await saveDshThreatFeedSubscription(subscription, home);

    assert.deepEqual(await loadDshThreatFeedSubscription(home), subscription);
    assert.equal((await stat(dshThreatFeedSubscriptionPath(home))).mode & 0o777, 0o600);
  });

  it('rejects malformed or unsupported subscription state', async () => {
    const home = await temporaryHome();
    await mkdir(home, { recursive: true });
    const statePath = dshThreatFeedSubscriptionPath(home);

    await writeFile(statePath, '{"version":2}\n', 'utf8');
    await assert.rejects(
      () => loadDshThreatFeedSubscription(home),
      /Invalid DSH threat-feed subscription state/,
    );

    await writeFile(statePath, '{not-json}\n', 'utf8');
    await assert.rejects(
      () => loadDshThreatFeedSubscription(home),
      /Could not parse DSH threat-feed subscription state/,
    );
  });

  it('removes an existing subscription idempotently', async () => {
    const home = await temporaryHome();
    await saveDshThreatFeedSubscription(subscription, home);

    await removeDshThreatFeedSubscription(home);
    await removeDshThreatFeedSubscription(home);

    assert.equal(await loadDshThreatFeedSubscription(home), null);
  });
});
