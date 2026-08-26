import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildDshThreatFeedNotification,
  enqueueDshThreatFeedNotification,
  listDshThreatFeedNotifications,
} from '../feed/dsh-notifications.js';
import { saveDshThreatFeedSubscription, type DshThreatFeedSubscription } from '../feed/dsh-subscription.js';
import type { Advisory } from '../feed/types.js';
import {
  installDshThreatFeedNotificationDelivery,
  type DshNotificationAgent,
  type DshNotificationFollowupMessage,
} from '../dsh/notification-delivery.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

function subscription(agentId = 'dsh-agent-1'): DshThreatFeedSubscription {
  return {
    version: 1,
    subscriptionId: 'subscription-delivery-test',
    agentId,
    cronName: 'agentguard-threat-feed',
    cronExpression: '0 * * * *',
    selfCheck: false,
    createdAt: '2026-08-26T00:00:00.000Z',
    updatedAt: '2026-08-26T00:00:00.000Z',
  };
}

function advisory(id = 'AGS-delivery-1'): Advisory {
  return {
    id,
    ecosystem: 'plugin',
    severity: 'high',
    summary: `Threat ${id}`,
    detailsMd: 'details are not delivered',
    affected: [],
    publishedAt: '2026-08-26T00:30:00.000Z',
  };
}

class FakeAgent implements DshNotificationAgent {
  status: 'idle' | 'running' = 'idle';
  maintenanceCalls = 0;
  busyFailures = 0;
  followupFailure = false;
  maintenanceGate: Promise<void> | undefined;
  followups: DshNotificationFollowupMessage[] = [];

  constructor(readonly id: string) {}

  async runMaintenance<T>(task: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.maintenanceCalls += 1;
    if (this.busyFailures > 0) {
      this.busyFailures -= 1;
      throw new Error(`agent "${this.id}" already has active work`);
    }
    if (this.maintenanceGate) await this.maintenanceGate;
    return task(new AbortController().signal);
  }

  followup(message: DshNotificationFollowupMessage): void {
    if (this.followupFailure) throw new Error('followup rejected');
    this.followups.push(message);
  }
}

type LifecycleEvent = 'agent/created' | 'agent/status';
type LifecycleListener = (payload: { agent: DshNotificationAgent; status?: unknown }) => void;

class FakeDeliveryContext {
  readonly warnings: string[] = [];
  readonly logger = { warn: (message: string) => { this.warnings.push(message); } };
  private readonly live = new Map<string, DshNotificationAgent>();
  private readonly listeners = new Map<LifecycleEvent, Set<LifecycleListener>>();
  readonly agents = {
    get: (id: string) => this.live.get(id),
    list: () => [...this.live.values()],
  };

  constructor(agents: DshNotificationAgent[] = []) {
    for (const agent of agents) this.live.set(String(agent.id), agent);
  }

  on(event: LifecycleEvent, listener: LifecycleListener): () => void {
    const listeners = this.listeners.get(event) ?? new Set<LifecycleListener>();
    listeners.add(listener);
    this.listeners.set(event, listeners);
    return () => { listeners.delete(listener); };
  }

  addAgent(agent: DshNotificationAgent): void {
    this.live.set(String(agent.id), agent);
  }

  emit(event: LifecycleEvent, payload: { agent: DshNotificationAgent; status?: unknown }): void {
    for (const listener of this.listeners.get(event) ?? []) listener(payload);
  }
}

async function queuedHome(agentId = 'dsh-agent-1', advisoryId = 'AGS-delivery-1'): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'agentguard-dsh-delivery-'));
  roots.push(home);
  const savedSubscription = subscription(agentId);
  await saveDshThreatFeedSubscription(savedSubscription, home);
  const notice = buildDshThreatFeedNotification({
    subscription: savedSubscription,
    freshAdvisories: [advisory(advisoryId)],
    results: [],
    selfCheck: false,
    now: '2026-08-26T01:00:00.000Z',
  });
  assert.ok(notice);
  await enqueueDshThreatFeedNotification(notice, home);
  return home;
}

async function eventually(check: () => boolean, message: string): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail(message);
}

describe('DSH threat-feed notification delivery', () => {
  it('delivers a notice published after the subscribed agent is already live', async () => {
    const home = await mkdtemp(join(tmpdir(), 'agentguard-dsh-delivery-live-'));
    roots.push(home);
    const savedSubscription = subscription();
    await saveDshThreatFeedSubscription(savedSubscription, home);
    const target = new FakeAgent('dsh-agent-1');
    const context = new FakeDeliveryContext([target]);
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    const notice = buildDshThreatFeedNotification({
      subscription: savedSubscription,
      freshAdvisories: [advisory('AGS-delivery-live')],
      results: [],
      selfCheck: false,
      now: '2026-08-26T01:00:00.000Z',
    });
    assert.ok(notice);

    await enqueueDshThreatFeedNotification(notice, home);
    await eventually(() => target.followups.length === 1, 'live target did not receive the new queue notice');
    assert.match(target.followups[0].content[0].text, /AGS-delivery-live/);

    await dispose();
  });

  it('delivers queued notices only to the exact already-live subscribed agent', async () => {
    const home = await queuedHome();
    const target = new FakeAgent('dsh-agent-1');
    const other = new FakeAgent('dsh-agent-2');
    const context = new FakeDeliveryContext([target, other]);

    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    await eventually(() => target.followups.length === 1, 'target agent did not receive its queued notice');

    assert.equal(other.followups.length, 0);
    assert.equal(target.followups[0].role, 'user');
    assert.deepEqual(target.followups[0].source, { kind: 'plugin', plugin: 'agentguard' });
    assert.match(target.followups[0].content[0].text, /untrusted threat intelligence data/i);
    assert.match(target.followups[0].content[0].text, /AGS-delivery-1/);
    assert.deepEqual(await listDshThreatFeedNotifications({
      subscriptionId: 'subscription-delivery-test', agentId: 'dsh-agent-1',
    }, home), []);
    await dispose();
  });

  it('does not deliver when the saved target agent is not live', async () => {
    const home = await queuedHome();
    const other = new FakeAgent('dsh-agent-2');
    const context = new FakeDeliveryContext([other]);
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });

    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(other.followups.length, 0);
    assert.equal(other.maintenanceCalls, 0);

    await dispose();
  });

  it('coalesces concurrent triggers into one follow-up for the queued batch', async () => {
    const home = await queuedHome();
    const target = new FakeAgent('dsh-agent-1');
    let releaseMaintenance!: () => void;
    target.maintenanceGate = new Promise(resolve => { releaseMaintenance = resolve; });
    const context = new FakeDeliveryContext([target]);
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    await eventually(() => target.maintenanceCalls === 1, 'initial delivery did not claim maintenance');

    context.emit('agent/created', { agent: target });
    context.emit('agent/status', { agent: target, status: 'idle' });
    context.emit('agent/status', { agent: target, status: 'idle' });
    releaseMaintenance();
    await eventually(() => target.followups.length === 1, 'coalesced delivery did not complete');
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(target.followups.length, 1);

    await dispose();
  });

  it('delivers after the subscribed agent is created later', async () => {
    const home = await queuedHome();
    const context = new FakeDeliveryContext();
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    const target = new FakeAgent('dsh-agent-1');

    context.addAgent(target);
    context.emit('agent/created', { agent: target });
    await eventually(() => target.followups.length === 1, 'created target did not receive its queued notice');

    await dispose();
  });

  it('retains a busy delivery and retries when the exact agent becomes idle', async () => {
    const home = await queuedHome();
    const target = new FakeAgent('dsh-agent-1');
    target.busyFailures = 1;
    target.status = 'running';
    const context = new FakeDeliveryContext([target]);
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    await eventually(() => target.maintenanceCalls === 1, 'initial busy maintenance was not attempted');
    assert.equal(target.followups.length, 0);

    target.status = 'idle';
    context.emit('agent/status', { agent: target, status: 'idle' });
    await eventually(() => target.followups.length === 1, 'idle retry did not deliver the queued notice');
    assert.equal(target.maintenanceCalls, 2);

    await dispose();
  });

  it('retains queue files when followup admission fails', async () => {
    const home = await queuedHome();
    const target = new FakeAgent('dsh-agent-1');
    target.followupFailure = true;
    const context = new FakeDeliveryContext([target]);
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    await eventually(() => context.warnings.length > 0, 'followup failure was not reported');

    const queued = await listDshThreatFeedNotifications({
      subscriptionId: 'subscription-delivery-test', agentId: 'dsh-agent-1',
    }, home);
    assert.equal(queued.length, 1);
    assert.match(context.warnings[0], /delivery failed/i);
    assert.doesNotMatch(context.warnings[0], /Threat AGS-delivery-1/);

    await dispose();
  });

  it('stops observing lifecycle events after disposal', async () => {
    const home = await queuedHome();
    const context = new FakeDeliveryContext();
    const dispose = installDshThreatFeedNotificationDelivery(context, {
      agentGuardHome: () => home,
    });
    await dispose();
    const target = new FakeAgent('dsh-agent-1');

    context.addAgent(target);
    context.emit('agent/created', { agent: target });
    await new Promise(resolve => setTimeout(resolve, 25));

    assert.equal(target.followups.length, 0);
    assert.equal(target.maintenanceCalls, 0);
  });
});
