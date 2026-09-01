import { randomUUID } from 'node:crypto';
import { getAgentGuardPaths } from '../config.js';
import {
  buildDshThreatFeedFollowup,
  listDshThreatFeedNotifications,
  removeDshThreatFeedNotifications,
  watchDshThreatFeedNotifications,
  type QueuedDshThreatFeedNotification,
} from '../feed/dsh-notifications.js';
import {
  loadDshThreatFeedSubscription,
  type DshThreatFeedSubscription,
} from '../feed/dsh-subscription.js';

export interface DshNotificationFollowupMessage {
  readonly id: string;
  readonly role: 'user';
  readonly content: ReadonlyArray<{ readonly type: 'text'; readonly text: string }>;
  readonly source: { readonly kind: 'plugin'; readonly plugin: 'agentguard' };
}

export interface DshNotificationAgent {
  readonly id: unknown;
  readonly status?: unknown;
  runMaintenance<T>(task: (signal: AbortSignal) => Promise<T>): Promise<T>;
  followup(message: DshNotificationFollowupMessage): void;
}

type DshNotificationLifecycleEvent = 'agent/created' | 'agent/status';
type DshNotificationLifecyclePayload = { agent: DshNotificationAgent; status?: unknown };

export interface DshNotificationDeliveryContext {
  agents: {
    get(id: string): DshNotificationAgent | undefined;
    list(): DshNotificationAgent[];
  };
  on(
    event: DshNotificationLifecycleEvent,
    listener: (payload: DshNotificationLifecyclePayload) => void,
  ): unknown;
  logger?: {
    warn(message: string): void;
  };
}

export interface DshNotificationDeliveryDependencies {
  agentGuardHome?: () => string;
  loadSubscription?: (home: string) => Promise<DshThreatFeedSubscription | null>;
  listNotifications?: (
    options: {
      subscriptionId: string;
      agentId: string;
      limit?: number;
      onWarning?: (message: string) => void;
    },
    home: string,
  ) => Promise<QueuedDshThreatFeedNotification[]>;
  removeNotifications?: (noticeIds: string[], home: string) => Promise<void>;
  watchNotifications?: (
    home: string,
    onChange: () => void,
    onWarning?: (message: string) => void,
  ) => () => void;
  createMessageId?: () => string;
}

const MAX_DELIVERY_NOTICES = 20;

export function installDshThreatFeedNotificationDelivery(
  context: DshNotificationDeliveryContext,
  dependencies: DshNotificationDeliveryDependencies = {},
): () => Promise<void> {
  const home = (dependencies.agentGuardHome ?? (() => getAgentGuardPaths().home))();
  const loadSubscription = dependencies.loadSubscription ?? loadDshThreatFeedSubscription;
  const listNotifications = dependencies.listNotifications ?? listDshThreatFeedNotifications;
  const removeNotifications = dependencies.removeNotifications ?? removeDshThreatFeedNotifications;
  const watchNotifications = dependencies.watchNotifications ?? watchDshThreatFeedNotifications;
  const createMessageId = dependencies.createMessageId ?? randomUUID;
  const inFlight = new Map<string, Promise<void>>();
  const retryRequested = new Set<string>();
  const disposers: Array<() => unknown> = [];
  let stopped = false;

  const warn = (message: string): void => {
    context.logger?.warn(message.slice(0, 700));
  };

  const deliver = async (agent: DshNotificationAgent, agentId: string): Promise<void> => {
    try {
      const subscription = await loadSubscription(home);
      if (!isExactTarget(context, agent, agentId, subscription)) return;

      await agent.runMaintenance(async signal => {
        signal.throwIfAborted();
        const currentSubscription = await loadSubscription(home);
        if (!isExactTarget(context, agent, agentId, currentSubscription)
          || currentSubscription.subscriptionId !== subscription.subscriptionId) {
          return;
        }
        const queued = await listNotifications({
          subscriptionId: currentSubscription.subscriptionId,
          agentId,
          limit: MAX_DELIVERY_NOTICES,
          onWarning: warn,
        }, home);
        if (queued.length === 0) return;
        const followup = buildDshThreatFeedFollowup(queued.map(entry => entry.notification));
        if (followup.noticeIds.length === 0) return;
        const message = createFollowupMessage(followup.text, createMessageId());
        agent.followup(message);
        await removeNotifications(followup.noticeIds, home);
      });
    } catch (error) {
      warn(
        `AgentGuard DSH threat-feed delivery failed for agent ${safeAgentId(agentId)}; `
        + `queued notices were retained (${errorName(error)}).`,
      );
    }
  };

  const requestDelivery = (agent: DshNotificationAgent): void => {
    if (stopped) return;
    const agentId = normalizedAgentId(agent.id);
    if (agentId === null || context.agents.get(agentId) !== agent) return;
    if (inFlight.has(agentId)) {
      retryRequested.add(agentId);
      return;
    }
    const running = deliver(agent, agentId).finally(() => {
      if (inFlight.get(agentId) === running) inFlight.delete(agentId);
      if (!stopped && retryRequested.delete(agentId) && context.agents.get(agentId) === agent) {
        requestDelivery(agent);
      }
    });
    inFlight.set(agentId, running);
  };

  const requestSavedTarget = async (): Promise<void> => {
    if (stopped) return;
    try {
      const subscription = await loadSubscription(home);
      if (stopped || subscription === null) return;
      const agent = context.agents.get(subscription.agentId);
      if (agent !== undefined) requestDelivery(agent);
    } catch (error) {
      warn(`AgentGuard DSH threat-feed queue check failed (${errorName(error)}).`);
    }
  };

  const register = (
    event: DshNotificationLifecycleEvent,
    listener: (payload: DshNotificationLifecyclePayload) => void,
  ): void => {
    const result = context.on(event, listener);
    if (typeof result === 'function') disposers.push(result as () => unknown);
  };

  register('agent/created', ({ agent }) => { requestDelivery(agent); });
  register('agent/status', ({ agent, status }) => {
    if (status === 'idle') requestDelivery(agent);
  });
  try {
    disposers.push(watchNotifications(
      home,
      () => { void requestSavedTarget(); },
      warn,
    ));
  } catch (error) {
    warn(`AgentGuard DSH threat-feed notification watcher could not start (${errorName(error)}).`);
  }
  for (const agent of context.agents.list()) requestDelivery(agent);

  return async () => {
    if (stopped) return;
    stopped = true;
    retryRequested.clear();
    const cleanup = disposers.splice(0).map(dispose => Promise.resolve().then(dispose));
    await Promise.allSettled(cleanup);
    await Promise.allSettled([...inFlight.values()]);
  };
}

function isExactTarget(
  context: DshNotificationDeliveryContext,
  agent: DshNotificationAgent,
  agentId: string,
  subscription: DshThreatFeedSubscription | null,
): subscription is DshThreatFeedSubscription {
  return subscription !== null
    && subscription.agentId === agentId
    && context.agents.get(agentId) === agent;
}

function createFollowupMessage(text: string, id: string): DshNotificationFollowupMessage {
  return Object.freeze({
    id,
    role: 'user' as const,
    content: Object.freeze([Object.freeze({ type: 'text' as const, text })]),
    source: Object.freeze({ kind: 'plugin' as const, plugin: 'agentguard' as const }),
  });
}

function normalizedAgentId(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value : null;
}

function safeAgentId(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]+/g, ' ').slice(0, 200);
}

function errorName(error: unknown): string {
  if (!(error instanceof Error)) return 'unknown error';
  return error.name.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 80) || 'Error';
}
