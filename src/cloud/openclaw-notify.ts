import { randomUUID } from 'node:crypto';
import { openClawGatewayRequest, type OpenClawGatewayOptions } from '../feed/cron.js';

export interface OpenClawRegistrationNotificationResult {
  notified: boolean;
  reason?: string;
}

export interface OpenClawSessionRow {
  key?: string;
  lastChannel?: string;
  lastTo?: string;
  lastAccountId?: string;
  lastThreadId?: string | number;
}

export async function findLatestDeliverableOpenClawSession(
  gateway: OpenClawGatewayOptions = {}
): Promise<OpenClawSessionRow | undefined> {
  const listed = await openClawGatewayRequest(
    'sessions.list',
    { limit: 20, configuredAgentsOnly: false },
    gateway
  );
  return extractOpenClawSessionRows(listed).find(
    (row) => typeof row.lastChannel === 'string' && row.lastChannel.trim() &&
      typeof row.lastTo === 'string' && row.lastTo.trim()
  );
}

export async function notifyOpenClawMessage(
  message: string,
  gateway: OpenClawGatewayOptions = {},
  options: { idempotencyKeyPrefix?: string } = {}
): Promise<OpenClawRegistrationNotificationResult> {
  try {
    const session = await findLatestDeliverableOpenClawSession(gateway);
    if (!session?.lastChannel || !session.lastTo) {
      return { notified: false, reason: 'No OpenClaw session with a deliverable last channel was found.' };
    }

    await openClawGatewayRequest(
      'send',
      {
        channel: session.lastChannel,
        to: session.lastTo,
        ...(session.lastAccountId ? { accountId: session.lastAccountId } : {}),
        ...(session.lastThreadId ? { threadId: String(session.lastThreadId) } : {}),
        ...(session.key ? { sessionKey: session.key } : {}),
        message,
        idempotencyKey: `${options.idempotencyKeyPrefix ?? 'agentguard-send'}-${randomUUID()}`,
      },
      gateway
    );
    return { notified: true };
  } catch (err) {
    return {
      notified: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function notifyOpenClawRegistrationLink(
  registerUrl: string,
  gateway: OpenClawGatewayOptions = {}
): Promise<OpenClawRegistrationNotificationResult> {
  return notifyOpenClawMessage(
    [
      'AgentGuard Cloud activation is ready.',
      '',
      'Open this link to bind this agent to your account:',
      registerUrl,
    ].join('\n'),
    gateway,
    { idempotencyKeyPrefix: 'agentguard-register' }
  );
}

function extractOpenClawSessionRows(value: unknown): OpenClawSessionRow[] {
  if (Array.isArray(value)) return value.flatMap(extractOpenClawSessionRows);
  if (!value || typeof value !== 'object') return [];
  const obj = value as {
    sessions?: unknown;
    rows?: unknown;
    result?: unknown;
    data?: unknown;
    key?: unknown;
    lastChannel?: unknown;
    lastTo?: unknown;
    lastAccountId?: unknown;
    lastThreadId?: unknown;
  };
  if (typeof obj.lastChannel === 'string' || typeof obj.lastTo === 'string') {
    return [{
      key: typeof obj.key === 'string' ? obj.key : undefined,
      lastChannel: typeof obj.lastChannel === 'string' ? obj.lastChannel : undefined,
      lastTo: typeof obj.lastTo === 'string' ? obj.lastTo : undefined,
      lastAccountId: typeof obj.lastAccountId === 'string' ? obj.lastAccountId : undefined,
      lastThreadId: typeof obj.lastThreadId === 'string' || typeof obj.lastThreadId === 'number'
        ? obj.lastThreadId
        : undefined,
    }];
  }
  return [
    ...extractOpenClawSessionRows(obj.sessions),
    ...extractOpenClawSessionRows(obj.rows),
    ...extractOpenClawSessionRows(obj.result),
    ...extractOpenClawSessionRows(obj.data),
  ];
}
