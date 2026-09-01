import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { getAgentGuardPaths } from '../config.js';

const DSH_SUBSCRIPTION_FILENAME = 'dsh-threat-feed-subscription.json';

export interface DshThreatFeedSubscription {
  version: 1;
  subscriptionId: string;
  agentId: string;
  cronName: string;
  cronExpression: string;
  selfCheck: boolean;
  createdAt: string;
  updatedAt: string;
}

export function dshThreatFeedSubscriptionPath(home = getAgentGuardPaths().home): string {
  return join(home, DSH_SUBSCRIPTION_FILENAME);
}

export async function loadDshThreatFeedSubscription(
  home = getAgentGuardPaths().home,
): Promise<DshThreatFeedSubscription | null> {
  const path = dshThreatFeedSubscriptionPath(home);
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if (isFileSystemError(error, 'ENOENT')) return null;
    throw error;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `Could not parse DSH threat-feed subscription state at ${path}: ${errorMessage(error)}`,
    );
  }
  return validateDshThreatFeedSubscription(parsed, path);
}

export async function saveDshThreatFeedSubscription(
  subscription: DshThreatFeedSubscription,
  home = getAgentGuardPaths().home,
): Promise<void> {
  const path = dshThreatFeedSubscriptionPath(home);
  const validated = validateDshThreatFeedSubscription(subscription, path);
  await mkdir(home, { recursive: true, mode: 0o700 });
  await chmod(home, 0o700).catch(() => undefined);
  const temporaryPath = join(home, `.${DSH_SUBSCRIPTION_FILENAME}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporaryPath, `${JSON.stringify(validated, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    await rename(temporaryPath, path);
    await chmod(path, 0o600).catch(() => undefined);
  } finally {
    await rm(temporaryPath, { force: true }).catch(() => undefined);
  }
}

export async function removeDshThreatFeedSubscription(
  home = getAgentGuardPaths().home,
): Promise<void> {
  await rm(dshThreatFeedSubscriptionPath(home), { force: true });
}

function validateDshThreatFeedSubscription(
  value: unknown,
  path: string,
): DshThreatFeedSubscription {
  if (!isRecord(value)
    || value.version !== 1
    || !isNonEmptyString(value.subscriptionId)
    || !isNonEmptyString(value.agentId)
    || !isNonEmptyString(value.cronName)
    || !isNonEmptyString(value.cronExpression)
    || typeof value.selfCheck !== 'boolean'
    || !isIsoTimestamp(value.createdAt)
    || !isIsoTimestamp(value.updatedAt)) {
    throw new Error(`Invalid DSH threat-feed subscription state at ${path}.`);
  }
  return {
    version: 1,
    subscriptionId: value.subscriptionId,
    agentId: value.agentId,
    cronName: value.cronName,
    cronExpression: value.cronExpression,
    selfCheck: value.selfCheck,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isIsoTimestamp(value: unknown): value is string {
  return typeof value === 'string'
    && !Number.isNaN(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function isFileSystemError(error: unknown, code: string): error is NodeJS.ErrnoException {
  return error instanceof Error && (error as NodeJS.ErrnoException).code === code;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
