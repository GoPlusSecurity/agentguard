/**
 * Local feed-subscription state I/O.
 *
 * Persisted at `~/.agentguard/feed-state.json` as newest-first pull records so
 * subscribe runs are easy to inspect when debugging feed behavior.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { getAgentGuardPaths } from '../config.js';
import type { FeedState, FeedStateEntry } from './types.js';

function statePath(): string {
  return join(getAgentGuardPaths().home, 'feed-state.json');
}

export function loadFeedState(): FeedState {
  const file = statePath();
  if (!existsSync(file)) return [];
  try {
    const raw = readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) {
      const migrated = normalizeLegacyState(parsed);
      return migrated ? [migrated] : [];
    }
    return parsed
      .map(normalizeEntry)
      .filter((entry): entry is FeedStateEntry => Boolean(entry));
  } catch {
    // Corrupt state file: pretend it's empty rather than crash. The next
    // successful subscribe will overwrite it.
    return [];
  }
}

export function saveFeedState(state: FeedState): void {
  const file = statePath();
  mkdirSync(dirname(file), { recursive: true });
  const normalized = state.map(normalizeEntry).filter(Boolean);
  writeFileSync(file, `${JSON.stringify(normalized, null, 2)}\n`, { mode: 0o600 });
}

export function getSeenAdvisoryIds(state: FeedState): string[] {
  return [...new Set(state.flatMap((entry) => entry.newSeenIds))];
}

export function prependFeedStateEntry(
  state: FeedState,
  entry: FeedStateEntry
): FeedState {
  const normalized = normalizeEntry(entry);
  return normalized ? [normalized, ...state] : state;
}

function normalizeEntry(value: unknown): FeedStateEntry | null {
  if (!value || typeof value !== 'object') return null;
  const entry = value as Partial<FeedStateEntry>;
  if (typeof entry.pulledAt !== 'string' || entry.pulledAt.length === 0) return null;
  return {
    pulledAt: entry.pulledAt,
    newSeenIds: uniqueStrings(entry.newSeenIds),
    foundIds: uniqueStrings(entry.foundIds),
  };
}

function normalizeLegacyState(value: unknown): FeedStateEntry | null {
  if (!value || typeof value !== 'object') return null;
  const legacy = value as {
    lastPulledAt?: unknown;
    seenAdvisoryIds?: unknown;
    foundIds?: unknown;
  };
  const newSeenIds = uniqueStrings(legacy.seenAdvisoryIds);
  if (newSeenIds.length === 0) return null;
  const pulledAt = typeof legacy.lastPulledAt === 'string' && legacy.lastPulledAt.length > 0
    ? legacy.lastPulledAt
    : new Date(0).toISOString();
  return {
    pulledAt,
    newSeenIds,
    foundIds: uniqueStrings(legacy.foundIds),
  };
}

function uniqueStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [
    ...new Set(value.filter((item): item is string => typeof item === 'string' && item.length > 0)),
  ];
}
