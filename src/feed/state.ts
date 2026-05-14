/**
 * Local feed-subscription state I/O.
 *
 * Persisted at `~/.agentguard/feed-state.json` so the `subscribe` command
 * doesn't re-process the same advisory across invocations / cron ticks.
 *
 * Kept tiny (single JSON object) on purpose — bigger ledgers go through the
 * audit log path, not here.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { getAgentGuardPaths } from '../config.js';
import type { FeedState } from './types.js';

const SEEN_ID_LIMIT = 1000;

function statePath(): string {
  return join(getAgentGuardPaths().home, 'feed-state.json');
}

export function loadFeedState(): FeedState {
  const file = statePath();
  if (!existsSync(file)) return {};
  try {
    const raw = readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw) as Partial<FeedState>;
    return {
      lastPulledAt: parsed.lastPulledAt,
      seenAdvisoryIds: parsed.seenAdvisoryIds ?? [],
    };
  } catch {
    // Corrupt state file: pretend it's empty rather than crash. The next
    // successful subscribe will overwrite it.
    return {};
  }
}

export function saveFeedState(state: FeedState): void {
  const file = statePath();
  mkdirSync(dirname(file), { recursive: true });
  const trimmed: FeedState = {
    lastPulledAt: state.lastPulledAt,
    seenAdvisoryIds: (state.seenAdvisoryIds ?? []).slice(-SEEN_ID_LIMIT),
  };
  writeFileSync(file, `${JSON.stringify(trimmed, null, 2)}\n`, { mode: 0o600 });
}

export function markAdvisorySeen(state: FeedState, advisoryId: string): FeedState {
  const set = new Set(state.seenAdvisoryIds ?? []);
  set.add(advisoryId);
  return {
    ...state,
    seenAdvisoryIds: [...set],
  };
}
