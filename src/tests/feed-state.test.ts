import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getSeenAdvisoryIds, loadFeedState, prependFeedStateEntry, saveFeedState } from '../feed/state.js';

const originalAgentGuardHome = process.env.AGENTGUARD_HOME;

function isolateHome(): void {
  process.env.AGENTGUARD_HOME = mkdtempSync(join(tmpdir(), 'ag-feed-state-'));
}

describe('feed/state', () => {
  afterEach(() => {
    if (originalAgentGuardHome === undefined) {
      delete process.env.AGENTGUARD_HOME;
    } else {
      process.env.AGENTGUARD_HOME = originalAgentGuardHome;
    }
  });

  it('persists newest-first pull records', () => {
    isolateHome();
    saveFeedState([
      {
        pulledAt: '2026-05-13T00:00:00Z',
        newSeenIds: ['AGS-2026-2'],
        foundIds: ['AGS-2026-2'],
      },
      {
        pulledAt: '2026-05-12T00:00:00Z',
        newSeenIds: ['AGS-2026-1'],
        foundIds: [],
      },
    ]);

    const state = loadFeedState();
    assert.deepEqual(state, [
      {
        pulledAt: '2026-05-13T00:00:00Z',
        newSeenIds: ['AGS-2026-2'],
        foundIds: ['AGS-2026-2'],
      },
      {
        pulledAt: '2026-05-12T00:00:00Z',
        newSeenIds: ['AGS-2026-1'],
        foundIds: [],
      },
    ]);
    assert.deepEqual(getSeenAdvisoryIds(state), ['AGS-2026-2', 'AGS-2026-1']);
  });

  it('prepends normalized records without duplicating ids inside a record', () => {
    const state = prependFeedStateEntry([], {
      pulledAt: '2026-05-13T00:00:00Z',
      newSeenIds: ['AGS-2026-1', 'AGS-2026-1'],
      foundIds: ['AGS-2026-1', 'AGS-2026-1'],
    });

    assert.deepEqual(state, [{
      pulledAt: '2026-05-13T00:00:00Z',
      newSeenIds: ['AGS-2026-1'],
      foundIds: ['AGS-2026-1'],
    }]);
  });

  it('migrates the old object state format', () => {
    isolateHome();
    writeFileSync(join(process.env.AGENTGUARD_HOME!, 'feed-state.json'), JSON.stringify({
      lastPulledAt: '2026-05-13T00:00:00Z',
      seenAdvisoryIds: ['AGS-2026-1'],
    }));

    assert.deepEqual(loadFeedState(), [{
      pulledAt: '2026-05-13T00:00:00Z',
      newSeenIds: ['AGS-2026-1'],
      foundIds: [],
    }]);
  });
});
