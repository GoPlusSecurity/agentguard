import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadFeedState, markAdvisorySeen, saveFeedState } from '../feed/state.js';

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

  it('persists pull cursor and seen advisory ids', () => {
    isolateHome();
    saveFeedState({
      lastPulledAt: '2026-05-13T00:00:00Z',
      seenAdvisoryIds: ['AGS-2026-1'],
    });

    const state = loadFeedState();
    assert.equal(state.lastPulledAt, '2026-05-13T00:00:00Z');
    assert.deepEqual(state.seenAdvisoryIds, ['AGS-2026-1']);
  });

  it('marks advisory ids as seen without duplicating them', () => {
    const state = markAdvisorySeen(
      { seenAdvisoryIds: ['AGS-2026-1'] },
      'AGS-2026-1'
    );

    assert.deepEqual(state.seenAdvisoryIds, ['AGS-2026-1']);
  });
});
