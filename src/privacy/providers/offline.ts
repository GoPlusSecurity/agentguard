import type { AdjudicationRequest, AdjudicationResult, PrivacyAdjudicator } from '../types.js';

/**
 * Default adjudicator: judges nothing and says so.
 *
 * AgentGuard's local guard must work with no account and no network, so the
 * semantic layer is opt-in. When it is off the pipeline still runs on
 * deterministic rules; this provider exists to report `unsupported` coverage
 * so that a scan without semantic judgment is never mistaken for a clean one.
 */
export class OfflineAdjudicator implements PrivacyAdjudicator {
  readonly name = 'offline';
  readonly available = true;

  async adjudicate(_request: AdjudicationRequest): Promise<AdjudicationResult> {
    return {
      candidateVerdicts: [],
      chunkVerdicts: [],
      coverage: 'unsupported',
      provider: this.name,
    };
  }
}
