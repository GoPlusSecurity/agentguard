import { packageVersion } from '../version.js';

/** Frozen rule implementation used for the Phase 1 release candidate. */
export const DSH_RULES_BASELINE = '2337e266cf78f82e8d07f5555f7cc760b6ddc830';

/** Integration milestone exposed in reports so results remain attributable. */
export const DSH_INTEGRATION_PHASE = 'phase1-rc3' as const;

export function getDshScannerMetadata() {
  return {
    name: 'AgentGuard for DSH',
    version: packageVersion,
    phase: DSH_INTEGRATION_PHASE,
    rulesBaseline: DSH_RULES_BASELINE,
  };
}
