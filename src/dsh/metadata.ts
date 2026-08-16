import { packageVersion } from '../version.js';

/** Frozen rule implementation used for the Phase 1 release candidate. */
export const DSH_RULES_BASELINE = '367227cc2b8bc064af369bf41e4490f6c4d3ea8b';

/** Integration milestone exposed in reports so results remain attributable. */
export const DSH_INTEGRATION_PHASE = 'phase1-rc2' as const;

export function getDshScannerMetadata() {
  return {
    name: 'AgentGuard for DSH',
    version: packageVersion,
    phase: DSH_INTEGRATION_PHASE,
    rulesBaseline: DSH_RULES_BASELINE,
  };
}
