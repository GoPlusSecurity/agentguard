import { packageVersion } from '../version.js';

/** Frozen rule implementation used for the Phase 1 release candidate. */
export const DSH_RULES_BASELINE = '83db977a566d8a853568a2d2903b142106d80196';

/** Integration milestone exposed in reports so results remain attributable. */
export const DSH_INTEGRATION_PHASE = 'phase1-rc1' as const;

export function getDshScannerMetadata() {
  return {
    name: 'AgentGuard for DSH',
    version: packageVersion,
    phase: DSH_INTEGRATION_PHASE,
    rulesBaseline: DSH_RULES_BASELINE,
  };
}
