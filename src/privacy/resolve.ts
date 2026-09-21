import type { AgentGuardConfig } from '../config.js';
import { DEFAULT_ADJUDICATE_OPTIONS, type AdjudicateOptions, type PrivacyAdjudicator } from './types.js';
import { JevAdjudicator } from './providers/jev.js';
import { TokenBudget } from './types.js';
import { OfflineAdjudicator } from './providers/offline.js';

/** Default ceiling for one invocation; roughly a large repository's prose. */
export const DEFAULT_TOKEN_BUDGET = 400_000;

export interface ResolvedPrivacyMode {
  adjudicator: PrivacyAdjudicator;
  options: AdjudicateOptions;
  /** Fresh per invocation, shared by every file in that run. */
  budget: TokenBudget;
  /** What the user asked for, which is not always what they got. */
  requestedMode: 'off' | 'jev';
  /** Set when the requested mode could not be honoured. */
  warning?: string;
}

/**
 * Build the adjudicator the configuration asks for.
 *
 * When enhancement is requested but unusable — typically a missing key — this
 * returns the offline adjudicator *and* a warning. It deliberately does not
 * fail the command: a privacy scan should still run on deterministic rules.
 * It equally does not stay silent, because a user who enabled enhancement and
 * is quietly getting local-only coverage would misread a clean result.
 */
export function resolvePrivacyMode(config: AgentGuardConfig): ResolvedPrivacyMode {
  const privacy = config.privacy;
  const requestedMode = privacy?.mode ?? 'off';
  const budget = new TokenBudget(privacy?.tokenBudget ?? DEFAULT_TOKEN_BUDGET);
  const options: AdjudicateOptions = {
    ...DEFAULT_ADJUDICATE_OPTIONS,
    threshold: privacy?.threshold ?? DEFAULT_ADJUDICATE_OPTIONS.threshold,
    budget,
  };

  if (requestedMode !== 'jev') {
    return { adjudicator: new OfflineAdjudicator(), options, budget, requestedMode };
  }

  const apiKey = process.env.TYPESAFE_API_KEY ?? privacy?.apiKey;
  if (!apiKey) {
    return {
      adjudicator: new OfflineAdjudicator(),
      options,
      budget,
      requestedMode,
      warning:
        'Enhanced privacy mode is enabled but no TypeSafe API key was found. ' +
        'Set TYPESAFE_API_KEY or re-run `agentguard privacy enable --api-key <key>`. ' +
        'Falling back to local-only detection; prose coverage will be reported as unsupported.',
    };
  }

  const adjudicator = new JevAdjudicator({ apiKey, model: privacy?.model, endpoint: privacy?.endpoint });
  return { adjudicator, options, budget, requestedMode };
}

/** One-line description for `status` and `doctor`. */
export function describePrivacyMode(config: AgentGuardConfig): string {
  const resolved = resolvePrivacyMode(config);
  if (resolved.requestedMode === 'off') return 'off (local rules only; prose coverage limited)';
  if (resolved.warning) return 'jev (ENABLED BUT INACTIVE — no API key; running local-only)';
  return `jev (spans and sentences are sent to ${config.privacy?.endpoint ?? 'api.typesafe.ai'} for judgment)`;
}
