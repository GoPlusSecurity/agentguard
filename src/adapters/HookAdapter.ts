import { SecurityEngine } from '../core/SecurityEngine.js';
import { ActionNormalizer } from '../core/ActionNormalizer.js';

interface HookContext {
  prompt: string;
  agent: { name: string };
  rawPayload?: Record<string, unknown>;
}

/**
 * HookAdapter — Cross-harness security hook factory (Track 1: Quick-Check).
 *
 * Creates a security interceptor for any registered harness. The ActionNormalizer
 * whitelist ensures only known protocols produce auditable envelopes; unknown
 * harnesses are logged and passed through.
 *
 * This is the primary entry point for multi-agent orchestration scenarios
 * (parallel execution, internal memory exchanges) where sub-millisecond
 * latency matters. For platform-specific hooks with full trust-registry
 * evaluation (Track 2), use ClaudeCodeAdapter / OpenClawAdapter + evaluateHook().
 */
export const createGoPlusHook = (harnessId: string) => {
  return async (ctx: HookContext): Promise<HookContext> => {
    const dataToNormalize = ctx.rawPayload ?? ctx;

    // Attempt normalization via whitelist
    const envelope = ActionNormalizer.normalize(dataToNormalize, harnessId);

    // If harness is not whitelisted, we cannot guarantee audit quality.
    if (!envelope) {
      console.warn(`[HookAdapter] Skipping security audit: Harness [${harnessId}] is not in the whitelist.`);
      return ctx;
    }

    // Perform audit on validated envelope
    const result = await SecurityEngine.auditAction(envelope);

    if (!result.isSafe) {
      console.warn(`[HookAdapter] Action blocked for harness [${harnessId}]: ${result.reason}`);
      ctx.prompt = result.modifiedPrompt;
    }

    return ctx;
  };
};
