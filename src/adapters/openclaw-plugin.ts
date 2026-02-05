/**
 * GoPlus AgentGuard — OpenClaw Plugin
 *
 * Registers before_tool_call and after_tool_call hooks with the
 * OpenClaw plugin API to evaluate tool safety at runtime.
 *
 * Usage in OpenClaw plugin config:
 *   import agentguard from '@goplus/agentguard/openclaw';
 *   export default agentguard;
 *
 * Or register manually:
 *   import { registerOpenClawPlugin } from '@goplus/agentguard';
 *   registerOpenClawPlugin(api);
 */

import { OpenClawAdapter } from './openclaw.js';
import { evaluateHook } from './engine.js';
import { loadConfig, writeAuditLog } from './common.js';
import type { AgentGuardInstance } from './types.js';

/**
 * OpenClaw plugin API interface (subset we use)
 */
interface OpenClawPluginApi {
  on(event: string, handler: (event: unknown) => Promise<unknown>): void;
  on(event: string, options: Record<string, unknown>, handler: (event: unknown) => Promise<unknown>): void;
}

/**
 * Register AgentGuard hooks with OpenClaw plugin API
 */
export function registerOpenClawPlugin(
  api: OpenClawPluginApi,
  agentguardFactory?: () => AgentGuardInstance
): void {
  const adapter = new OpenClawAdapter();
  const config = loadConfig();

  // Lazy-initialize agentguard instance
  let agentguard: AgentGuardInstance | null = null;
  function getAgentGuard(): AgentGuardInstance {
    if (!agentguard) {
      if (agentguardFactory) {
        agentguard = agentguardFactory();
      } else {
        // Dynamic import from parent package
        try {
          // eslint-disable-next-line @typescript-eslint/no-require-imports
          const { createAgentGuard } = require('@goplus/agentguard');
          agentguard = createAgentGuard();
        } catch {
          throw new Error('AgentGuard: unable to load engine. Install @goplus/agentguard.');
        }
      }
    }
    return agentguard!;
  }

  // before_tool_call → evaluate and optionally block
  api.on('before_tool_call', async (event: unknown) => {
    try {
      const result = await evaluateHook(adapter, event, {
        config,
        agentguard: getAgentGuard(),
      });

      if (result.decision === 'deny') {
        return {
          block: true,
          blockReason: result.reason || 'Blocked by GoPlus AgentGuard',
        };
      }

      // OpenClaw has no 'ask' mode — block with explanation in strict/balanced
      if (result.decision === 'ask') {
        return {
          block: true,
          blockReason: result.reason || 'Requires confirmation (GoPlus AgentGuard)',
        };
      }

      return undefined; // allow
    } catch {
      // Fail open
      return undefined;
    }
  });

  // after_tool_call → audit log
  api.on('after_tool_call', async (event: unknown) => {
    try {
      const input = adapter.parseInput(event);
      writeAuditLog(input, null, null);
    } catch {
      // Non-critical
    }
  });
}

/**
 * Default export for OpenClaw plugin registration
 *
 * Usage: export default from '@goplus/agentguard/openclaw'
 */
export default function register(api: OpenClawPluginApi): void {
  registerOpenClawPlugin(api);
}
