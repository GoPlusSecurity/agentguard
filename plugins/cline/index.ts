/**
 * GoPlus AgentGuard — native Cline runtime plugin.
 *
 * Implements `@cline/core`'s `AgentPlugin` shape and hooks
 * `beforeTool` / `afterTool` into the AgentGuard decision engine
 * via the shared `ClineAdapter` + `evaluateHook`.
 *
 * Install (recommended):
 *   agentguard init --agent cline
 *   # Then in Cline:
 *   cline plugin install ~/.cline/plugins/agentguard
 *
 * Or directly:
 *   cline plugin install https://github.com/GoPlusSecurity/agentguard/blob/main/plugins/cline/index.ts
 */

// `@cline/core` provides the AgentPlugin type. We declare a structural fallback
// so this file type-checks inside the AgentGuard repo (which does not depend on
// @cline/core) — at runtime inside Cline, the real type is used.
type BeforeToolResult =
  | { skip: true; reason: string }
  | { review: true; reason?: string }
  | undefined;

interface BeforeToolArgs {
  toolCall: { id: string; toolName: string; input: Record<string, unknown> };
  input: Record<string, unknown>;
  taskId?: string;
  workspaceRoots?: string[];
}

interface AfterToolArgs {
  toolCall: { id: string; toolName: string; input: Record<string, unknown> };
  result?: unknown;
  taskId?: string;
}

export interface AgentPlugin {
  name: string;
  manifest?: { capabilities?: string[] };
  hooks?: {
    beforeTool?: (args: BeforeToolArgs) => Promise<BeforeToolResult> | BeforeToolResult;
    afterTool?: (args: AfterToolArgs) => Promise<void> | void;
  };
}

// Lazy-load the engine so the plugin works whether AgentGuard is installed
// alongside Cline (npm i -g @goplus/agentguard) or vendored elsewhere.
let engineCache: {
  evaluateHook: (
    adapter: unknown,
    raw: unknown,
    opts: { config: { level?: string }; agentguard: unknown }
  ) => Promise<{ decision: 'allow' | 'deny' | 'ask'; reason?: string }>;
  ClineAdapter: new () => unknown;
  loadConfig: () => { level?: string };
  createAgentGuard: () => unknown;
} | null = null;

async function loadEngine() {
  if (engineCache) return engineCache;
  let mod: Record<string, unknown> | undefined;
  try {
    mod = (await import('@goplus/agentguard')) as Record<string, unknown>;
  } catch {
    return null;
  }
  const evaluateHook = mod.evaluateHook as typeof engineCache extends null
    ? never
    : NonNullable<typeof engineCache>['evaluateHook'];
  const ClineAdapter = mod.ClineAdapter as typeof engineCache extends null
    ? never
    : NonNullable<typeof engineCache>['ClineAdapter'];
  const loadConfig =
    (mod.loadConfig as (() => { level?: string }) | undefined) ||
    (() => ({ level: process.env.AGENTGUARD_LEVEL || 'balanced' }));
  const createAgentGuard =
    (mod.createAgentGuard as (() => unknown) | undefined) ||
    (mod.default as (() => unknown) | undefined);
  if (!evaluateHook || !ClineAdapter || !createAgentGuard) return null;
  engineCache = { evaluateHook, ClineAdapter, loadConfig, createAgentGuard };
  return engineCache;
}

function envBool(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  return value === '1' || value.toLowerCase() === 'true';
}

const plugin: AgentPlugin = {
  name: '@goplus/agentguard',
  manifest: {
    capabilities: ['hooks'],
  },
  hooks: {
    async beforeTool({ toolCall, input, taskId, workspaceRoots }): Promise<BeforeToolResult> {
      const engine = await loadEngine();
      if (!engine) {
        // Default: fail-closed — match the file-hook surface and the hermes
        // plugin so users get consistent enforcement across integrations.
        // Override with AGENTGUARD_CLINE_FAIL_OPEN=1 for local dev.
        if (envBool('AGENTGUARD_CLINE_FAIL_OPEN', false)) {
          return undefined;
        }
        return {
          skip: true,
          reason:
            'GoPlus AgentGuard: engine not found (install @goplus/agentguard) — blocking fail-closed. Set AGENTGUARD_CLINE_FAIL_OPEN=1 to allow.',
        };
      }

      const adapter = new engine.ClineAdapter();
      const envelope = {
        hookName: 'tool_call',
        taskId,
        workspaceRoots,
        tool_call: { id: toolCall.id, name: toolCall.toolName, input },
      };

      try {
        const decision = await engine.evaluateHook(adapter, envelope, {
          config: engine.loadConfig(),
          agentguard: engine.createAgentGuard(),
        });
        if (decision.decision === 'deny') {
          return { skip: true, reason: decision.reason || 'GoPlus AgentGuard blocked this tool call' };
        }
        if (decision.decision === 'ask') {
          // Cline supports `review` to pause for user confirmation.
          return { review: true, reason: decision.reason } as BeforeToolResult;
        }
        return undefined;
      } catch (err) {
        if (envBool('AGENTGUARD_CLINE_FAIL_OPEN', false)) {
          return undefined;
        }
        return {
          skip: true,
          reason: `GoPlus AgentGuard engine error: ${err instanceof Error ? err.message : 'unknown'} — blocking fail-closed. Set AGENTGUARD_CLINE_FAIL_OPEN=1 to allow.`,
        };
      }
    },

    async afterTool({ toolCall, taskId }) {
      const engine = await loadEngine();
      if (!engine) return;
      const adapter = new engine.ClineAdapter();
      const envelope = {
        hookName: 'tool_result',
        taskId,
        tool_call: { id: toolCall.id, name: toolCall.toolName, input: toolCall.input },
      };
      try {
        await engine.evaluateHook(adapter, envelope, {
          config: engine.loadConfig(),
          agentguard: engine.createAgentGuard(),
        });
      } catch {
        // Post-tool is audit-only; never affect Cline execution.
      }
    },
  },
};

export { plugin };
export default plugin;
