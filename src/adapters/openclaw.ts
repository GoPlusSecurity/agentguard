import type { ActionEnvelope } from '../types/action.js';
import type { HookAdapter, HookInput } from './types.js';

/**
 * Tool name → action type mapping for OpenClaw
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  exec: 'exec_command',
  write: 'write_file',
  read: 'read_file',
  web_fetch: 'network_request',
  browser: 'network_request',
};

/**
 * OpenClaw hook adapter
 *
 * Bridges OpenClaw's before_tool_call / after_tool_call plugin hooks
 * to the common AgentGuard decision engine.
 *
 * OpenClaw plugin hooks receive an event object:
 *   { toolName: string, params: Record<string, any>, toolCallId?: string }
 *
 * Blocking is done by returning { block: true, blockReason: "..." }
 * from the before_tool_call handler.
 */
export class OpenClawAdapter implements HookAdapter {
  readonly name = 'openclaw';

  parseInput(raw: unknown): HookInput {
    const event = raw as Record<string, unknown>;
    return {
      toolName: (event.toolName as string) || '',
      toolInput: (event.params as Record<string, unknown>) || {},
      eventType: 'pre', // before_tool_call = pre
      raw: event,
    };
  }

  mapToolToActionType(toolName: string): string | null {
    // Direct match
    if (TOOL_ACTION_MAP[toolName]) {
      return TOOL_ACTION_MAP[toolName];
    }
    // Prefix match for tool families (e.g. "exec_python" → "exec_command")
    for (const [prefix, actionType] of Object.entries(TOOL_ACTION_MAP)) {
      if (toolName.startsWith(prefix)) {
        return actionType;
      }
    }
    return null;
  }

  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null {
    const actionType = this.mapToolToActionType(input.toolName);
    if (!actionType) return null;

    const actor = {
      skill: {
        id: initiatingSkill || 'openclaw-session',
        source: initiatingSkill || 'openclaw',
        version_ref: '0.0.0',
        artifact_hash: '',
      },
    };

    const context = {
      session_id: `openclaw-${Date.now()}`,
      user_present: true,
      env: 'prod' as const,
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    let actionData: Record<string, unknown>;

    switch (actionType) {
      case 'exec_command':
        actionData = {
          command: (input.toolInput.command as string) || '',
          args: [],
        };
        break;

      case 'write_file':
        actionData = {
          path: (input.toolInput.path as string) ||
                (input.toolInput.file_path as string) || '',
        };
        break;

      case 'read_file':
        actionData = {
          path: (input.toolInput.path as string) ||
                (input.toolInput.file_path as string) || '',
        };
        break;

      case 'network_request':
        actionData = {
          method: (input.toolInput.method as string) || 'GET',
          url: (input.toolInput.url as string) || '',
          body_preview: input.toolInput.body as string | undefined,
        };
        break;

      default:
        return null;
    }

    return {
      actor,
      action: { type: actionType, data: actionData },
      context,
    } as unknown as ActionEnvelope;
  }

  async inferInitiatingSkill(input: HookInput): Promise<string | null> {
    // Try to get plugin ID from tool → plugin mapping
    try {
      const { getPluginIdFromTool } = await import('./openclaw-plugin.js');
      return getPluginIdFromTool(input.toolName);
    } catch {
      // Mapping not available (plugin not loaded)
      return null;
    }
  }
}
