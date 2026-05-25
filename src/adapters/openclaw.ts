import type { ActionEnvelope, ActionType, ActionContext } from '../types/action.js';
import type { SkillIdentity } from '../types/skill.js';
import type { HookAdapter, HookInput } from './types.js';
import { getString } from './common.js';

/**
 * Tool name -> action type mapping for OpenClaw
 */
const TOOL_ACTION_MAP: Record<string, ActionType> = {
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
    const event = (raw !== null && typeof raw === 'object') ? raw as Record<string, unknown> : {};
    const toolInput = (event.params !== null && typeof event.params === 'object')
      ? event.params as Record<string, unknown>
      : {};
    return {
      toolName: getString(event, 'toolName'),
      toolInput,
      eventType: 'pre', // before_tool_call = pre
      raw: event,
    };
  }

  mapToolToActionType(toolName: string): ActionType | null {
    // Direct match
    if (TOOL_ACTION_MAP[toolName]) {
      return TOOL_ACTION_MAP[toolName];
    }
    // Prefix match for tool families (e.g. "exec_python" -> "exec_command")
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

    const skill: SkillIdentity = {
      id: initiatingSkill || 'openclaw-session',
      source: initiatingSkill || 'openclaw',
      version_ref: '0.0.0',
      artifact_hash: '',
    };

    const context: ActionContext = {
      session_id: `openclaw-${Date.now()}`,
      user_present: true,
      env: 'prod',
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    const ti = input.toolInput as Record<string, unknown>;

    switch (actionType) {
      case 'exec_command':
        return {
          actor: { skill },
          action: {
            type: actionType,
            data: {
              command: getString(ti, 'command'),
              args: [],
            },
          },
          context,
        };

      case 'write_file':
        return {
          actor: { skill },
          action: {
            type: actionType,
            data: {
              path: getString(ti, 'path') || getString(ti, 'file_path'),
            },
          },
          context,
        };

      case 'read_file':
        return {
          actor: { skill },
          action: {
            type: actionType,
            data: {
              path: getString(ti, 'path') || getString(ti, 'file_path'),
            },
          },
          context,
        };

      case 'network_request':
        return {
          actor: { skill },
          action: {
            type: actionType,
            data: {
              method: (getString(ti, 'method') || 'GET') as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
              url: getString(ti, 'url'),
              body_preview: getString(ti, 'body') || undefined,
            },
          },
          context,
        };

      default:
        return null;
    }
  }

  async inferInitiatingSkill(input: HookInput): Promise<string | null> {
    // Try to get plugin ID from tool -> plugin mapping
    try {
      const { getPluginIdFromTool } = await import('./openclaw-plugin.js');
      return getPluginIdFromTool(input.toolName);
    } catch {
      // Mapping not available (plugin not loaded)
      return null;
    }
  }
}
