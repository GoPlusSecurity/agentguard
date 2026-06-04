import type { ActionEnvelope } from '../types/action.js';
import type { HookAdapter, HookInput } from './types.js';

/**
 * Tool name -> action type mapping for Hermes Agent.
 *
 * Hermes shell hooks expose Python tool names such as "terminal",
 * "write_file", and "web_extract" through the pre_tool_call/post_tool_call
 * plugin-hook bridge.
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  terminal: 'exec_command',
  execute_code: 'exec_command',
  write_file: 'write_file',
  patch: 'write_file',
  skill_manage: 'write_file',
  read_file: 'read_file',
  web_search: 'web_search',
  web_extract: 'network_request',
  browser_navigate: 'network_request',
  browser_open: 'network_request',
  web_open: 'network_request',
  open_url: 'network_request',
  visit_url: 'network_request',
  open: 'network_request',
};

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function eventTypeFromName(name: string): 'pre' | 'post' {
  return name.startsWith('post') ? 'post' : 'pre';
}

/**
 * Hermes hook adapter.
 *
 * Bridges Hermes shell-hook JSON payloads to the common AgentGuard decision
 * engine. Hermes passes hook input as:
 *
 *   {
 *     "hook_event_name": "pre_tool_call",
 *     "tool_name": "terminal",
 *     "tool_input": {"command": "echo hello"},
 *     "session_id": "sess_...",
 *     "cwd": "/workspace",
 *     "extra": {"task_id": "...", "tool_call_id": "..."}
 *   }
 */
export class HermesAdapter implements HookAdapter {
  readonly name = 'hermes';

  parseInput(raw: unknown): HookInput {
    const data = raw as Record<string, unknown>;
    const hookEvent = (data.hook_event_name as string) || '';
    const toolInput =
      (data.tool_input as Record<string, unknown>) ||
      (data.args as Record<string, unknown>) ||
      {};

    return {
      toolName: (data.tool_name as string) || '',
      toolInput,
      eventType: eventTypeFromName(hookEvent),
      sessionId: data.session_id as string | undefined,
      cwd: data.cwd as string | undefined,
      raw: data,
    };
  }

  mapToolToActionType(toolName: string): string | null {
    if (TOOL_ACTION_MAP[toolName]) {
      return TOOL_ACTION_MAP[toolName];
    }
    return null;
  }

  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null {
    const actionType = this.mapToolToActionType(input.toolName);
    if (!actionType) return null;

    const actor = {
      skill: {
        id: initiatingSkill || 'hermes-session',
        source: initiatingSkill || 'hermes',
        version_ref: '0.0.0',
        artifact_hash: '',
      },
    };

    const context = {
      session_id: input.sessionId || `hermes-${Date.now()}`,
      user_present: true,
      env: 'prod' as const,
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    let actionData: Record<string, unknown>;

    switch (actionType) {
      case 'exec_command':
        actionData = {
          command: firstString(input.toolInput.command, input.toolInput.code),
          args: [],
          cwd: firstString(input.toolInput.workdir, input.toolInput.cwd, input.cwd),
        };
        break;

      case 'write_file':
        actionData = {
          path: firstString(
            input.toolInput.path,
            input.toolInput.file_path,
            input.toolInput.target,
            input.toolInput.skill_path
          ),
        };
        break;

      case 'read_file':
        actionData = {
          path: firstString(input.toolInput.path, input.toolInput.file_path),
        };
        break;

      case 'network_request':
        actionData = {
          method: firstString(input.toolInput.method) || 'GET',
          url: firstString(
            input.toolInput.url,
            input.toolInput.href,
            input.toolInput.target
          ),
          body_preview: input.toolInput.body as string | undefined,
        };
        break;

      case 'web_search':
        actionData = {
          query: firstString(input.toolInput.query, input.toolInput.q, input.toolInput.search),
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
    const raw = input.raw as Record<string, unknown>;
    const extra = raw.extra as Record<string, unknown> | undefined;

    return firstString(
      raw.initiating_skill,
      raw.skill,
      extra?.initiating_skill,
      extra?.skill
    ) || null;
  }
}
