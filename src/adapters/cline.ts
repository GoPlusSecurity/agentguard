import type { ActionEnvelope } from '../types/action.js';
import { isSensitivePath } from './common.js';
import type { HookAdapter, HookInput } from './types.js';

/**
 * Tool name -> action type mapping for Cline.
 *
 * Cline tool names come from two places:
 *   - File hooks (PreToolUse/PostToolUse): `tool_call.name`
 *   - Runtime plugins (@cline/core hooks.beforeTool): `toolCall.toolName`
 *
 * Both surfaces use the same identifiers, so a single map covers them.
 * See https://github.com/cline/cline/tree/main/sdk/examples/hooks and
 * https://github.com/cline/cline/tree/main/sdk/examples/plugins
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  run_commands: 'exec_command',
  execute_command: 'exec_command',
  write_to_file: 'write_file',
  write_file: 'write_file',
  replace_in_file: 'write_file',
  editor: 'write_file',
  read_files: 'read_file',
  read_file: 'read_file',
  web_fetch: 'network_request',
  browser_action: 'network_request',
  web_search: 'web_search',
};

function collectReadFilePaths(toolInput: Record<string, unknown>): string[] {
  const out: string[] = [];
  const single = firstString(toolInput.path, toolInput.file_path, toolInput.filePath);
  if (single) out.push(single);
  const lists = [toolInput.files, toolInput.file_paths, toolInput.paths];
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const entry of list) {
      if (typeof entry === 'string' && entry.length > 0) {
        out.push(entry);
      } else if (entry && typeof entry === 'object') {
        const p = (entry as Record<string, unknown>).path;
        if (typeof p === 'string' && p.length > 0) out.push(p);
      }
    }
  }
  return out;
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function eventTypeFromHookName(name: string): 'pre' | 'post' {
  // Cline file-hook event names: tool_call (pre), tool_result (post).
  // Runtime hook names: beforeTool / afterTool.
  if (name === 'tool_result' || name.startsWith('after') || name.startsWith('Post')) return 'post';
  return 'pre';
}

/**
 * Cline hook adapter.
 *
 * Bridges Cline file-hook stdin/stdout payloads and runtime-plugin
 * `beforeTool` / `afterTool` events to the common AgentGuard engine.
 *
 * Cline file-hook payload (PreToolUse):
 *   {
 *     "hookName": "tool_call",
 *     "taskId": "...",
 *     "workspaceRoots": ["/repo"],
 *     "tool_call": { "id": "...", "name": "run_commands", "input": {...} }
 *   }
 *
 * Cline runtime-plugin payload (hooks.beforeTool):
 *   { toolCall: { id, toolName, input }, input }
 *   — wrap as { hookName: 'beforeTool', tool_call: {name: toolName, input} }
 *   before calling parseInput, or pass through as-is.
 */
export class ClineAdapter implements HookAdapter {
  readonly name = 'cline';

  parseInput(raw: unknown): HookInput {
    const data = (raw as Record<string, unknown>) || {};
    const hookEvent = firstString(data.hookName, data.hook_event_name, data.event);

    const toolCall =
      (data.tool_call as Record<string, unknown>) ||
      (data.toolCall as Record<string, unknown>) ||
      {};

    const toolName =
      firstString(toolCall.name, (toolCall as Record<string, unknown>).toolName, data.tool_name) ||
      '';

    const toolInput =
      ((toolCall.input as Record<string, unknown>) ||
        (data.tool_input as Record<string, unknown>) ||
        (data.preToolUse as Record<string, unknown> | undefined)?.parameters ||
        {}) as Record<string, unknown>;

    const workspaceRoots = data.workspaceRoots;
    const cwd = Array.isArray(workspaceRoots) && typeof workspaceRoots[0] === 'string'
      ? (workspaceRoots[0] as string)
      : (data.cwd as string | undefined);

    return {
      toolName,
      toolInput,
      eventType: eventTypeFromHookName(hookEvent),
      sessionId: firstString(data.taskId, data.session_id, data.sessionId) || undefined,
      cwd,
      raw: data,
    };
  }

  mapToolToActionType(toolName: string): string | null {
    return TOOL_ACTION_MAP[toolName] || null;
  }

  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null {
    const actionType = this.mapToolToActionType(input.toolName);
    if (!actionType) return null;

    const actor = {
      skill: {
        id: initiatingSkill || 'cline-session',
        source: initiatingSkill || 'cline',
        version_ref: '0.0.0',
        artifact_hash: '',
      },
    };

    const context = {
      session_id: input.sessionId || `cline-${Date.now()}`,
      user_present: true,
      env: 'prod' as const,
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    let actionData: Record<string, unknown>;

    switch (actionType) {
      case 'exec_command': {
        // run_commands accepts string | string[] | { command | commands | cmd }
        const ti = input.toolInput;
        let command = firstString(ti.command, ti.cmd, ti.commands);
        if (!command && Array.isArray(ti.commands)) {
          command = (ti.commands as unknown[])
            .filter((c): c is string => typeof c === 'string')
            .join(' && ');
        }
        actionData = {
          command,
          args: [],
          cwd: firstString(ti.cwd, ti.workdir, input.cwd),
        };
        break;
      }

      case 'write_file':
        actionData = {
          path: firstString(
            input.toolInput.path,
            input.toolInput.file_path,
            input.toolInput.filePath,
            input.toolInput.target
          ),
        };
        break;

      case 'read_file': {
        // Cline's read_files accepts multiple files (string | string[] |
        // { path }[] under .files/.file_paths/.paths). The single-envelope
        // contract forces us to pick one representative path; we prefer a
        // path that isSensitivePath flags so multi-file reads can't smuggle
        // a sensitive target alongside benign ones.
        const ti = input.toolInput;
        const paths = collectReadFilePaths(ti);
        const sensitive = paths.find((p) => isSensitivePath(p));
        const path = sensitive || paths[0] || '';
        actionData = sensitive
          ? { path, paths, sensitive_path: sensitive }
          : { path, ...(paths.length > 1 ? { paths } : {}) };
        break;
      }

      case 'network_request':
        actionData = {
          method: firstString(input.toolInput.method) || 'GET',
          url: firstString(input.toolInput.url, input.toolInput.href, input.toolInput.target),
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
    // Cline does not currently expose a skill stack the way Claude Code does.
    // Plugins may set `initiating_skill` on the payload; honor it when present.
    const raw = input.raw as Record<string, unknown>;
    return (
      firstString(raw.initiating_skill, raw.sourceSkill, (raw.metadata as Record<string, unknown> | undefined)?.skill) ||
      null
    );
  }
}
