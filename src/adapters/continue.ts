import type { ActionEnvelope } from '../types/action.js';
import { isSensitivePath } from './common.js';
import type { HookAdapter, HookInput } from './types.js';

/**
 * Tool name → action type mapping for Continue.
 *
 * Continue's CLI (`cn`) exposes a Claude-Code-compatible PreToolUse/PostToolUse
 * hook system at `~/.continue/settings.json` (and `~/.claude/settings.json`).
 * Built-in tool names are listed in continuedev/continue's
 * `core/tools/builtIn.ts` and `extensions/cli/src/tools/builtInToolNames.ts`.
 *
 * MCP tools come through with their bare server-defined names; we leave them
 * unmapped (pass-through) so AgentGuard does not block third-party tools it
 * cannot reason about.
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  run_terminal_command: 'exec_command',
  create_new_file: 'write_file',
  edit_existing_file: 'write_file',
  single_find_and_replace: 'write_file',
  multi_edit: 'write_file',
  read_file: 'read_file',
  read_file_range: 'read_file',
  read_currently_open_file: 'read_file',
  fetch_url_content: 'network_request',
  search_web: 'web_search',
};

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function eventTypeFromHookName(name: string): 'pre' | 'post' {
  // Continue: PreToolUse / PostToolUse / PostToolUseFailure
  if (name.startsWith('Post')) return 'post';
  return 'pre';
}

/**
 * Continue hook adapter.
 *
 * Continue's PreToolUse payload (stdin JSON):
 *   {
 *     "hook_event_name": "PreToolUse",
 *     "tool_name": "run_terminal_command",
 *     "tool_input": {...},
 *     "tool_use_id": "...",
 *     "session_id": "...",
 *     "cwd": "/repo",
 *     "transcript_path": "..."
 *   }
 *
 * Response shape lives in the engine bridge (continue-hook.js); this adapter
 * is responsible only for normalizing the payload and building an envelope.
 */
export class ContinueAdapter implements HookAdapter {
  readonly name = 'continue';

  parseInput(raw: unknown): HookInput {
    const data = (raw as Record<string, unknown>) || {};
    const hookEvent = firstString(data.hook_event_name, data.hookEventName);

    return {
      toolName: firstString(data.tool_name, data.toolName),
      toolInput:
        ((data.tool_input as Record<string, unknown>) ||
          (data.toolInput as Record<string, unknown>) ||
          {}) as Record<string, unknown>,
      eventType: eventTypeFromHookName(hookEvent),
      sessionId: firstString(data.session_id, data.sessionId, data.tool_use_id) || undefined,
      cwd: firstString(data.cwd) || undefined,
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
        id: initiatingSkill || 'continue-session',
        source: initiatingSkill || 'continue',
        version_ref: '0.0.0',
        artifact_hash: '',
      },
    };

    const context = {
      session_id: input.sessionId || `continue-${Date.now()}`,
      user_present: true,
      env: 'prod' as const,
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    let actionData: Record<string, unknown>;

    switch (actionType) {
      case 'exec_command': {
        const ti = input.toolInput;
        actionData = {
          command: firstString(ti.command, ti.cmd),
          args: [],
          cwd: firstString(ti.cwd, input.cwd),
        };
        break;
      }

      case 'write_file': {
        // Continue's multi_edit accepts an `edits: [{filePath, ...}]` list.
        // Apply the same worst-case-path rule as the Cline adapter: any
        // sensitive target in the batch should be the envelope's primary
        // path so it can't be smuggled past the engine alongside benign
        // edits.
        const ti = input.toolInput;
        const paths = collectWritePaths(ti);
        const sensitive = paths.find((p) => isSensitivePath(p));
        const primary =
          sensitive ||
          paths[0] ||
          firstString(ti.filepath, ti.file_path, ti.filePath, ti.path, ti.target);
        actionData = sensitive
          ? { path: primary, paths, sensitive_path: sensitive }
          : { path: primary, ...(paths.length > 1 ? { paths } : {}) };
        break;
      }

      case 'read_file': {
        const ti = input.toolInput;
        actionData = {
          path: firstString(ti.filepath, ti.file_path, ti.filePath, ti.path, ti.target),
        };
        break;
      }

      case 'network_request': {
        const ti = input.toolInput;
        actionData = {
          method: firstString(ti.method) || 'GET',
          url: firstString(ti.url, ti.uri, ti.href),
          body_preview: ti.body as string | undefined,
        };
        break;
      }

      case 'web_search': {
        const ti = input.toolInput;
        actionData = {
          query: firstString(ti.query, ti.q, ti.search),
        };
        break;
      }

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
    // Continue passes `transcript_path` and `cwd` but no first-class "skill"
    // attribution. Honor an explicit hint when present.
    const raw = input.raw as Record<string, unknown>;
    return (
      firstString(raw.initiating_skill, raw.sourceSkill, raw.skill) || null
    );
  }
}

function collectWritePaths(toolInput: Record<string, unknown>): string[] {
  const out: string[] = [];
  const single = firstString(
    toolInput.filepath,
    toolInput.file_path,
    toolInput.filePath,
    toolInput.path,
    toolInput.target
  );
  if (single) out.push(single);
  const edits = toolInput.edits;
  if (Array.isArray(edits)) {
    for (const entry of edits) {
      if (!entry || typeof entry !== 'object') continue;
      const p = firstString(
        (entry as Record<string, unknown>).filepath,
        (entry as Record<string, unknown>).file_path,
        (entry as Record<string, unknown>).filePath,
        (entry as Record<string, unknown>).path
      );
      if (p) out.push(p);
    }
  }
  const files = toolInput.files || toolInput.file_paths || toolInput.paths;
  if (Array.isArray(files)) {
    for (const entry of files) {
      if (typeof entry === 'string' && entry.length > 0) out.push(entry);
    }
  }
  return out;
}
