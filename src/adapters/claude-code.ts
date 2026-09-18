import type { ActionEnvelope } from '../types/action.js';
import type { HookAdapter, HookInput } from './types.js';
import type { AgentLifecycleCapabilities, RuntimeActionType } from '../runtime/types.js';

/**
 * Tool name → action type mapping for Claude Code
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  Bash: 'exec_command',
  PowerShell: 'exec_command',
  Read: 'read_file',
  Write: 'write_file',
  Edit: 'write_file',
  MultiEdit: 'write_file',
  WebFetch: 'network_request',
  WebSearch: 'web_search',
};

export type ClaudeCodeLifecycleHook =
  | 'UserPromptSubmit'
  | 'UserPromptExpansion'
  | 'PreToolUse'
  | 'PostToolUse'
  | 'PostToolUseFailure'
  | 'PostToolBatch'
  | 'ConfigChange'
  | 'PreModelSwitch'
  | 'PostModelSwitch'
  | 'MessageDisplay'
  | 'Stop'
  | 'InstructionsLoaded'
  | 'PreCompact'
  | 'PostCompact';

export interface ClaudeCodeRuntimeHookInput {
  rawInput: Record<string, unknown>;
  actionType: RuntimeActionType;
  toolName: string;
  sessionId?: string;
  phase?: 'pre' | 'post';
}

/**
 * Claude Code hook adapter
 *
 * Bridges Claude Code's PreToolUse/PostToolUse stdin/stdout protocol
 * to the common AgentGuard decision engine.
 */
export class ClaudeCodeAdapter implements HookAdapter {
  readonly name = 'claude-code';
  readonly capabilities: AgentLifecycleCapabilities = {
    userPrompt: 'blocking',
    promptExpansion: 'blocking',
    modelRequest: 'none',
    modelResponse: 'none',
    preTool: 'blocking',
    postTool: 'blocking',
    toolOutputRewrite: true,
    postToolBatch: 'blocking',
    configChange: 'blocking',
    modelSwitch: 'blocking',
    assistantDisplay: 'rewrite_display_only',
    finalDestination: false,
    credentialFacts: false,
    exactPayloadBytes: false,
    retryAndFallback: false,
    auxiliaryModelCalls: false,
  };

  parseInput(raw: unknown): HookInput {
    const data = raw as Record<string, unknown>;
    const hookEvent = (data.hook_event_name as string) || '';
    return {
      toolName: (data.tool_name as string) || '',
      toolInput: (data.tool_input as Record<string, unknown>) || {},
      eventType: hookEvent.startsWith('Post') ? 'post' : 'pre',
      hookEventName: hookEvent,
      sessionId: data.session_id as string | undefined,
      cwd: data.cwd as string | undefined,
      raw: data,
    };
  }

  mapToolToActionType(toolName: string): string | null {
    const runtimeType = this.mapToolToRuntimeAction(toolName, {});
    if (runtimeType === 'shell') return 'exec_command';
    if (runtimeType === 'file_read') return 'read_file';
    if (runtimeType === 'file_write') return 'write_file';
    if (runtimeType === 'network') return 'network_request';
    if (runtimeType === 'web_search') return 'web_search';
    if (runtimeType === 'mcp_tool') return 'mcp_tool';
    return TOOL_ACTION_MAP[toolName] || null;
  }

  mapToolToRuntimeAction(toolName: string, raw?: unknown): RuntimeActionType {
    const lower = toolName.toLowerCase();
    if (lower.startsWith('mcp__')) return 'mcp_tool';
    if (toolName === 'Bash' || toolName === 'PowerShell' || lower.includes('shell') || lower.includes('exec')) return 'shell';
    if (toolName === 'Read' || lower.includes('read') || lower === 'view_image') return 'file_read';
    if (['Write', 'Edit', 'MultiEdit', 'apply_patch'].includes(toolName)
        || lower.includes('write') || lower.includes('edit') || lower.includes('patch')) return 'file_write';
    if (toolName === 'WebSearch' || lower.includes('websearch') || lower.includes('web_search')) return 'web_search';
    if (toolName === 'WebFetch' || lower.includes('web') || lower.includes('browser')) return 'network';
    const event = record(raw);
    const input = record(event.tool_input ?? event.toolInput ?? event.params ?? event.args);
    if (typeof input.command === 'string' || typeof input.cmd === 'string') return 'shell';
    if (typeof input.url === 'string' || typeof input.uri === 'string') return 'network';
    if (typeof input.query === 'string') return 'web_search';
    if (typeof input.file_path === 'string' || typeof input.path === 'string') {
      return ['content', 'new_string', 'old_string', 'patch'].some((key) => typeof input[key] === 'string')
        ? 'file_write'
        : 'file_read';
    }
    return 'other';
  }

  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null {
    const actionType = this.mapToolToActionType(input.toolName);
    if (!actionType) return null;

    const actor = {
      skill: {
        id: initiatingSkill || 'claude-code-session',
        source: initiatingSkill || 'claude-code',
        version_ref: '0.0.0',
        artifact_hash: '',
      },
    };

    const context = {
      session_id: input.sessionId || `hook-${Date.now()}`,
      user_present: true,
      env: 'prod' as const,
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    // Build action data based on type
    let actionData: Record<string, unknown>;

    switch (actionType) {
      case 'exec_command':
        actionData = {
          command: (input.toolInput.command as string) || '',
          args: [],
          cwd: input.cwd,
        };
        break;

      case 'write_file':
        actionData = {
          path: (input.toolInput.file_path as string) || '',
        };
        break;

      case 'read_file':
        actionData = {
          path: (input.toolInput.file_path as string) || (input.toolInput.path as string) || '',
        };
        break;

      case 'mcp_tool':
        actionData = { ...input.toolInput };
        break;

      case 'network_request':
        actionData = {
          method: 'GET',
          url: (input.toolInput.url as string) || '',
        };
        break;

      case 'web_search':
        actionData = {
          query: (input.toolInput.query as string) || '',
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
    const data = input.raw as Record<string, unknown>;
    const explicit = data.skill_name ?? data.skillName;
    return typeof explicit === 'string' && explicit.length > 0 ? explicit : null;
  }

  normalizeLifecycleEvent(raw: unknown): ClaudeCodeRuntimeHookInput {
    const event = record(raw);
    const hook = typeof event.hook_event_name === 'string' ? event.hook_event_name : '';
    const toolName = typeof event.tool_name === 'string' ? event.tool_name : hook;
    return {
      rawInput: event,
      actionType: hook === 'PostToolBatch' ? 'llm_request' : this.mapToolToRuntimeAction(toolName, event),
      toolName,
      sessionId: typeof event.session_id === 'string' ? event.session_id : undefined,
      phase: hook.startsWith('Post') || hook === 'MessageDisplay' || hook === 'Stop'
        || hook === 'InstructionsLoaded' ? 'post' : 'pre',
    };
  }
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
