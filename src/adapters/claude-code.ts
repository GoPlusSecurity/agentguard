import { openSync, readSync, closeSync, fstatSync } from 'node:fs';
import type { ActionEnvelope } from '../types/action.js';
import type { HookAdapter, HookInput } from './types.js';

/**
 * Tool name → action type mapping for Claude Code
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  Bash: 'exec_command',
  Write: 'write_file',
  Edit: 'write_file',
  WebFetch: 'network_request',
  WebSearch: 'network_request',
};

/**
 * Claude Code hook adapter
 *
 * Bridges Claude Code's PreToolUse/PostToolUse stdin/stdout protocol
 * to the common AgentGuard decision engine.
 */
export class ClaudeCodeAdapter implements HookAdapter {
  readonly name = 'claude-code';

  parseInput(raw: unknown): HookInput {
    const data = raw as Record<string, unknown>;
    const hookEvent = (data.hook_event_name as string) || '';
    return {
      toolName: (data.tool_name as string) || '',
      toolInput: (data.tool_input as Record<string, unknown>) || {},
      eventType: hookEvent.startsWith('Post') ? 'post' : 'pre',
      sessionId: data.session_id as string | undefined,
      cwd: data.cwd as string | undefined,
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

      case 'network_request':
        actionData = {
          method: 'GET',
          url: (input.toolInput.url as string) || (input.toolInput.query as string) || '',
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
    const transcriptPath = data.transcript_path as string | undefined;
    if (!transcriptPath) return null;

    try {
      const fd = openSync(transcriptPath, 'r');
      const stat = fstatSync(fd);
      const TAIL_SIZE = 4096;
      const start = Math.max(0, stat.size - TAIL_SIZE);
      const buf = Buffer.alloc(Math.min(TAIL_SIZE, stat.size));
      readSync(fd, buf, 0, buf.length, start);
      closeSync(fd);

      const tail = buf.toString('utf-8');
      const lines = tail.split('\n').filter(Boolean);

      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const entry = JSON.parse(lines[i]);
          if (entry.type === 'tool_use' && entry.name === 'Skill' && entry.input?.skill) {
            return entry.input.skill;
          }
          if (entry.role === 'assistant' && Array.isArray(entry.content)) {
            for (const block of entry.content) {
              if (block.type === 'tool_use' && block.name === 'Skill' && block.input?.skill) {
                return block.input.skill;
              }
            }
          }
        } catch {
          // Not valid JSON
        }
      }
    } catch {
      // Can't read transcript
    }
    return null;
  }
}
