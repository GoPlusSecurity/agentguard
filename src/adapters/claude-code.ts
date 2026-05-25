import { openSync, readSync, closeSync, fstatSync } from 'node:fs';
import type { ActionEnvelope, ActionType, ActionContext } from '../types/action.js';
import type { SkillIdentity } from '../types/skill.js';
import type { HookAdapter, HookInput } from './types.js';
import { getString } from './common.js';

/**
 * Tool name -> action type mapping for Claude Code
 */
const TOOL_ACTION_MAP: Record<string, ActionType> = {
  Bash: 'exec_command',
  Write: 'write_file',
  Edit: 'write_file',
  Read: 'read_file',
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
    const data = (raw !== null && typeof raw === 'object') ? raw as Record<string, unknown> : {};
    const hookEvent = getString(data, 'hook_event_name');
    const toolInput = (data.tool_input !== null && typeof data.tool_input === 'object')
      ? data.tool_input as Record<string, unknown>
      : {};
    return {
      toolName: getString(data, 'tool_name'),
      toolInput,
      eventType: hookEvent.startsWith('Post') ? 'post' : 'pre',
      sessionId: getString(data, 'session_id') || undefined,
      cwd: getString(data, 'cwd') || undefined,
      raw: data,
    };
  }

  mapToolToActionType(toolName: string): ActionType | null {
    return TOOL_ACTION_MAP[toolName] ?? null;
  }

  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null {
    const actionType = this.mapToolToActionType(input.toolName);
    if (!actionType) return null;

    const skill: SkillIdentity = {
      id: initiatingSkill || 'claude-code-session',
      source: initiatingSkill || 'claude-code',
      version_ref: '0.0.0',
      artifact_hash: '',
    };

    const context: ActionContext = {
      session_id: input.sessionId || `hook-${Date.now()}`,
      user_present: true,
      env: 'prod',
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    switch (actionType) {
      case 'exec_command':
        return {
          actor: { skill },
          action: {
            type: actionType,
            data: {
              command: getString(input.toolInput as Record<string, unknown>, 'command'),
              args: [],
              cwd: input.cwd,
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
              path: getString(input.toolInput as Record<string, unknown>, 'file_path'),
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
              path: getString(input.toolInput as Record<string, unknown>, 'file_path'),
            },
          },
          context,
        };

      case 'network_request': {
        const ti = input.toolInput as Record<string, unknown>;
        return {
          actor: { skill },
          action: {
            type: actionType,
            data: {
              method: 'GET' as const,
              url: getString(ti, 'url') || getString(ti, 'query'),
            },
          },
          context,
        };
      }

      default:
        return null;
    }
  }

  async inferInitiatingSkill(input: HookInput): Promise<string | null> {
    const data = (input.raw !== null && typeof input.raw === 'object')
      ? input.raw as Record<string, unknown>
      : {};
    const transcriptPath = getString(data, 'transcript_path');
    if (!transcriptPath) return null;

    let fd: number | null = null;
    try {
      fd = openSync(transcriptPath, 'r');
      const stat = fstatSync(fd);
      const TAIL_SIZE = 4096;
      const start = Math.max(0, stat.size - TAIL_SIZE);
      const buf = Buffer.alloc(Math.min(TAIL_SIZE, stat.size));
      readSync(fd, buf, 0, buf.length, start);
      closeSync(fd);
      fd = null;

      const tail = buf.toString('utf-8');
      const lines = tail.split('\n').filter(Boolean);

      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const entry = JSON.parse(lines[i]);
          if (entry.type === 'tool_use' && entry.name === 'Skill' && typeof entry.input?.skill === 'string') {
            return entry.input.skill;
          }
          if (entry.role === 'assistant' && Array.isArray(entry.content)) {
            for (const block of entry.content) {
              if (block.type === 'tool_use' && block.name === 'Skill' && typeof block.input?.skill === 'string') {
                return block.input.skill;
              }
            }
          }
        } catch {
          // Not valid JSON line — skip
        }
      }
    } catch {
      // Can't read transcript
    } finally {
      // Ensure file descriptor is always closed
      if (fd !== null) {
        try { closeSync(fd); } catch { /* ignore */ }
      }
    }
    return null;
  }
}
