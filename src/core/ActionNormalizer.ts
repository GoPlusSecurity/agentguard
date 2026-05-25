/**
 * @file ActionNormalizer.ts
 * @description Validated harness registry for GoPlus Agent Guard.
 *
 * Each registered harness maps its protocol-specific payload to a unified
 * ActionEnvelope. The whitelist ensures only known multi-agent protocols
 * are auditable — unknown harnesses are rejected at normalize() time.
 *
 * user_present defaults vary by harness type:
 *   - User-facing harnesses (claude-code, openai-functions): true
 *   - Orchestration / machine-to-machine harnesses (mcp, openclaw,
 *     open-multi-agent): false unless explicitly signalled
 */

import type { ActionEnvelope, ActionData, ActionType } from '../types/action.js';

export type AdapterFunction = (raw: Record<string, unknown>) => ActionEnvelope;

/**
 * Valid action types — used to validate dynamic values before casting.
 */
const VALID_ACTION_TYPES: ReadonlySet<string> = new Set<ActionType>([
  'network_request', 'exec_command', 'read_file',
  'write_file', 'secret_access', 'web3_tx', 'web3_sign',
]);

function isValidActionType(value: unknown): value is ActionType {
  return typeof value === 'string' && VALID_ACTION_TYPES.has(value);
}

export class ActionNormalizer {
  private static registry = new Map<string, AdapterFunction>();

  static {
    // 1. Anthropic Claude Code (Official Protocol) — user-facing harness
    this.register('claude-code', (raw) => ({
      actor: { skill: { id: 'claude-code', source: 'official', version_ref: '1.0.0', artifact_hash: '' } },
      action: { type: 'exec_command', data: (raw.tool_input ?? {}) as ActionData },
      context: {
        session_id: (typeof raw.session_id === 'string' ? raw.session_id : '') || 'default',
        user_present: typeof raw.user_present === 'boolean' ? raw.user_present : true,
        env: 'prod',
        time: new Date().toISOString(),
      },
    }));

    // 2. Model Context Protocol (MCP - Industry Standard)
    this.register('mcp', (raw) => ({
      actor: {
        skill: {
          id: (typeof raw.name === 'string' ? raw.name : '') || 'mcp-server',
          source: 'mcp',
          version_ref: '1.0.0',
          artifact_hash: '',
        },
      },
      action: { type: 'exec_command', data: (raw.arguments ?? {}) as ActionData },
      context: {
        session_id: (typeof raw.session_id === 'string' ? raw.session_id : '') || 'mcp-session',
        user_present: typeof raw.user_present === 'boolean' ? raw.user_present : false,
        env: 'prod',
        time: new Date().toISOString(),
      },
    }));

    // 3. OpenAI Function Calling — user-facing harness
    this.register('openai-functions', (raw) => {
      let parsedArgs: ActionData;
      if (typeof raw.arguments === 'string') {
        try {
          parsedArgs = JSON.parse(raw.arguments) as ActionData;
        } catch {
          parsedArgs = { command: '' } as unknown as ActionData;
        }
      } else {
        parsedArgs = (raw.arguments ?? {}) as ActionData;
      }
      return {
        actor: { skill: { id: 'openai-agent', source: 'official', version_ref: '4.0.0', artifact_hash: '' } },
        action: { type: 'exec_command', data: parsedArgs },
        context: {
          session_id: (typeof raw.session_id === 'string' ? raw.session_id : '') || 'openai-session',
          user_present: typeof raw.user_present === 'boolean' ? raw.user_present : true,
          env: 'prod',
          time: new Date().toISOString(),
        },
      };
    });

    // 4. OpenClaw (Local Plugin Harness)
    this.register('openclaw', (raw) => {
      const actionType = isValidActionType(raw.actionType) ? raw.actionType : 'exec_command';
      return {
        actor: {
          skill: {
            id: (typeof raw.skillId === 'string' ? raw.skillId : '') || 'openclaw-plugin',
            source: 'local',
            version_ref: '1.0.0',
            artifact_hash: '',
          },
        },
        action: { type: actionType, data: (raw.params ?? {}) as ActionData },
        context: {
          session_id: (typeof raw.session_id === 'string' ? raw.session_id : '') || 'openclaw-session',
          user_present: typeof raw.user_present === 'boolean' ? raw.user_present : false,
          env: 'prod',
          time: new Date().toISOString(),
        },
      };
    });

    // 5. Open Multi Agent (Parallel Orchestration)
    //
    // Sub-agents may invoke any action type (exec, network, file, web3).
    // The harness payload can carry an explicit actionType and structured
    // params; if absent, falls back to exec_command with raw prompt text
    // for backward compatibility.
    this.register('open-multi-agent', (raw) => {
      const actionType: ActionType = isValidActionType(raw.actionType)
        ? raw.actionType
        : 'exec_command';

      const params = (raw.params !== null && typeof raw.params === 'object')
        ? raw.params as Record<string, unknown>
        : null;

      let data: ActionData;
      switch (actionType) {
        case 'network_request':
          data = {
            method: (typeof params?.method === 'string' ? params.method : 'GET') as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
            url: typeof params?.url === 'string' ? params.url : '',
            body_preview: typeof params?.body === 'string' ? params.body : undefined,
          };
          break;

        case 'write_file':
        case 'read_file':
          data = {
            path: typeof params?.path === 'string'
              ? params.path
              : typeof params?.file_path === 'string'
                ? params.file_path
                : '',
          };
          break;

        case 'web3_tx':
          data = {
            chain_id: typeof params?.chain_id === 'number' ? params.chain_id : 1,
            from: typeof params?.from === 'string' ? params.from : '',
            to: typeof params?.to === 'string' ? params.to : '',
            value: typeof params?.value === 'string' ? params.value : '0',
            data: typeof params?.data === 'string' ? params.data : undefined,
          };
          break;

        case 'web3_sign':
          data = {
            chain_id: typeof params?.chain_id === 'number' ? params.chain_id : 1,
            signer: typeof params?.signer === 'string' ? params.signer : '',
            message: typeof params?.message === 'string' ? params.message : undefined,
            typed_data: params?.typed_data,
          };
          break;

        default:
          // exec_command, secret_access, and any future types
          data = {
            command: typeof raw.prompt === 'string'
              ? raw.prompt
              : typeof params?.command === 'string'
                ? params.command
                : '',
          } as ActionData;
          break;
      }

      return {
        actor: {
          skill: {
            id: typeof raw.agentId === 'string' ? raw.agentId : 'parallel-orchestrator',
            source: 'local',
            version_ref: '1.0.0',
            artifact_hash: '',
          },
        },
        action: { type: actionType, data },
        context: {
          session_id: (typeof raw.session_id === 'string' ? raw.session_id : '') || 'parallel-session',
          user_present: typeof raw.user_present === 'boolean' ? raw.user_present : false,
          env: 'prod',
          time: new Date().toISOString(),
        },
      };
    });
  }

  public static register(harnessId: string, adapter: AdapterFunction): void {
    this.registry.set(harnessId.toLowerCase(), adapter);
  }

  public static normalize(raw: unknown, harnessId: string): ActionEnvelope | null {
    const adapter = this.registry.get(harnessId.toLowerCase());
    if (!adapter) return null;
    if (raw === null || typeof raw !== 'object') return null;
    try {
      return adapter(raw as Record<string, unknown>);
    } catch {
      return null;
    }
  }
}
