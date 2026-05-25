import { SecurityEngine } from '../core/SecurityEngine.js';
import type { ActionEnvelope } from '../types/action.js';

/**
 * Adapter for process-based orchestration (e.g. sessions_spawn, shell interceptors).
 *
 * Uses Track 1 (SecurityEngine quick-check) to audit raw shell commands
 * with sub-millisecond latency. Suitable for high-throughput pipelines
 * where full Track 2 evaluation would create an IPC bottleneck.
 */
export class LegacyAdapter {
  public static async interceptCommand(cmd: string): Promise<string> {
    const envelope: ActionEnvelope = {
      actor: {
        skill: {
          id: 'legacy-shell',
          source: 'shell_interceptor',
          version_ref: '0.0.0',
          artifact_hash: '',
        },
      },
      action: {
        type: 'exec_command',
        data: { command: cmd, args: [] },
      },
      context: {
        session_id: `legacy-${Date.now()}`,
        user_present: false,
        env: 'prod',
        time: new Date().toISOString(),
      },
    };

    const result = await SecurityEngine.auditAction(envelope);
    return result.isSafe ? cmd : result.modifiedPrompt;
  }
}
