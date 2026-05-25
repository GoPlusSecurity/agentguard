/**
 * @file SecurityEngine.ts
 * @description Core security engine for GoPlus Agent Guard — Track 1 (Quick-Check).
 *
 * Part of the Dual-Track Defense System:
 *   Track 1 (this): Stateless, sub-millisecond pattern matching for high-throughput
 *                    multi-agent orchestration. Used by HookAdapter / LegacyAdapter
 *                    to avoid IPC bottlenecks in parallel execution pipelines.
 *   Track 2:        Full ActionScanner.decide() with trust registry, capability
 *                   checks, and Web3 simulation — used by platform adapters
 *                   (ClaudeCodeAdapter / OpenClawAdapter) via evaluateHook().
 *
 * Action-type-aware: rules are grouped by action type so that each category
 * gets purpose-built pattern matching while maintaining sub-ms latency.
 */

import type { ActionEnvelope, ActionType } from '../types/action.js';

export type ThreatLevel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';

export interface AuditResult {
  isSafe: boolean;
  action: 'PASS' | 'REWRITE' | 'BLOCK';
  modifiedPrompt: string;
  threatLevel: ThreatLevel;
  reason?: string;
}

interface DangerRule {
  pattern: RegExp;
  level: ThreatLevel;
  label: string;
}

// ---------------------------------------------------------------------------
// Rules grouped by action type
// ---------------------------------------------------------------------------

/** Shell / exec patterns */
const EXEC_RULES: readonly DangerRule[] = [
  { pattern: /rm\s+-rf/i, level: 'HIGH', label: 'Filesystem Destruction' },
  { pattern: /rm\s+-fr/i, level: 'HIGH', label: 'Filesystem Destruction' },
  { pattern: /mkfs\b/i, level: 'HIGH', label: 'Filesystem Format' },
  { pattern: /dd\s+if=/i, level: 'HIGH', label: 'Raw Disk Write' },
  { pattern: /:\s*\(\s*\)\s*\{.*:\s*\|\s*:.*&.*\}/, level: 'HIGH', label: 'Fork Bomb' },
  { pattern: /delete\s+from/i, level: 'HIGH', label: 'Database Wipe' },
  { pattern: /drop\s+table/i, level: 'HIGH', label: 'Database Drop' },
  { pattern: /sudo\s+/i, level: 'MEDIUM', label: 'Privilege Escalation' },
  { pattern: /curl.*\|\s*(?:bash|sh)\b/, level: 'HIGH', label: 'Remote Code Execution' },
  { pattern: /wget.*\|\s*(?:bash|sh)\b/, level: 'HIGH', label: 'Remote Code Execution' },
  { pattern: /chmod\s+777/i, level: 'MEDIUM', label: 'Overly Permissive File Mode' },
];

/** Network request patterns */
const NETWORK_RULES: readonly DangerRule[] = [
  // Internal / metadata endpoints
  { pattern: /169\.254\.169\.254/i, level: 'HIGH', label: 'Cloud Metadata SSRF' },
  { pattern: /metadata\.google\.internal/i, level: 'HIGH', label: 'GCP Metadata SSRF' },
  { pattern: /localhost:\d+\/(?:admin|internal|debug)/i, level: 'MEDIUM', label: 'Localhost Admin Access' },
  // Data exfiltration via known paste / webhook services
  { pattern: /(?:webhook\.site|requestbin\.com|pipedream\.net|hookbin\.com)/i, level: 'HIGH', label: 'Data Exfiltration Endpoint' },
  { pattern: /(?:ngrok\.io|burpcollaborator\.net|interact\.sh)/i, level: 'HIGH', label: 'Suspicious Callback Endpoint' },
  // File protocol
  { pattern: /^file:\/\//i, level: 'HIGH', label: 'File Protocol Access' },
];

/** File path patterns (write & read) */
const FILE_RULES: readonly DangerRule[] = [
  // Sensitive credential files
  { pattern: /\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)/i, level: 'HIGH', label: 'SSH Key Access' },
  { pattern: /\.aws\/credentials/i, level: 'HIGH', label: 'AWS Credentials Access' },
  { pattern: /\.env(?:\.local|\.production|\.staging)?$/i, level: 'HIGH', label: 'Environment Secrets Access' },
  { pattern: /\.gnupg\//i, level: 'MEDIUM', label: 'GPG Keyring Access' },
  { pattern: /\.git-credentials/i, level: 'HIGH', label: 'Git Credentials Access' },
  { pattern: /\.kube\/config/i, level: 'HIGH', label: 'Kubernetes Config Access' },
  { pattern: /\.docker\/config\.json/i, level: 'MEDIUM', label: 'Docker Config Access' },
  { pattern: /wallet\.dat/i, level: 'HIGH', label: 'Crypto Wallet Access' },
  { pattern: /keystore\//i, level: 'MEDIUM', label: 'Keystore Access' },
  // System critical paths
  { pattern: /\/etc\/(?:passwd|shadow|sudoers)/i, level: 'HIGH', label: 'System Auth File Access' },
  { pattern: /\/etc\/(?:hosts|resolv\.conf)/i, level: 'MEDIUM', label: 'System Network Config Access' },
];

/** Web3 transaction patterns */
const WEB3_RULES: readonly DangerRule[] = [
  // Unlimited approvals (maxUint256 = 0xfff...fff)
  { pattern: /^0x095ea7b3.*ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/i, level: 'HIGH', label: 'Unlimited Token Approval' },
  // Known malicious patterns: setApprovalForAll(address,bool=true)
  { pattern: /^0xa22cb465/i, level: 'MEDIUM', label: 'SetApprovalForAll' },
  // transferOwnership
  { pattern: /^0xf2fde38b/i, level: 'HIGH', label: 'Ownership Transfer' },
  // selfdestruct / delegatecall in raw data
  { pattern: /selfdestruct/i, level: 'HIGH', label: 'Contract Self-Destruct' },
  // Zero address as recipient (burn or exploit)
  { pattern: /"to"\s*:\s*"0x0{40}"/i, level: 'MEDIUM', label: 'Zero Address Recipient' },
];

/** Lookup table: action type → rules */
const RULES_BY_TYPE: Partial<Record<ActionType, readonly DangerRule[]>> = {
  exec_command: EXEC_RULES,
  network_request: NETWORK_RULES,
  read_file: FILE_RULES,
  write_file: FILE_RULES,
  web3_tx: WEB3_RULES,
  web3_sign: WEB3_RULES,
};

export class SecurityEngine {
  /**
   * Legacy compat: full rule list for tests that reference DANGER_ZONE.
   */
  private static readonly DANGER_ZONE: readonly DangerRule[] = EXEC_RULES;

  /**
   * Audit an action envelope for obviously dangerous patterns.
   *
   * Action-type-aware: selects the appropriate rule set based on
   * `envelope.action.type`. Falls back to the generic EXEC_RULES
   * for unrecognized types (fail-closed on pattern matching).
   *
   * Returns BLOCK for HIGH threats, REWRITE for MEDIUM.
   */
  public static async auditAction(envelope: ActionEnvelope): Promise<AuditResult> {
    const { action } = envelope;

    // Select rules by action type, falling back to exec rules
    const rules = RULES_BY_TYPE[action.type] ?? EXEC_RULES;

    // Build the string to scan:
    //  - For network_request: prioritize the url field for faster matching
    //  - For file actions: prioritize the path field
    //  - For web3: scan both the 'data' field and the full JSON
    //  - Default: JSON-serialize all action data
    const data = action.data as unknown as Record<string, unknown>;
    let scanTarget: string;

    switch (action.type) {
      case 'network_request':
        scanTarget = typeof data.url === 'string' ? data.url : JSON.stringify(data);
        break;
      case 'read_file':
      case 'write_file':
        scanTarget = typeof data.path === 'string' ? data.path : JSON.stringify(data);
        break;
      case 'web3_tx':
      case 'web3_sign':
        // Scan calldata + full JSON to catch function selectors and field values
        scanTarget = (typeof data.data === 'string' ? data.data : '') + '\n' + JSON.stringify(data);
        break;
      default:
        scanTarget = JSON.stringify(data);
        break;
    }

    for (const rule of rules) {
      if (rule.pattern.test(scanTarget)) {
        return {
          isSafe: false,
          action: rule.level === 'HIGH' ? 'BLOCK' : 'REWRITE',
          threatLevel: rule.level,
          reason: rule.label,
          modifiedPrompt: 'Instruction blocked due to security policy violation.',
        };
      }
    }

    return { isSafe: true, action: 'PASS', threatLevel: 'NONE', modifiedPrompt: '' };
  }
}
