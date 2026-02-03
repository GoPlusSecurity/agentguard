import type { SkillIdentity } from './skill.js';

/**
 * Risk levels for scan results
 */
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Risk tag identifiers
 */
export type RiskTag =
  // Execution risks
  | 'SHELL_EXEC'
  | 'REMOTE_LOADER'
  | 'AUTO_UPDATE'
  // Secret access risks
  | 'READ_ENV_SECRETS'
  | 'READ_SSH_KEYS'
  | 'READ_KEYCHAIN'
  // Data exfiltration risks
  | 'NET_EXFIL_UNRESTRICTED'
  | 'WEBHOOK_EXFIL'
  // Code obfuscation
  | 'OBFUSCATION'
  // Prompt injection
  | 'PROMPT_INJECTION'
  // Web3 specific
  | 'PRIVATE_KEY_PATTERN'
  | 'MNEMONIC_PATTERN'
  | 'WALLET_DRAINING'
  | 'UNLIMITED_APPROVAL'
  | 'DANGEROUS_SELFDESTRUCT'
  | 'HIDDEN_TRANSFER'
  | 'PROXY_UPGRADE'
  | 'FLASH_LOAN_RISK'
  | 'REENTRANCY_PATTERN'
  | 'SIGNATURE_REPLAY';

/**
 * Evidence of a detected risk
 */
export interface ScanEvidence {
  /** Risk tag that was triggered */
  tag: RiskTag;
  /** File path relative to scan root */
  file: string;
  /** Line number (1-indexed) */
  line: number;
  /** Matched content (truncated if too long) */
  match: string;
  /** Additional context */
  context?: string;
}

/**
 * Scan payload types
 */
export type ScanPayloadType = 'dir' | 'zip' | 'repo_url';

/**
 * Scan request payload
 */
export interface ScanPayload {
  /** Skill identity */
  skill: SkillIdentity;
  /** Payload to scan */
  payload: {
    type: ScanPayloadType;
    ref: string;
  };
  /** Scan options */
  options?: {
    /** Hint for languages to scan */
    language_hint?: string[];
    /** Enable deep analysis (slower) */
    deep?: boolean;
  };
}

/**
 * Scan result
 */
export interface ScanResult {
  /** Overall risk level */
  risk_level: RiskLevel;
  /** All detected risk tags */
  risk_tags: RiskTag[];
  /** Detailed evidence for each finding */
  evidence: ScanEvidence[];
  /** Human-readable summary */
  summary: string;
  /** Scan metadata */
  metadata?: {
    files_scanned: number;
    scan_duration_ms: number;
    scan_time: string;
  };
}

/**
 * Rule definition for the scanner
 */
export interface ScanRule {
  /** Rule identifier */
  id: RiskTag;
  /** Rule description */
  description: string;
  /** Risk level when triggered */
  severity: RiskLevel;
  /** File patterns to scan (glob) */
  file_patterns: string[];
  /** Detection patterns (regex) */
  patterns: RegExp[];
  /** Optional validator function for complex rules */
  validator?: (content: string, match: RegExpMatchArray) => boolean;
}

/**
 * Calculate overall risk level from tags
 */
export function calculateRiskLevel(tags: RiskTag[], rules: ScanRule[]): RiskLevel {
  const severities = tags.map((tag) => {
    const rule = rules.find((r) => r.id === tag);
    return rule?.severity ?? 'low';
  });

  if (severities.includes('critical')) return 'critical';
  if (severities.includes('high')) return 'high';
  if (severities.includes('medium')) return 'medium';
  return 'low';
}
