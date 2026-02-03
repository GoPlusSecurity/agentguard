import type { ScanRule, RiskTag } from '../../types/scanner.js';

// Import all rule modules
import { SHELL_EXEC_RULES } from './shell-exec.js';
import { REMOTE_LOADER_RULES } from './remote-loader.js';
import { SECRETS_RULES } from './secrets.js';
import { WEB3_RULES } from './web3.js';
import { OBFUSCATION_RULES } from './obfuscation.js';
import { PROMPT_INJECTION_RULES } from './prompt-injection.js';
import { EXFILTRATION_RULES } from './exfiltration.js';
import { TROJAN_RULES } from './trojan.js';

/**
 * All built-in scan rules
 */
export const ALL_RULES: ScanRule[] = [
  ...SHELL_EXEC_RULES,
  ...REMOTE_LOADER_RULES,
  ...SECRETS_RULES,
  ...WEB3_RULES,
  ...OBFUSCATION_RULES,
  ...PROMPT_INJECTION_RULES,
  ...EXFILTRATION_RULES,
  ...TROJAN_RULES,
];

/**
 * Get rules by severity
 */
export function getRulesBySeverity(severity: 'low' | 'medium' | 'high' | 'critical'): ScanRule[] {
  return ALL_RULES.filter(rule => rule.severity === severity);
}

/**
 * Get rule by ID
 */
export function getRuleById(id: RiskTag): ScanRule | undefined {
  return ALL_RULES.find(rule => rule.id === id);
}

/**
 * Get rules for specific file extension
 */
export function getRulesForExtension(extension: string): ScanRule[] {
  return ALL_RULES.filter(rule => {
    return rule.file_patterns.some(pattern => {
      if (pattern === '*') return true;
      if (pattern.startsWith('*.')) {
        return extension === pattern.slice(1);
      }
      return false;
    });
  });
}
