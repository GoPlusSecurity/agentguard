import type { ActionEvidence } from '../../types/action.js';
import { containsSensitiveData, SENSITIVE_PATTERNS } from '../../utils/patterns.js';

/**
 * Secret leak detection result
 */
export interface SecretLeakResult {
  /** Whether sensitive data was found */
  found: boolean;
  /** Risk level */
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  /** Types of secrets found */
  secret_types: string[];
  /** Evidence */
  evidence: ActionEvidence[];
}

/**
 * Priority of secret types (higher = more critical)
 */
const SECRET_PRIORITY: Record<string, number> = {
  PRIVATE_KEY: 100,
  MNEMONIC: 100,
  SSH_KEY: 90,
  AWS_SECRET: 80,
  AWS_KEY: 70,
  GITHUB_TOKEN: 70,
  BEARER_TOKEN: 60,
  API_SECRET: 50,
  DB_CONNECTION: 50,
  PASSWORD_CONFIG: 40,
};

/**
 * Detect sensitive data in content
 */
export function detectSecretLeak(content: string): SecretLeakResult {
  const detection = containsSensitiveData(content);

  if (!detection.found) {
    return {
      found: false,
      risk_level: 'low',
      secret_types: [],
      evidence: [],
    };
  }

  // Determine risk level based on secret types
  const maxPriority = Math.max(
    ...detection.types.map((t) => SECRET_PRIORITY[t] || 0)
  );

  let riskLevel: 'low' | 'medium' | 'high' | 'critical';
  if (maxPriority >= 90) {
    riskLevel = 'critical';
  } else if (maxPriority >= 70) {
    riskLevel = 'high';
  } else if (maxPriority >= 50) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }

  // Build evidence
  const evidence: ActionEvidence[] = detection.matches.map((m) => ({
    type: 'secret_leak',
    field: 'content',
    match: m.truncated,
    description: `Found ${m.type} pattern`,
  }));

  return {
    found: true,
    risk_level: riskLevel,
    secret_types: detection.types,
    evidence,
  };
}

/**
 * Check if content contains private keys or mnemonics
 * These are always critical and should be blocked
 */
export function containsCriticalSecrets(content: string): boolean {
  SENSITIVE_PATTERNS.PRIVATE_KEY.lastIndex = 0;
  SENSITIVE_PATTERNS.MNEMONIC.lastIndex = 0;
  SENSITIVE_PATTERNS.SSH_KEY.lastIndex = 0;

  return (
    SENSITIVE_PATTERNS.PRIVATE_KEY.test(content) ||
    SENSITIVE_PATTERNS.MNEMONIC.test(content) ||
    SENSITIVE_PATTERNS.SSH_KEY.test(content)
  );
}

/**
 * Get human-readable description of secret type
 */
export function getSecretTypeDescription(type: string): string {
  const descriptions: Record<string, string> = {
    PRIVATE_KEY: 'Ethereum private key',
    MNEMONIC: 'Wallet seed phrase / mnemonic',
    SSH_KEY: 'SSH private key',
    AWS_KEY: 'AWS access key ID',
    AWS_SECRET: 'AWS secret access key',
    GITHUB_TOKEN: 'GitHub personal access token',
    BEARER_TOKEN: 'Bearer/JWT token',
    API_SECRET: 'API secret key',
    DB_CONNECTION: 'Database connection string',
    PASSWORD_CONFIG: 'Password in configuration',
  };

  return descriptions[type] || type;
}
