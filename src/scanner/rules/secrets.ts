import type { ScanRule } from '../../types/scanner.js';

/**
 * Secret and sensitive data access detection rules
 */
export const SECRETS_RULES: ScanRule[] = [
  {
    id: 'READ_ENV_SECRETS',
    description: 'Detects access to environment variables',
    severity: 'medium',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.py'],
    patterns: [
      // Node.js
      /process\.env\s*\[/,
      /process\.env\./,
      /require\s*\(\s*['"`]dotenv['"`]\s*\)/,
      /from\s+['"`]dotenv['"`]/,
      // Python
      /os\.environ/,
      /os\.getenv\s*\(/,
      /dotenv\.load_dotenv/,
      /from\s+dotenv\s+import/,
    ],
  },
  {
    id: 'READ_SSH_KEYS',
    description: 'Detects access to SSH keys',
    severity: 'critical',
    file_patterns: ['*'],
    patterns: [
      /~\/\.ssh/,
      /\.ssh\/id_rsa/,
      /\.ssh\/id_ed25519/,
      /\.ssh\/id_ecdsa/,
      /\.ssh\/id_dsa/,
      /\.ssh\/known_hosts/,
      /\.ssh\/authorized_keys/,
      /HOME.*\.ssh/,
      /USERPROFILE.*\.ssh/,
    ],
  },
  {
    id: 'READ_KEYCHAIN',
    description: 'Detects access to system keychains and browser profiles',
    severity: 'critical',
    file_patterns: ['*'],
    patterns: [
      // macOS Keychain
      /keychain/i,
      /security\s+find-/,
      // Chrome/Chromium
      /Chrome.*Local\s+State/i,
      /Chrome.*Login\s+Data/i,
      /Chrome.*Cookies/i,
      /Chromium/i,
      // Firefox
      /Firefox.*logins\.json/i,
      /Firefox.*cookies\.sqlite/i,
      // Windows Credential Manager
      /CredRead/,
      /Windows.*Credentials/i,
      // Generic credential patterns
      /credential.*manager/i,
    ],
  },
];
