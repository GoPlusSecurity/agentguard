import type { ScanRule } from '../../types/scanner.js';

/**
 * Code obfuscation detection rules
 */
export const OBFUSCATION_RULES: ScanRule[] = [
  {
    id: 'OBFUSCATION',
    description: 'Detects code obfuscation techniques',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.py'],
    patterns: [
      // JavaScript eval
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /setTimeout\s*\(\s*['"`]/,
      /setInterval\s*\(\s*['"`]/,
      // Base64 decode + execute
      /atob\s*\([^)]+\).*eval/,
      /Buffer\.from\s*\([^,]+,\s*['"`]base64['"`]\s*\).*eval/,
      // Python eval/exec
      /\bexec\s*\(/,
      /\beval\s*\(/,
      /\bcompile\s*\([^)]+,\s*['"`]<[^>]+>['"`],\s*['"`]exec['"`]\s*\)/,
      // Hex encoding patterns
      /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}/,
      // Unicode encoding patterns
      /\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){10,}/,
      // Character code obfuscation
      /String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){10,}\s*\)/,
      // Packed JavaScript
      /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/,
    ],
  },
];
