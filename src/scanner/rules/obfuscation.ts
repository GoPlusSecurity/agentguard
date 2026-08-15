import type { ScanRule } from '../../types/scanner.js';

/**
 * Code obfuscation detection rules
 */
export const OBFUSCATION_RULES: ScanRule[] = [
  {
    id: 'DYNAMIC_CODE_EXECUTION',
    description: 'Detects eval-like dynamic code execution primitives',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.py'],
    patterns: [
      // JavaScript eval
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /setTimeout\s*\(\s*['"`]/,
      /setInterval\s*\(\s*['"`]/,
      // Python eval/exec
      /(?<!\.)\bexec\s*\(/,
      /\bcompile\s*\([^)]+,\s*['"`]<[^>]+>['"`],\s*['"`]exec['"`]\s*\)/,
    ],
  },
  {
    id: 'OBFUSCATION',
    description: 'Detects strong encoded or packed-code indicators',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.py'],
    patterns: [
      // Base64 decode + execute
      /atob\s*\([^)]+\).*eval/,
      /Buffer\.from\s*\([^,]+,\s*['"`]base64['"`]\s*\).*eval/,
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
