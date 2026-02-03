import type { ScanRule } from '../../types/scanner.js';

/**
 * Shell execution detection rules
 */
export const SHELL_EXEC_RULES: ScanRule[] = [
  {
    id: 'SHELL_EXEC',
    description: 'Detects command execution capabilities',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.py'],
    patterns: [
      // Node.js
      /require\s*\(\s*['"`]child_process['"`]\s*\)/,
      /from\s+['"`]child_process['"`]/,
      /\bexec\s*\(/,
      /\bexecSync\s*\(/,
      /\bspawn\s*\(/,
      /\bspawnSync\s*\(/,
      /\bexecFile\s*\(/,
      /\bfork\s*\(/,
      // Python
      /\bsubprocess\./,
      /\bos\.system\s*\(/,
      /\bos\.popen\s*\(/,
      /\bos\.exec\w*\s*\(/,
      /\bcommands\.getoutput\s*\(/,
      /\bcommands\.getstatusoutput\s*\(/,
      // Shell scripts
      /\$\(.*\)/,
      /`[^`]*`/,
    ],
  },
  {
    id: 'AUTO_UPDATE',
    description: 'Detects auto-update mechanisms that could execute remote code',
    severity: 'critical',
    file_patterns: ['*.js', '*.ts', '*.py', '*.sh'],
    patterns: [
      // Cron/scheduled execution patterns
      /cron|schedule|interval.*exec|setInterval.*exec/i,
      // Auto-update patterns
      /auto.?update|self.?update/i,
      // Download and execute patterns
      /curl.*\|\s*(bash|sh)|wget.*\|\s*(bash|sh)/,
      /fetch.*then.*eval/,
      /download.*execute/i,
    ],
  },
];
