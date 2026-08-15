import type { ScanRule } from '../../types/scanner.js';

/**
 * Shell execution detection rules
 */
export const SHELL_EXEC_RULES: ScanRule[] = [
  {
    id: 'SHELL_EXEC',
    description: 'Detects command execution capabilities',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.py', '*.md'],
    patterns: [
      // Node.js
      /require\s*\(\s*['"`]child_process['"`]\s*\)/,
      /from\s+['"`]child_process['"`]/,
      /(?<!\.)\bexec\s*\(/,
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
    ],
  },
  {
    id: 'SHELL_EXEC',
    description: 'Detects command substitution in shell scripts and documented shell commands',
    severity: 'high',
    file_patterns: ['*.sh', '*.bash', '*.md'],
    patterns: [/\$\(.*\)/, /`[^`]*`/],
  },
  {
    id: 'AUTO_UPDATE',
    description: 'Detects remote acquisition combined with automatic code installation or execution',
    severity: 'critical',
    file_patterns: ['*.js', '*.ts', '*.py', '*.sh', '*.md'],
    patterns: [
      // Scheduled execution must name an execution sink on the same line.
      /(?:cron|schedule|setInterval)[^\n;]*(?:exec|spawn|eval|import\s*\()/i,
      // Auto-update names require both remote acquisition and a code/file sink.
      /auto.?update|self.?update/i,
      // Download and execute patterns
      /curl.*\|\s*(bash|sh)|wget.*\|\s*(bash|sh)/,
      /fetch.*then.*eval/,
      /download.*execute/i,
    ],
    validator: (content, match) => {
      const remoteAcquisition = /\b(?:fetch|axios|requests\.get|urllib|curl|wget|download)\b/i.test(content);
      if (/(?:cron|schedule|setInterval)/i.test(match[0])) return remoteAcquisition;
      if (!/auto.?update|self.?update/i.test(match[0])) return true;
      const installOrExecute = /\b(?:eval|exec|spawn|execFile|writeFile|rename|chmod|import\s*\(|npm\s+install|pnpm\s+add|pip\s+install)\b/i.test(content);
      return remoteAcquisition && installOrExecute;
    },
  },
];
