import type { ExecCommandData, ActionEvidence } from '../../types/action.js';

/**
 * Command execution analysis result
 */
export interface ExecAnalysisResult {
  /** Risk level */
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  /** Risk tags */
  risk_tags: string[];
  /** Evidence */
  evidence: ActionEvidence[];
  /** Should block */
  should_block: boolean;
  /** Block reason */
  block_reason?: string;
}

/**
 * Safe read-only commands that should be allowed without restriction.
 * Only applied when the command has no shell metacharacters.
 */
const SAFE_COMMAND_PREFIXES = [
  // Basic read-only
  'ls', 'echo', 'pwd', 'whoami', 'date', 'hostname', 'uname',
  'cat', 'head', 'tail', 'wc', 'grep', 'find', 'which', 'type',
  'tree', 'du', 'df', 'sort', 'uniq', 'diff', 'cd',
  // File operations (safe without metacharacters)
  'mkdir', 'cp', 'mv', 'touch',
  // Git (read + common write operations)
  'git status', 'git log', 'git diff', 'git branch', 'git show', 'git remote',
  'git checkout', 'git pull', 'git fetch', 'git merge', 'git add', 'git commit', 'git push',
  // Package managers (run/test/start only — install commands moved to audit list)
  'npm run', 'npm test', 'npm ci', 'npm start',
  'npx', 'yarn', 'pnpm',
  // Version checks
  'node --version', 'node -v', 'npm --version', 'npm -v', 'npx --version',
  'python --version', 'python3 --version', 'pip --version',
  'tsc --version', 'go version', 'rustc --version', 'java -version',
  // Build & run
  'tsc', 'go build', 'go run',
  'cargo build', 'cargo run', 'cargo test',
  'make',
];

/**
 * Commands that are not blocked but should be logged with elevated risk
 * (can execute arbitrary code via postinstall scripts, hooks, or setup.py)
 */
const AUDIT_COMMAND_PREFIXES = [
  'npm install', 'pip install', 'pip3 install', 'git clone',
];

/**
 * Shell metacharacters that disqualify a command from the safe list
 */
const SHELL_METACHAR_PATTERN = /[;|&`$(){}<>!#\n\t]/;

/**
 * Fork bomb patterns (regex-based for variants with spaces)
 */
const FORK_BOMB_PATTERNS = [
  /:\s*\(\s*\)\s*\{.*:\s*\|\s*:.*&.*\}/,    // :(){ :|:& };: and space variants
  /\bfork\s*bomb\b/i,
];

/**
 * Dangerous commands that should always be blocked
 */
const DANGEROUS_COMMANDS = [
  'rm -rf',
  'rm -fr',
  'mkfs',
  'dd if=',
  'chmod 777',
  'chmod -R 777',
  '> /dev/sda',
  'mv /* ',
  'wget.*\\|.*sh',
  'curl.*\\|.*sh',
  'curl.*\\|.*bash',
  'wget.*\\|.*bash',
];

/**
 * Commands that access sensitive data
 */
const SENSITIVE_COMMANDS = [
  'cat /etc/passwd',
  'cat /etc/shadow',
  'cat ~/.ssh',
  'cat ~/.aws',
  'cat ~/.kube',
  'cat ~/.npmrc',
  'cat ~/.netrc',
  'printenv',
  'env',
  'set',
];

/**
 * Commands that modify system state
 */
const SYSTEM_COMMANDS = [
  'sudo',
  'su ',
  'chown',
  'chmod',
  'chgrp',
  'useradd',
  'userdel',
  'groupadd',
  'passwd',
  'visudo',
  'systemctl',
  'service ',
  'init ',
  'shutdown',
  'reboot',
  'halt',
];

/**
 * Network-related commands
 */
const NETWORK_COMMANDS = [
  'curl ',
  'wget ',
  'nc ',
  'netcat',
  'ncat',
  'ssh ',
  'scp ',
  'rsync ',
  'ftp ',
  'sftp ',
];

/**
 * Analyze a command for security risks
 */
export function analyzeExecCommand(
  command: ExecCommandData,
  execAllowed: boolean = false
): ExecAnalysisResult {
  const fullCommand = command.args
    ? `${command.command} ${command.args.join(' ')}`
    : command.command;

  const lowerCommand = fullCommand.toLowerCase();
  const riskTags: string[] = [];
  const evidence: ActionEvidence[] = [];
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  let shouldBlock = !execAllowed; // Block by default if exec not allowed
  let blockReason: string | undefined = execAllowed
    ? undefined
    : 'Command execution not allowed';

  // Check for fork bomb patterns (regex-based)
  for (const pattern of FORK_BOMB_PATTERNS) {
    if (pattern.test(fullCommand)) {
      riskTags.push('DANGEROUS_COMMAND');
      evidence.push({
        type: 'dangerous_command',
        field: 'command',
        match: 'fork bomb',
        description: 'Fork bomb detected',
      });
      riskLevel = 'critical';
      shouldBlock = true;
      blockReason = 'Dangerous command: fork bomb';
      break;
    }
  }

  // Check for dangerous commands
  if (riskLevel !== 'critical') {
    for (const dangerous of DANGEROUS_COMMANDS) {
      if (lowerCommand.includes(dangerous.toLowerCase())) {
        riskTags.push('DANGEROUS_COMMAND');
        evidence.push({
          type: 'dangerous_command',
          field: 'command',
          match: dangerous,
          description: `Dangerous command pattern detected: ${dangerous}`,
        });
        riskLevel = 'critical';
        shouldBlock = true;
        blockReason = `Dangerous command: ${dangerous}`;
        break;
      }
    }
  }

  // Safe command check: if not dangerous, no shell metacharacters, and no sensitive paths, allow
  if (riskLevel !== 'critical' && !SHELL_METACHAR_PATTERN.test(fullCommand)) {
    const hasSensitivePath = SENSITIVE_COMMANDS.some(s => lowerCommand.includes(s.toLowerCase()));
    if (!hasSensitivePath) {
      const isSafe = SAFE_COMMAND_PREFIXES.some(prefix =>
        lowerCommand === prefix || lowerCommand.startsWith(prefix + ' ')
      );
      if (isSafe) {
        return {
          risk_level: 'low',
          risk_tags: [],
          evidence: [],
          should_block: false,
        };
      }

      // Audit commands: allow but flag as medium risk (can run arbitrary code via hooks/scripts)
      const isAudit = AUDIT_COMMAND_PREFIXES.some(prefix =>
        lowerCommand === prefix || lowerCommand.startsWith(prefix + ' ')
      );
      if (isAudit) {
        return {
          risk_level: 'medium',
          risk_tags: ['INSTALL_COMMAND'],
          evidence: [{
            type: 'install_command',
            field: 'command',
            description: 'Package install or clone command can execute arbitrary code via hooks',
          }],
          should_block: false,
        };
      }
    }
  }

  // Check for sensitive data access
  for (const sensitive of SENSITIVE_COMMANDS) {
    if (lowerCommand.includes(sensitive.toLowerCase())) {
      riskTags.push('SENSITIVE_DATA_ACCESS');
      evidence.push({
        type: 'sensitive_access',
        field: 'command',
        match: sensitive,
        description: `Sensitive data access: ${sensitive}`,
      });
      if (riskLevel !== 'critical') riskLevel = 'high';
    }
  }

  // Check for system commands
  for (const sys of SYSTEM_COMMANDS) {
    if (
      lowerCommand.startsWith(sys.toLowerCase()) ||
      lowerCommand.includes(' ' + sys.toLowerCase())
    ) {
      riskTags.push('SYSTEM_COMMAND');
      evidence.push({
        type: 'system_command',
        field: 'command',
        match: sys.trim(),
        description: `System modification command: ${sys.trim()}`,
      });
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }

  // Check for network commands
  for (const net of NETWORK_COMMANDS) {
    if (
      lowerCommand.startsWith(net.toLowerCase()) ||
      lowerCommand.includes(' ' + net.toLowerCase())
    ) {
      riskTags.push('NETWORK_COMMAND');
      evidence.push({
        type: 'network_command',
        field: 'command',
        match: net.trim(),
        description: `Network command: ${net.trim()}`,
      });
      if (riskLevel === 'low') riskLevel = 'medium';
    }
  }

  // Check for shell injection patterns
  const shellInjectionPatterns = [
    /;\s*\w+/,      // ; command
    /\|\s*\w+/,     // | command
    /`[^`]+`/,      // `command`
    /\$\([^)]+\)/,  // $(command)
    /&&\s*\w+/,     // && command
    /\|\|\s*\w+/,   // || command
  ];

  for (const pattern of shellInjectionPatterns) {
    if (pattern.test(fullCommand)) {
      riskTags.push('SHELL_INJECTION_RISK');
      evidence.push({
        type: 'shell_injection',
        field: 'command',
        description: 'Command contains shell metacharacters',
      });
      if (riskLevel === 'low') riskLevel = 'medium';
      break;
    }
  }

  // Check environment variables for secrets
  if (command.env) {
    const sensitiveEnvKeys = [
      'API_KEY',
      'SECRET',
      'PASSWORD',
      'TOKEN',
      'PRIVATE',
      'CREDENTIAL',
    ];

    for (const [key, value] of Object.entries(command.env)) {
      const upperKey = key.toUpperCase();
      if (sensitiveEnvKeys.some((s) => upperKey.includes(s))) {
        riskTags.push('SENSITIVE_ENV_VAR');
        evidence.push({
          type: 'sensitive_env',
          field: 'env',
          match: key,
          description: `Sensitive environment variable: ${key}`,
        });
      }
    }
  }

  return {
    risk_level: riskLevel,
    risk_tags: riskTags,
    evidence,
    should_block: shouldBlock,
    block_reason: blockReason,
  };
}
