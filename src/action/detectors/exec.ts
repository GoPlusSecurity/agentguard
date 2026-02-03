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
 * Dangerous commands that should always be blocked
 */
const DANGEROUS_COMMANDS = [
  'rm -rf',
  'rm -fr',
  'mkfs',
  'dd if=',
  ':(){:|:&};:',  // Fork bomb
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

  // Check for dangerous commands
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
