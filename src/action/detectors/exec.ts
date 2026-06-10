import type { ExecCommandData, ActionEvidence } from '../../types/action.js';
import { classifySystemPathOperation, type SystemPathOperation } from '../../utils/system-paths.js';

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
  // File operations (safe only after protected-path operation checks)
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
 * Shell metacharacters that disqualify a command from the safe list.
 * Runtime policy scores these as low-risk signals so benign commands with
 * metacharacters do not enter an approval flow on this signal alone.
 */
const SHELL_METACHAR_PATTERN = /\$\(|&&|\|\||>>|[|&;^!`%$<>"'*?\\\n\r\t]/;

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
  'mkfs',
  'dd if=',
  'chmod 777',
  'chmod -R 777',
  '> /dev/sda',
  'mv /* ',
];

const DOWNLOAD_AND_EXEC_PATTERNS = [
  /\b(?:curl|wget)\b(?:(?!&&|\|\||;|\n|\r).)*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i,
  /\b(?:bash|sh)\s+<\s*\(\s*(?:curl|wget)\b[^;)\n\r]*\)/i,
  /\beval\s+["']?\$\(\s*(?:curl|wget)\b[^;)\n\r]*\)/i,
];

const HIDDEN_NETWORK_PATTERNS = [
  /\$\(\s*(?:curl|wget|nc|netcat|ncat|ssh|scp|rsync|ftp|sftp)\b[^)]*\)/i,
  /`[^`]*(?:curl|wget|nc|netcat|ncat|ssh|scp|rsync|ftp|sftp)\b[^`]*`/i,
  /\bpython3?\s+-c\s+["'][\s\S]*(?:os\.system|subprocess\.(?:run|popen|call|check_call|check_output)|requests\.|urllib\.)[\s\S]*(?:curl|wget|https?:\/\/)/i,
  /\bnode\s+-e\s+["'][\s\S]*(?:child_process|exec|execfile|spawn|fetch|https?\.request)[\s\S]*(?:curl|wget|https?:\/\/)/i,
  /\bperl\s+-e\s+["'][\s\S]*(?:system|exec|lwp::useragent|http::tiny)[\s\S]*(?:curl|wget|https?:\/\/)/i,
  /\b(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(["'])[\s\S]*(?:curl|wget|nc|netcat|ncat|ssh|scp|rsync|ftp|sftp|https?:\/\/)[\s\S]*\1[\s;&|]+(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})/i,
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

  const pathOperationFindings = analyzePathOperations(fullCommand);
  if (pathOperationFindings.length > 0) {
    for (const finding of pathOperationFindings) {
      riskTags.push(finding.tag);
      evidence.push(finding.evidence);
      if (finding.risk_level === 'critical') {
        riskLevel = 'critical';
        shouldBlock = true;
        blockReason = finding.block_reason;
        continue;
      }
      if (riskLevel === 'low') riskLevel = finding.risk_level;
      shouldBlock = true;
      blockReason = blockReason || finding.block_reason;
    }
  }

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

  if (riskLevel !== 'critical') {
    for (const pattern of DOWNLOAD_AND_EXEC_PATTERNS) {
      if (pattern.test(fullCommand)) {
        riskTags.push('DANGEROUS_COMMAND');
        evidence.push({
          type: 'dangerous_command',
          field: 'command',
          match: 'download-and-execute',
          description: 'Remote download piped or substituted into a shell',
        });
        riskLevel = 'critical';
        shouldBlock = true;
        blockReason = 'Dangerous command: remote download executed by shell';
        break;
      }
    }
  }

  if (riskLevel !== 'critical') {
    for (const pattern of HIDDEN_NETWORK_PATTERNS) {
      if (pattern.test(fullCommand)) {
        riskTags.push('HIDDEN_NETWORK_COMMAND');
        evidence.push({
          type: 'hidden_network_command',
          field: 'command',
          match: 'wrapped-network-command',
          description: 'Network command hidden inside command substitution, interpreter code, or variable expansion',
        });
        riskLevel = 'high';
        shouldBlock = true;
        blockReason = blockReason || 'Hidden network command requires approval';
        break;
      }
    }
  }

  // Safe command check: if not dangerous, no shell metacharacters, and no sensitive paths, allow
  if (riskTags.length === 0 && riskLevel !== 'critical' && !SHELL_METACHAR_PATTERN.test(fullCommand)) {
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

  // Check for shell metacharacters. These are advisory by themselves; combined
  // with dangerous commands or sensitive access, the stronger finding controls.
  if (SHELL_METACHAR_PATTERN.test(fullCommand)) {
    riskTags.push('SHELL_INJECTION_RISK');
    evidence.push({
      type: 'shell_injection',
      field: 'command',
      description: 'Command contains shell metacharacters',
    });
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

interface PathOperationFinding {
  risk_level: 'high' | 'critical';
  tag: 'DANGEROUS_COMMAND' | 'DESTRUCTIVE_FILE_OPERATION' | 'SYSTEM_PATH_MUTATION' | 'SYSTEM_PATH_ACCESS';
  evidence: ActionEvidence;
  block_reason: string;
}

function analyzePathOperations(command: string): PathOperationFinding[] {
  const findings: PathOperationFinding[] = [];

  findings.push(...redirectionFindings(command));

  for (const segment of shellCommandSegments(command)) {
    const tokens = effectiveCommandTokens(shellTokens(segment));
    const commandName = basename(tokens[0] || '');
    findings.push(...teeFindings(tokens));

    if (commandName === 'rm') {
      findings.push(...rmFindings(tokens));
    } else if (commandName === 'mv') {
      findings.push(...pathArgsFindings(tokens, 'move', 1));
    } else if (commandName === 'chmod') {
      findings.push(...pathArgsFindings(tokens, 'chmod', 2));
    } else if (commandName === 'chown' || commandName === 'chgrp') {
      findings.push(...pathArgsFindings(tokens, 'chown', 2));
    } else if (commandName === 'cp') {
      findings.push(...copyFindings(tokens));
    } else if (commandName === 'touch' || commandName === 'mkdir') {
      findings.push(...pathArgsFindings(tokens, 'write', 1));
    }
  }

  return findings;
}

function rmFindings(tokens: string[]): PathOperationFinding[] {
  const args = tokens.slice(1);
  const hasRecursive = args.some((token) => isRmFlag(token, 'r') || isRmFlag(token, 'R'));
  const hasForce = args.some((token) => isRmFlag(token, 'f'));
  const targets = args.filter((token) => !token.startsWith('-'));
  const findings: PathOperationFinding[] = [];

  for (const target of targets) {
    const systemFinding = systemPathFinding(target, 'delete');
    if (systemFinding) findings.push(systemFinding);
  }

  if (hasRecursive && hasForce) {
    const hasCriticalTarget = findings.some((item) => item.risk_level === 'critical');
    if (hasCriticalTarget) {
      findings.push({
        risk_level: 'critical',
        tag: 'DANGEROUS_COMMAND',
        evidence: {
          type: 'dangerous_command',
          field: 'command',
          match: 'rm -rf',
          description: 'Recursive force delete targets a protected system path',
        },
        block_reason: 'Recursive force delete targets a protected system path',
      });
    } else {
      findings.push({
        risk_level: 'high',
        tag: 'DESTRUCTIVE_FILE_OPERATION',
        evidence: {
          type: 'destructive_file_operation',
          field: 'command',
          match: 'rm -rf',
          description: 'Recursive force delete requires approval',
        },
        block_reason: 'Recursive force delete requires approval',
      });
    }
  }

  return findings;
}

function copyFindings(tokens: string[]): PathOperationFinding[] {
  const args = nonFlagArgs(tokens.slice(1));
  const destination = args[args.length - 1];
  return destination ? collectSystemPathFindings([destination], 'write') : [];
}

function pathArgsFindings(tokens: string[], operation: SystemPathOperation, firstPathIndex: number): PathOperationFinding[] {
  const args = nonFlagArgs(tokens.slice(1));
  return collectSystemPathFindings(args.slice(Math.max(0, firstPathIndex - 1)), operation);
}

function redirectionFindings(command: string): PathOperationFinding[] {
  const findings: PathOperationFinding[] = [];
  for (const match of command.matchAll(/(?:\d*|&)(?:>>?|>\|)\s*([^\s"'`]+|"[^"]+"|'[^']+')/g)) {
    const target = match[1];
    const finding = systemPathFinding(target, 'write');
    if (finding) findings.push(finding);
  }
  return findings;
}

function teeFindings(tokens: string[]): PathOperationFinding[] {
  const teeIndex = tokens.findIndex((token) => basename(token) === 'tee');
  if (teeIndex === -1) return [];
  return collectSystemPathFindings(nonFlagArgs(tokens.slice(teeIndex + 1)), 'write');
}

function collectSystemPathFindings(paths: string[], operation: SystemPathOperation): PathOperationFinding[] {
  return paths
    .map((path) => systemPathFinding(path, operation))
    .filter((item): item is PathOperationFinding => item !== null);
}

function systemPathFinding(path: string, operation: SystemPathOperation): PathOperationFinding | null {
  const classification = classifySystemPathOperation(path, operation);
  if (!classification) return null;
  return {
    risk_level: classification.severity,
    tag: classification.decision === 'block' ? 'SYSTEM_PATH_MUTATION' : 'SYSTEM_PATH_ACCESS',
    evidence: {
      type: 'system_path_operation',
      field: 'command',
      match: classification.path,
      description: `${operation} operation targets ${classification.description}`,
    },
    block_reason: classification.decision === 'block'
      ? `System path ${operation} blocked: ${classification.path}`
      : `System path ${operation} requires approval: ${classification.path}`,
  };
}

function isRmFlag(token: string, flag: string): boolean {
  return token.startsWith('-') && token.slice(1).includes(flag);
}

function nonFlagArgs(tokens: string[]): string[] {
  return tokens.filter((token) => token && !token.startsWith('-') && token !== '--');
}

function basename(value: string): string {
  return value.replace(/\\/g, '/').split('/').pop() || value;
}

function effectiveCommandTokens(tokens: string[]): string[] {
  let index = 0;
  while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index] || '')) index += 1;
  if (basename(tokens[index] || '') === 'sudo') {
    index += 1;
    while (tokens[index]?.startsWith('-')) index += 1;
  }
  while (['command', 'builtin'].includes(basename(tokens[index] || ''))) index += 1;
  return tokens.slice(index);
}

function shellCommandSegments(command: string): string[] {
  const segments: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (let index = 0; index < command.length; index += 1) {
    const char = command[index];
    const next = command[index + 1];
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      current += char;
      escaped = true;
      continue;
    }
    if ((char === '"' || char === "'") && !quote) {
      quote = char;
      current += char;
      continue;
    }
    if (char === quote) {
      quote = null;
      current += char;
      continue;
    }
    if (!quote && (char === ';' || char === '\n' || (char === '&' && next === '&') || (char === '|' && next === '|') || char === '|')) {
      if (current.trim()) segments.push(current.trim());
      current = '';
      if ((char === '&' && next === '&') || (char === '|' && next === '|')) index += 1;
      continue;
    }
    current += char;
  }

  if (current.trim()) segments.push(current.trim());
  return segments;
}

function shellTokens(command: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (const char of command) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      escaped = true;
      continue;
    }
    if ((char === '"' || char === "'") && !quote) {
      quote = char;
      continue;
    }
    if (char === quote) {
      quote = null;
      continue;
    }
    if (/\s/.test(char) && !quote) {
      if (current) {
        tokens.push(current);
        current = '';
      }
      continue;
    }
    current += char;
  }

  if (escaped) current += '\\';
  if (current) tokens.push(current);
  return quote ? [] : tokens;
}
