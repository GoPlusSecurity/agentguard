import { realpathSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

const SUPPORTED_AGENT_COMMANDS = [
  'agentguard',
  'agentguard-mcp',
  'claude',
  'claude-code',
  'codex',
  'openclaw',
  'qclaw',
  'hermes',
  'cursor',
  'cursor-agent',
  'gemini',
  'copilot',
  'gh copilot',
];
const SHELL_CONTROL_RE = /[;&|<>`\n\r\t]|\$\(/;
const SHELL_EXECUTABLES = new Set(['sh', 'bash', 'zsh', 'dash', 'fish']);

export function isAgentGuardCliCommand(command: string): boolean {
  return isAgentGuardCliCommandInner(command, 0);
}

/** Accept a single AgentGuard invocation, including simple shell wrappers.
 * An explicit executable path must resolve to this package's CLI entrypoint;
 * npx must name the official scoped package and a supported public command.
 */
export function isStandaloneAgentGuardCliCommand(command: string): boolean {
  return isStandaloneAgentGuardCliCommandInner(command, 0);
}

/** Recognize the documented installer only for post-tool output sanitization. */
export function isAgentGuardOwnedOutputCommand(command: string): boolean {
  return isStandaloneAgentGuardCliCommand(command) || isOfficialAgentGuardInstallerCommand(command);
}

export function isOfficialAgentGuardInstallerCommand(command: string): boolean {
  return /^curl[ \t]+-fsSL[ \t]+https:\/\/(?:www\.)?agentguard\.one\/install\.sh[ \t]*\|[ \t]*bash$/.test(command.trim());
}

export function isAgentGuardStatusCommand(command: string): boolean {
  const trimmed = command.trim();
  if (!trimmed || /[\r\n]/.test(trimmed)) return false;
  return trimmed.replace(/[ \t]+/g, ' ') === 'agentguard status';
}

function isAgentGuardCliCommandInner(command: string, depth: number): boolean {
  if (depth > 2) return false;
  const trimmed = command.trim();
  if (!trimmed || SHELL_CONTROL_RE.test(trimmed)) return false;

  const tokens = shellTokens(trimmed);
  if (!tokens.length) return false;

  let index = skipAssignments(tokens, 0);
  if (basename(tokens[index]) === 'env') {
    index += 1;
    while (tokens[index]?.startsWith('-')) index += 1;
    index = skipAssignments(tokens, index);
  }

  while (['command', 'builtin'].includes(basename(tokens[index] || ''))) {
    index += 1;
  }

  if (SUPPORTED_AGENT_COMMANDS.some((command) => matchesCommand(tokens, index, command))) {
    return true;
  }
  if (isVerifiedAgentGuardNpxInvocation(tokens, index)) return true;

  const wrappedCommand = shellWrapperCommand(tokens, index);
  return wrappedCommand ? isAgentGuardCliCommandInner(wrappedCommand, depth + 1) : false;
}

function isStandaloneAgentGuardCliCommandInner(command: string, depth: number): boolean {
  if (depth > 2) return false;
  const trimmed = command.trim();
  if (!trimmed || SHELL_CONTROL_RE.test(trimmed)) return false;
  const tokens = shellTokens(trimmed);
  if (!tokens.length) return false;

  let index = skipAssignments(tokens, 0);
  if (basename(tokens[index]) === 'env') {
    index += 1;
    while (tokens[index]?.startsWith('-')) index += 1;
    index = skipAssignments(tokens, index);
  }
  while (['command', 'builtin'].includes(basename(tokens[index] || ''))) index += 1;
  if (isVerifiedAgentGuardExecutable(tokens[index])) return true;
  if (isVerifiedAgentGuardNpxInvocation(tokens, index)) return true;

  const wrappedCommand = shellWrapperCommand(tokens, index);
  return wrappedCommand ? isStandaloneAgentGuardCliCommandInner(wrappedCommand, depth + 1) : false;
}

function isVerifiedAgentGuardNpxInvocation(tokens: string[], start: number): boolean {
  if (tokens[start] !== 'npx'
      || !tokens.slice(0, start).every((token) => token === 'command' || token === 'builtin')) return false;
  let index = start + 1;
  if (tokens[index] === '-y' || tokens[index] === '--yes') index += 1;
  return /^@goplus\/agentguard(?:@(?:\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?|latest|beta))?$/.test(tokens[index] || '')
    && ['init', 'connect', 'disconnect', 'status', 'policy', 'privacy', 'doctor',
      'scan', 'dsh-scan', 'dsh-scan-batch', 'dsh-compare', 'approvals',
      'subscribe', 'checkup'].includes(tokens[index + 1] || '');
}

function isVerifiedAgentGuardExecutable(executable: string | undefined): boolean {
  if (executable === 'agentguard') return true;
  if (!executable || basename(executable) !== 'agentguard' || !isAbsolute(executable)) return false;
  try {
    return realpathSync(executable) === realpathSync(join(__dirname, '..', 'cli.js'));
  } catch {
    return false;
  }
}

function matchesCommand(tokens: string[], start: number, command: string): boolean {
  const expected = command.split(/\s+/);
  if (start + expected.length > tokens.length) return false;
  return expected.every((part, offset) => basename(tokens[start + offset] || '') === part);
}

function skipAssignments(tokens: string[], start: number): number {
  let index = start;
  while (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index] || '')) {
    index += 1;
  }
  return index;
}

function shellWrapperCommand(tokens: string[], start: number): string | null {
  if (!SHELL_EXECUTABLES.has(basename(tokens[start] || ''))) return null;

  for (let index = start + 1; index < tokens.length; index += 1) {
    const token = tokens[index] || '';
    if (!token.startsWith('-') || token === '-') return null;
    if (token.includes('c')) return tokens[index + 1] || null;
  }

  return null;
}

function basename(value: string): string {
  return value.replace(/\\/g, '/').split('/').pop() || value;
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
