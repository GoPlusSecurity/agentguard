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

  const wrappedCommand = shellWrapperCommand(tokens, index);
  return wrappedCommand ? isAgentGuardCliCommandInner(wrappedCommand, depth + 1) : false;
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
