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

export function isAgentGuardCliCommand(command: string): boolean {
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

  return SUPPORTED_AGENT_COMMANDS.some((command) => matchesCommand(tokens, index, command));
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
