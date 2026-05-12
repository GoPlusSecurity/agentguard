import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export type AgentInstaller = 'claude-code' | 'codex' | 'openclaw';

export interface InstallResult {
  agent: AgentInstaller;
  files: string[];
}

export function installAgentTemplates(agent: AgentInstaller, options: { cwd?: string; force?: boolean } = {}): InstallResult {
  const root = options.cwd || process.cwd();
  if (agent === 'claude-code') return installClaudeCode(root, Boolean(options.force));
  if (agent === 'codex') return installCodex(root, Boolean(options.force));
  if (agent === 'openclaw') return installOpenClaw(root, Boolean(options.force));
  throw new Error(`Unsupported agent installer: ${agent}`);
}

function installClaudeCode(root: string, force: boolean): InstallResult {
  const hookDir = join(root, '.claude', 'hooks');
  const hookPath = join(hookDir, 'agentguard-protect.sh');
  const settingsPath = join(root, '.claude', 'settings.local.json');
  mkdirSync(hookDir, { recursive: true });
  writeIfAllowed(hookPath, claudeHookScript(), force);
  writeIfAllowed(settingsPath, JSON.stringify(claudeSettings(), null, 2) + '\n', force);
  return { agent: 'claude-code', files: [hookPath, settingsPath] };
}

function installCodex(root: string, force: boolean): InstallResult {
  const skillDir = join(root, '.codex', 'skills', 'agentguard');
  const skillPath = join(skillDir, 'SKILL.md');
  const hookPath = join(root, '.codex', 'agentguard-hook.example.json');
  mkdirSync(skillDir, { recursive: true });
  writeIfAllowed(skillPath, codexSkillTemplate(), force);
  writeIfAllowed(hookPath, JSON.stringify(codexHookTemplate(), null, 2) + '\n', force);
  return { agent: 'codex', files: [skillPath, hookPath] };
}

function installOpenClaw(root: string, force: boolean): InstallResult {
  const pluginPath = join(root, 'openclaw.agentguard.plugin.ts');
  writeIfAllowed(pluginPath, openClawPluginTemplate(), force);
  return { agent: 'openclaw', files: [pluginPath] };
}

function writeIfAllowed(path: string, content: string, force: boolean): void {
  if (existsSync(path) && !force) return;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, { mode: path.endsWith('.sh') ? 0o755 : undefined });
}

function claudeHookScript(): string {
  return `#!/bin/sh
set -eu
exec agentguard protect
`;
}

function claudeSettings(): unknown {
  return {
    hooks: {
      PreToolUse: [
        {
          matcher: 'Bash',
          hooks: [
            {
              type: 'command',
              command:
                'AGENTGUARD_AGENT_HOST=claude-code AGENTGUARD_ACTION_TYPE=shell AGENTGUARD_TOOL_NAME=Bash ./.claude/hooks/agentguard-protect.sh',
            },
          ],
        },
        {
          matcher: 'Read',
          hooks: [
            {
              type: 'command',
              command:
                'AGENTGUARD_AGENT_HOST=claude-code AGENTGUARD_ACTION_TYPE=file_read AGENTGUARD_TOOL_NAME=Read ./.claude/hooks/agentguard-protect.sh',
            },
          ],
        },
        {
          matcher: 'Write|Edit|MultiEdit',
          hooks: [
            {
              type: 'command',
              command:
                'AGENTGUARD_AGENT_HOST=claude-code AGENTGUARD_ACTION_TYPE=file_write AGENTGUARD_TOOL_NAME=Write ./.claude/hooks/agentguard-protect.sh',
            },
          ],
        },
        {
          matcher: 'WebFetch|WebSearch',
          hooks: [
            {
              type: 'command',
              command:
                'AGENTGUARD_AGENT_HOST=claude-code AGENTGUARD_ACTION_TYPE=network AGENTGUARD_TOOL_NAME=WebFetch ./.claude/hooks/agentguard-protect.sh',
            },
          ],
        },
      ],
    },
  };
}

function codexSkillTemplate(): string {
  return `# AgentGuard

Use AgentGuard before risky shell, file, network, or MCP tool actions.

\`\`\`bash
printf '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \\
  | AGENTGUARD_AGENT_HOST=codex agentguard protect --json
\`\`\`

Expected decisions:

- \`allow\`: continue
- \`warn\`: show warning and continue
- \`confirm\`: ask for approval before continuing
- \`block\`: stop the action
`;
}

function codexHookTemplate(): unknown {
  return {
    agentHost: 'codex',
    command: 'AGENTGUARD_AGENT_HOST=codex agentguard protect',
    actionTypes: {
      shell: 'shell',
      fileRead: 'file_read',
      fileWrite: 'file_write',
      network: 'network',
      mcpTool: 'mcp_tool',
    },
  };
}

function openClawPluginTemplate(): string {
  return `import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',
    skipAutoScan: false,
  });
}
`;
}
