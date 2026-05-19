import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
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
  if (agent === 'openclaw') return installOpenClaw(options.cwd, Boolean(options.force));
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

function installOpenClaw(cwd: string | undefined, force: boolean): InstallResult {
  const openClawRoot = cwd
    ? join(cwd, '.openclaw')
    : process.env.OPENCLAW_STATE_DIR || join(homedir(), '.openclaw');
  const pluginDir = join(openClawRoot, 'plugins', 'agentguard');
  const packagePath = join(pluginDir, 'package.json');
  const pluginPath = join(pluginDir, 'index.js');
  const manifestPath = join(pluginDir, 'openclaw.plugin.json');
  const configPath = cwd
    ? join(openClawRoot, 'openclaw.json')
    : process.env.OPENCLAW_CONFIG_PATH || join(openClawRoot, 'openclaw.json');

  writeIfAllowed(packagePath, JSON.stringify(openClawPackageManifest(), null, 2) + '\n', force);
  writeIfAllowed(pluginPath, openClawPluginTemplate(), force);
  writeIfAllowed(manifestPath, JSON.stringify(openClawPluginManifest(), null, 2) + '\n', force);
  enableOpenClawPlugin(configPath, pluginDir);

  return { agent: 'openclaw', files: [packagePath, pluginPath, manifestPath, configPath] };
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
- \`confirm\`: ask for approval in the agent channel before continuing
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
  return `const { registerOpenClawPlugin } = require('@goplus/agentguard');

function register(api) {
  registerOpenClawPlugin(api, {
    skipAutoScan: false,
  });
}

module.exports = Object.defineProperties(register, {
  id: { enumerable: true, value: 'agentguard' },
  name: { enumerable: true, value: 'GoPlus AgentGuard' },
  description: {
    enumerable: true,
    value: 'AI agent security framework - blocks dangerous commands, prevents data leaks, and protects secrets',
  },
  register: { enumerable: true, value: register },
});
`;
}

function openClawPackageManifest(): unknown {
  return {
    name: 'agentguard-openclaw-local',
    private: true,
    type: 'commonjs',
    openclaw: {
      extensions: ['./index.js'],
      runtimeExtensions: ['./index.js'],
    },
  };
}

function openClawPluginManifest(): unknown {
  return {
    id: 'agentguard',
    name: 'GoPlus AgentGuard',
    description: 'AI agent security framework - blocks dangerous commands, prevents data leaks, and protects secrets',
    configSchema: {
      type: 'object',
      properties: {
        level: {
          type: 'string',
          enum: ['strict', 'balanced', 'permissive'],
          default: 'balanced',
          description: 'Protection level: strict (block all risky), balanced (block dangerous, confirm risky), permissive (only block critical)',
        },
      },
    },
  };
}

function enableOpenClawPlugin(configPath: string, pluginDir: string): void {
  let config: Record<string, unknown> = {};
  if (existsSync(configPath)) {
    const raw = readFileSync(configPath, 'utf8').trim();
    config = raw ? JSON.parse(raw) as Record<string, unknown> : {};
  }

  const plugins = ensureRecord(config, 'plugins');
  const load = ensureRecord(plugins, 'load');
  const entries = ensureRecord(plugins, 'entries');
  const agentguard = ensureRecord(entries, 'agentguard');
  agentguard.enabled = true;

  const paths = Array.isArray(load.paths) ? load.paths.filter((p): p is string => typeof p === 'string') : [];
  if (!paths.includes(pluginDir)) {
    paths.push(pluginDir);
  }
  load.paths = paths;

  if (Array.isArray(plugins.allow)) {
    const allow = plugins.allow.filter((id): id is string => typeof id === 'string');
    if (!allow.includes('agentguard')) {
      allow.push('agentguard');
    }
    plugins.allow = allow;
  }

  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');
}

function ensureRecord(parent: Record<string, unknown>, key: string): Record<string, unknown> {
  const existing = parent[key];
  if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
    return existing as Record<string, unknown>;
  }
  const next: Record<string, unknown> = {};
  parent[key] = next;
  return next;
}
