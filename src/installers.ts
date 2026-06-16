import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

export type AgentInstaller = 'claude-code' | 'codex' | 'openclaw' | 'hermes' | 'qclaw';

export interface InstallResult {
  agent: AgentInstaller;
  files: string[];
}

interface ClawInstallTarget {
  root: string;
  configPath: string;
}

export function installAgentTemplates(agent: AgentInstaller, options: { cwd?: string; force?: boolean; shellHooks?: boolean } = {}): InstallResult {
  const root = options.cwd || process.cwd();
  if (agent === 'claude-code') return installClaudeCode(root, Boolean(options.force));
  if (agent === 'codex') return installCodex(root, Boolean(options.force));
  if (agent === 'openclaw') return installOpenClaw(options.cwd, Boolean(options.force));
  if (agent === 'hermes') return installHermes(options.cwd, Boolean(options.force), { shellHooks: Boolean(options.shellHooks) });
  if (agent === 'qclaw') return installQClaw(root, Boolean(options.force));
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
  const hookPath = join(root, '.codex', 'agentguard-hook.json');
  mkdirSync(skillDir, { recursive: true });
  writeIfAllowed(skillPath, codexSkillTemplate(), force);
  writeIfAllowed(hookPath, JSON.stringify(codexHookTemplate(), null, 2) + '\n', force);
  return { agent: 'codex', files: [skillPath, hookPath] };
}

function installOpenClaw(cwd: string | undefined, force: boolean): InstallResult {
  const openClawRoot = cwd
    ? join(cwd, '.openclaw')
    : process.env.OPENCLAW_STATE_DIR || join(homedir(), '.openclaw');
  const configPath = cwd
    ? join(openClawRoot, 'openclaw.json')
    : process.env.OPENCLAW_CONFIG_PATH || join(openClawRoot, 'openclaw.json');

  if (cwd) {
    return installClawPlugin('openclaw', openClawRoot, configPath, force);
  }

  const targets = uniqueClawInstallTargets([
    { root: openClawRoot, configPath },
    ...inferOpenClawCompanionInstallTargets(openClawRoot, configPath),
  ]);
  const files = targets.flatMap((target) =>
    installClawPlugin('openclaw', target.root, target.configPath, force).files
  );

  return { agent: 'openclaw', files: uniqueStrings(files) };
}

function installHermes(cwd: string | undefined, force: boolean, opts: { shellHooks?: boolean } = {}): InstallResult {
  const configuredHome = process.env.HERMES_HOME?.trim();
  const hermesRoot = cwd
    ? join(cwd, '.hermes')
    : configuredHome
      ? (isAbsolute(configuredHome) ? configuredHome : resolve(configuredHome))
      : join(homedir(), '.hermes');
  const skillDir = join(hermesRoot, 'skills', 'agentguard');
  const configExamplePath = join(hermesRoot, 'agentguard-hooks.example.yaml');
  // The bundled skill ships hermes-hook.js + auto-scan.js, which the native
  // plugin reuses (engine fallback, session-start scan) and the shell-hook flow
  // wires directly. The example YAML is a non-invasive reference in both modes.
  copyBundledSkill(skillDir, force);
  writeIfAllowed(configExamplePath, hermesHooksTemplate(skillDir), force);
  const files = [skillDir, configExamplePath];

  if (opts.shellHooks) {
    // Legacy path: merge AgentGuard shell hooks into ~/.hermes/config.yaml.
    const configPaths = findHermesConfigPaths(hermesRoot);
    for (const configPath of configPaths) {
      enableHermesHooks(configPath, skillDir);
    }
    files.push(...configPaths);
  } else {
    // Default path: install and enable the native Hermes plugin.
    const pluginDir = join(hermesRoot, 'plugins', 'agentguard');
    const configPath = join(hermesRoot, 'config.yaml');
    copyBundledHermesPlugin(pluginDir, force);
    enableHermesNativePlugin(configPath);
    files.push(pluginDir, configPath);
  }

  return { agent: 'hermes', files };
}

// Entry-point files Hermes needs to load the plugin (manifest + register()).
const HERMES_PLUGIN_REQUIRED_FILES = ['plugin.yaml', '__init__.py'];

function copyBundledHermesPlugin(targetDir: string, force: boolean): void {
  const sourceDir = resolve(__dirname, '..', 'plugins', 'hermes');
  if (!existsSync(sourceDir)) {
    throw new Error(`Bundled Hermes plugin not found at ${sourceDir}. Reinstall @goplus/agentguard.`);
  }
  if (!(existsSync(targetDir) && !force)) {
    mkdirSync(dirname(targetDir), { recursive: true });
    cpSync(sourceDir, targetDir, {
      recursive: true,
      force,
      filter: (src) => {
        const base = basename(src);
        const skip = base === 'tests' || base === '__pycache__' || base === '.pytest_cache';
        return !skip && !base.endsWith('.pyc');
      },
    });
  }
  // Verify the installed package has the layout Hermes expects, so a broken
  // install fails loudly instead of silently failing to load at runtime.
  for (const required of HERMES_PLUGIN_REQUIRED_FILES) {
    if (!existsSync(join(targetDir, required))) {
      throw new Error(`Hermes plugin install is incomplete: missing ${required} in ${targetDir}.`);
    }
  }
}

function enableHermesNativePlugin(configPath: string): void {
  const existing = existsSync(configPath) ? readFileSync(configPath, 'utf8') : '';
  const next = mergeHermesNativePluginEnabled(existing);
  if (next === existing) return;
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, next);
}

function mergeHermesNativePluginEnabled(existing: string): string {
  const lines = existing.replace(/\s+$/g, '').split(/\r?\n/).filter((line, index, arr) => !(arr.length === 1 && index === 0 && line === ''));
  const merged: string[] = [];
  let sawPlugins = false;

  for (let index = 0; index < lines.length;) {
    if (isTopLevelHermesPluginsLine(lines[index])) {
      sawPlugins = true;
      const pluginsEnd = findNextTopLevelIndex(lines, index + 1);
      merged.push('plugins:');
      merged.push(...enableHermesPluginInPluginsBlock(lines.slice(index + 1, pluginsEnd)));
      index = pluginsEnd;
      continue;
    }
    merged.push(lines[index]);
    index += 1;
  }

  if (!sawPlugins) {
    if (merged.length > 0) merged.push('');
    merged.push('plugins:', '  enabled:', '    - agentguard');
  }

  return `${merged.join('\n').replace(/\s+$/g, '')}\n`;
}

function isTopLevelHermesPluginsLine(line: string): boolean {
  return /^plugins:\s*(?:\{\}\s*)?(?:#.*)?$/.test(line);
}

function enableHermesPluginInPluginsBlock(lines: string[]): string[] {
  const enabledPlugins = uniqueStrings([...readHermesEnabledPlugins(lines), 'agentguard']);
  const kept = removeHermesPluginEnabled(lines);
  return ['  enabled:', ...enabledPlugins.map((plugin) => `    - ${plugin}`), ...kept];
}

function removeHermesPluginEnabled(lines: string[]): string[] {
  const kept: string[] = [];
  for (let index = 0; index < lines.length;) {
    const match = /^  enabled:\s*(?:#.*)?$/.exec(lines[index]);
    if (match) {
      index += 1;
      while (index < lines.length && !/^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(lines[index]) && !/^\S/.test(lines[index])) {
        index += 1;
      }
      continue;
    }

    const inlineList = /^  enabled:\s*\[(.*)\]\s*(?:#.*)?$/.exec(lines[index]);
    if (inlineList) {
      index += 1;
      continue;
    }

    kept.push(lines[index]);
    index += 1;
  }
  return kept;
}

function readHermesEnabledPlugins(lines: string[]): string[] {
  const names: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const inlineList = /^  enabled:\s*\[(.*)\]\s*(?:#.*)?$/.exec(lines[index]);
    if (inlineList) {
      for (const item of inlineList[1].split(',')) {
        const name = parseHermesYamlScalar(item);
        if (name) names.push(name);
      }
      continue;
    }

    if (!/^  enabled:\s*(?:#.*)?$/.test(lines[index])) continue;
    index += 1;
    while (index < lines.length && !/^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(lines[index]) && !/^\S/.test(lines[index])) {
      const item = /^    -\s*(.+?)\s*(?:#.*)?$/.exec(lines[index]);
      const name = item ? parseHermesYamlScalar(item[1]) : '';
      if (name) names.push(name);
      index += 1;
    }
    index -= 1;
  }
  return names;
}

function parseHermesYamlScalar(value: string | undefined): string {
  const trimmed = (value || '').trim();
  if (!trimmed) return '';
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

function installQClaw(root: string, force: boolean): InstallResult {
  const qclawRoot = join(root, '.qclaw');
  const configPath = join(qclawRoot, 'qclaw.json');
  const pluginResult = installClawPlugin('qclaw', qclawRoot, configPath, force);
  return { agent: 'qclaw', files: pluginResult.files };
}

function writeIfAllowed(path: string, content: string, force: boolean): void {
  if (existsSync(path) && !force) return;
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, { mode: path.endsWith('.sh') ? 0o755 : undefined });
}

function copyBundledSkill(targetDir: string, force: boolean): void {
  if (existsSync(targetDir) && !force) return;
  mkdirSync(dirname(targetDir), { recursive: true });
  const sourceDir = resolve(__dirname, '..', 'skills', 'agentguard');
  if (!existsSync(sourceDir)) {
    mkdirSync(targetDir, { recursive: true });
    writeIfAllowed(join(targetDir, 'SKILL.md'), codexSkillTemplate(), force);
    return;
  }
  cpSync(sourceDir, targetDir, { recursive: true, force });
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

When a response includes \`Approve once ... agentguard approve --action-id ... --once\`,
show the exact approval command to the user and ask before running it. Do not
run an approval command proactively or infer approval from context. Treat replies such as
"yes", "approve", "confirm", "continue", "go ahead", "execute", "run it",
"同意", "确认", "批准", "继续", or "执行" as explicit approval for the most
recent protected action only after the user has seen the command and understood
which action is being approved. After approval, run the exact
\`agentguard approve --action-id ... --once\` command and retry the original
action once. If the id is unavailable, inspect \`agentguard approvals list --json\`;
use \`agentguard approve --last --once\` only when there is exactly one relevant
unexpired pending approval. If multiple pending approvals exist, ask the user to
choose a specific action id.
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

function hermesHooksTemplate(skillDir: string): string {
  return `# Copy this block into ~/.hermes/config.yaml.
hooks:
  on_session_start:
    - command: "env AGENTGUARD_AUTO_SCAN=1 node \\"${skillDir}/scripts/auto-scan.js\\""
      timeout: 30

  pre_tool_call:
    - matcher: "terminal|execute_code"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "write_file|patch|skill_manage"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "read_file"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "web_search"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "web_extract|browser_navigate"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10

  post_tool_call:
    - matcher: "terminal|execute_code|write_file|patch|skill_manage|read_file|web_search|web_extract|browser_navigate"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 5

hooks_auto_accept: false
`;
}

function installClawPlugin(agent: 'openclaw' | 'qclaw', root: string, configPath: string, force: boolean): InstallResult {
  const pluginDir = join(root, 'plugins', 'agentguard');
  const skillDir = join(root, 'skills', 'agentguard');
  const packagePath = join(pluginDir, 'package.json');
  const pluginPath = join(pluginDir, 'index.js');
  const manifestPath = join(pluginDir, 'openclaw.plugin.json');

  copyBundledSkill(skillDir, force);
  writeIfAllowed(packagePath, JSON.stringify(openClawPackageManifest(agent), null, 2) + '\n', force);
  writeIfAllowed(pluginPath, openClawPluginTemplate(), force);
  writeIfAllowed(manifestPath, JSON.stringify(openClawPluginManifest(), null, 2) + '\n', force);
  enableClawPlugin(configPath, pluginDir);

  return { agent, files: [skillDir, packagePath, pluginPath, manifestPath, configPath] };
}

function inferOpenClawCompanionInstallTargets(root: string, configPath: string): ClawInstallTarget[] {
  const targets: ClawInstallTarget[] = [];
  const workspaceParent = dirname(root);

  if (basename(root) === '.openclaw' && basename(workspaceParent) === 'workspace') {
    const mainRoot = dirname(workspaceParent);
    targets.push({ root: mainRoot, configPath: join(mainRoot, 'openclaw.json') });
    return targets;
  }

  const workspace = readOpenClawWorkspacePath(configPath, root) || existingOpenClawWorkspacePath(root);
  if (workspace) {
    const workspaceStateRoot = join(workspace, '.openclaw');
    if (workspaceStateRoot !== root) {
      targets.push({ root: workspaceStateRoot, configPath: join(workspaceStateRoot, 'openclaw.json') });
    }
  }

  return targets;
}

function readOpenClawWorkspacePath(configPath: string, root: string): string | undefined {
  if (!existsSync(configPath)) return undefined;
  try {
    const raw = readFileSync(configPath, 'utf8').trim();
    if (!raw) return undefined;
    const config = JSON.parse(raw) as Record<string, unknown>;
    const agents = config.agents;
    if (!agents || typeof agents !== 'object' || Array.isArray(agents)) return undefined;
    const defaults = (agents as Record<string, unknown>).defaults;
    if (!defaults || typeof defaults !== 'object' || Array.isArray(defaults)) return undefined;
    const workspace = (defaults as Record<string, unknown>).workspace;
    if (typeof workspace !== 'string' || workspace.trim() === '') return undefined;
    return resolveOpenClawPath(workspace.trim(), root);
  } catch {
    return undefined;
  }
}

function existingOpenClawWorkspacePath(root: string): string | undefined {
  const workspace = join(root, 'workspace');
  return existsSync(workspace) ? workspace : undefined;
}

function resolveOpenClawPath(path: string, baseDir: string): string {
  if (path === '~') return homedir();
  if (path.startsWith('~/') || path.startsWith('~\\')) {
    return join(homedir(), path.slice(2));
  }
  return isAbsolute(path) ? path : resolve(baseDir, path);
}

function uniqueClawInstallTargets(targets: ClawInstallTarget[]): ClawInstallTarget[] {
  const seen = new Set<string>();
  const unique: ClawInstallTarget[] = [];
  for (const target of targets) {
    const key = `${target.root}\0${target.configPath}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(target);
  }
  return unique;
}

function uniqueStrings(values: string[]): string[] {
  return values.filter((value, index) => values.indexOf(value) === index);
}

function openClawPluginTemplate(): string {
  const packageRoot = resolve(__dirname, '..');
  return `const agentGuardPackageRoot = ${JSON.stringify(packageRoot)};

function loadAgentGuard() {
  try {
    return require('@goplus/agentguard');
  } catch (firstError) {
    try {
      return require(agentGuardPackageRoot);
    } catch (fallbackError) {
      const error = new Error(
        'Unable to load @goplus/agentguard from OpenClaw plugin. ' +
        'Tried package resolution and fallback path: ' + agentGuardPackageRoot
      );
      error.cause = fallbackError;
      throw error;
    }
  }
}

const { registerOpenClawPlugin } = loadAgentGuard();

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

function openClawPackageManifest(agent: 'openclaw' | 'qclaw' = 'openclaw'): unknown {
  const manifest: Record<string, unknown> = {
    name: 'agentguard-openclaw-local',
    private: true,
    type: 'commonjs',
    openclaw: {
      extensions: ['./index.js'],
      runtimeExtensions: ['./index.js'],
    },
  };
  if (agent === 'qclaw') {
    manifest.name = 'agentguard-qclaw-local';
    manifest.qclaw = {
      extensions: ['./index.js'],
      runtimeExtensions: ['./index.js'],
    };
  }
  return manifest;
}

function openClawPluginManifest(): unknown {
  return {
    id: 'agentguard',
    name: 'GoPlus AgentGuard',
    description: 'AI agent security framework - blocks dangerous commands, prevents data leaks, and protects secrets',
    activation: {
      onStartup: true,
      onCapabilities: ['hook'],
    },
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

function enableClawPlugin(configPath: string, pluginDir: string): void {
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

function enableHermesHooks(configPath: string, skillDir: string): void {
  const existing = existsSync(configPath) ? readFileSync(configPath, 'utf8') : '';
  const next = mergeHermesHooks(existing, skillDir);
  if (next === existing) return;
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, next);
}

function mergeHermesHooks(existing: string, skillDir: string): string {
  const lines = existing.replace(/\s+$/g, '').split(/\r?\n/).filter((line, index, arr) => !(arr.length === 1 && index === 0 && line === ''));
  const hooksBlock = hermesHookEventBlock(skillDir).split('\n').filter(Boolean);
  const merged: string[] = [];
  let sawHooks = false;

  for (let index = 0; index < lines.length;) {
    if (isTopLevelHermesHooksLine(lines[index])) {
      sawHooks = true;
      const hooksEnd = findNextTopLevelIndex(lines, index + 1);
      merged.push('hooks:');
      merged.push(...removeHermesManagedEvents(lines.slice(index + 1, hooksEnd)));
      merged.push(...hooksBlock);
      index = hooksEnd;
      continue;
    }
    merged.push(lines[index]);
    index += 1;
  }

  if (!sawHooks) {
    if (merged.length > 0) merged.push('');
    merged.push('hooks:', ...hooksBlock);
  }

  if (!merged.some((line) => /^hooks_auto_accept:\s*/.test(line))) {
    merged.push('', 'hooks_auto_accept: false');
  }

  return `${merged.join('\n').replace(/\s+$/g, '')}\n`;
}

function isTopLevelHermesHooksLine(line: string): boolean {
  return /^hooks:\s*(?:\{\}\s*)?(?:#.*)?$/.test(line);
}

function findHermesConfigPaths(hermesRoot: string): string[] {
  const primary = join(hermesRoot, 'config.yaml');
  const found = new Set<string>([primary]);
  if (!existsSync(hermesRoot)) return [...found];

  const profilesDir = join(hermesRoot, 'profiles');
  if (!existsSync(profilesDir)) return [...found];

  for (const name of readdirSync(profilesDir).sort()) {
    const profileDir = join(profilesDir, name);
    const stat = lstatSync(profileDir);
    if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
    const profileConfigPath = join(profileDir, 'config.yaml');
    if (existsSync(profileConfigPath) && lstatSync(profileConfigPath).isFile()) {
      found.add(profileConfigPath);
    }
  }
  return [...found];
}

function hermesHookEventBlock(skillDir: string): string {
  return `  on_session_start:
    - command: "env AGENTGUARD_AUTO_SCAN=1 node \\"${skillDir}/scripts/auto-scan.js\\""
      timeout: 30

  pre_tool_call:
    - matcher: "terminal|execute_code"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "write_file|patch|skill_manage"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "read_file"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "web_search"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10
    - matcher: "web_extract|browser_navigate"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 10

  post_tool_call:
    - matcher: "terminal|execute_code|write_file|patch|skill_manage|read_file|web_search|web_extract|browser_navigate"
      command: "node \\"${skillDir}/scripts/hermes-hook.js\\""
      timeout: 5`;
}

function removeHermesManagedEvents(lines: string[]): string[] {
  const events = new Set(['on_session_start', 'pre_tool_call', 'post_tool_call']);
  const kept: string[] = [];
  for (let index = 0; index < lines.length;) {
    const match = /^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$/.exec(lines[index]);
    if (match && events.has(match[1])) {
      index += 1;
      while (index < lines.length && !/^  [A-Za-z0-9_-]+:\s*(?:#.*)?$/.test(lines[index]) && !/^\S/.test(lines[index])) {
        index += 1;
      }
      continue;
    }
    kept.push(lines[index]);
    index += 1;
  }
  return kept;
}

function findNextTopLevelIndex(lines: string[], start: number): number {
  for (let index = start; index < lines.length; index += 1) {
    if (/^\S/.test(lines[index]) && !/^#/.test(lines[index])) return index;
  }
  return lines.length;
}

function hermesAutoAcceptLine(lines: string[]): string {
  return lines.some((line) => /^hooks_auto_accept:\s*/.test(line)) ? '' : 'hooks_auto_accept: false';
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
