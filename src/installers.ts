import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

export type AgentInstaller = 'claude-code' | 'codex' | 'openclaw' | 'hermes' | 'qclaw' | 'dsh';

export interface InstallResult {
  agent: AgentInstaller;
  files: string[];
  messages?: string[];
}

interface ClawInstallTarget {
  root: string;
  configPath: string;
}

export function installAgentTemplates(agent: AgentInstaller, options: {
  cwd?: string;
  force?: boolean;
  shellHooks?: boolean;
  /** Exact paths explicitly selected for Claude Code @file Read deny compensation. */
  protectedPaths?: string[];
} = {}): InstallResult {
  const root = options.cwd || process.cwd();
  if (agent === 'claude-code') return installClaudeCode(root, Boolean(options.force), options.protectedPaths ?? []);
  if (agent === 'codex') return installCodex(root, Boolean(options.force));
  if (agent === 'openclaw') return installOpenClaw(options.cwd, Boolean(options.force));
  if (agent === 'hermes') return installHermes(options.cwd, Boolean(options.force), { shellHooks: Boolean(options.shellHooks) });
  if (agent === 'qclaw') return installQClaw(root, Boolean(options.force));
  if (agent === 'dsh') return installDsh(root);
  throw new Error(`Unsupported agent installer: ${agent}`);
}

function installDsh(root: string): InstallResult {
  const args = [
    'plugin', '--profile', 'web', 'add',
    '--allow-build=@goplus/agentguard', '@goplus/agentguard',
  ];
  const result = spawnSync('dsh', args, {
    cwd: root,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (result.error) {
    const code = (result.error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      throw new Error('DSH CLI was not found on PATH. Install or run DSH before initializing AgentGuard for DSH.');
    }
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`DSH plugin installation failed with exit code ${result.status ?? 1}.`);
  }
  return { agent: 'dsh', files: [] };
}

function installClaudeCode(root: string, force: boolean, protectedPaths: string[]): InstallResult {
  const stableRoot = resolve(root);
  const hookDir = join(stableRoot, '.claude', 'hooks');
  const hookPath = join(hookDir, 'agentguard-protect.sh');
  const settingsPath = join(stableRoot, '.claude', 'settings.local.json');
  const managedStatePath = join(stableRoot, '.claude', 'agentguard-managed.json');
  mkdirSync(hookDir, { recursive: true });
  writeIfAllowed(hookPath, claudeHookScript(), force);
  const version = probeClaudeVersion();
  const previousManagedDenies = readClaudeManagedDenies(managedStatePath);
  const managedReadDenies = mergeClaudeSettings(
    settingsPath,
    claudeSettings(version.supportsModelSwitch, protectedPaths, stableRoot),
    previousManagedDenies,
  );
  writeFileSync(managedStatePath, `${JSON.stringify({ version: 1, managedReadDenies }, null, 2)}\n`);
  return {
    agent: 'claude-code',
    files: [hookPath, settingsPath, managedStatePath],
    messages: claudeInstallMessages(version, protectedPaths.filter(isExactClaudeProtectedPath).length),
  };
}

function installCodex(root: string, force: boolean): InstallResult {
  const stableRoot = resolve(root);
  const skillDir = join(stableRoot, '.codex', 'skills', 'agentguard');
  const skillPath = join(skillDir, 'SKILL.md');
  const hookDir = join(stableRoot, '.codex', 'hooks');
  const hooksPath = join(stableRoot, '.codex', 'hooks.json');
  const userPromptPath = join(hookDir, 'agentguard-user-prompt.sh');
  const preToolPath = join(hookDir, 'agentguard-pre-tool.sh');
  const postToolPath = join(hookDir, 'agentguard-post-tool.sh');
  mkdirSync(skillDir, { recursive: true });
  writeIfAllowed(skillPath, codexSkillTemplate(), force);
  writeIfAllowed(userPromptPath, codexHookScript('user-prompt'), force);
  writeIfAllowed(preToolPath, codexHookScript('pre-tool'), force);
  writeIfAllowed(postToolPath, codexHookScript('post-tool'), force);
  mergeCodexHooks(hooksPath, codexHookTemplate({ userPromptPath, preToolPath, postToolPath }));
  return {
    agent: 'codex',
    files: [skillPath, hooksPath, userPromptPath, preToolPath, postToolPath],
    messages: codexInstallMessages(),
  };
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
set -u

input_file="$(mktemp "\${TMPDIR:-/tmp}/agentguard-claude-hook.XXXXXX")" || exit 2
trap 'rm -f "$input_file"' EXIT HUP INT TERM
chmod 600 "$input_file" 2>/dev/null || true
cat >"$input_file"
event="$(node -e 'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{try{const v=JSON.parse(s);if(v&&typeof v.hook_event_name==="string")process.stdout.write(v.hook_event_name)}catch{}})' <"$input_file" 2>/dev/null || true)"

if AGENTGUARD_AGENT_HOST=claude-code AGENTGUARD_CLAUDE_HOOK=1 agentguard protect <"$input_file" 2>/dev/null; then
  exit 0
fi

case "$event" in
  PostToolUseFailure|PostModelSwitch|MessageDisplay|Stop|InstructionsLoaded|PreCompact|PostCompact)
    printf '%s\n' 'SECURITY_GATE_ERROR' >&2
    exit 0
    ;;
esac

printf '%s\n' 'AgentGuard hook evaluation failed; action denied.' >&2
exit 2
`;
}

type ClaudeHookEvent =
  | 'UserPromptSubmit'
  | 'UserPromptExpansion'
  | 'PreToolUse'
  | 'PostToolUse'
  | 'PostToolUseFailure'
  | 'PostToolBatch'
  | 'ConfigChange'
  | 'PreModelSwitch'
  | 'PostModelSwitch'
  | 'MessageDisplay'
  | 'Stop'
  | 'InstructionsLoaded'
  | 'PreCompact'
  | 'PostCompact';

const CLAUDE_BASE_EVENTS: ClaudeHookEvent[] = [
  'UserPromptSubmit', 'UserPromptExpansion', 'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
  'PostToolBatch', 'ConfigChange', 'MessageDisplay', 'Stop', 'InstructionsLoaded', 'PreCompact', 'PostCompact',
];

function claudeSettings(
  supportsModelSwitch: boolean,
  protectedPaths: string[],
  projectRoot: string,
): Record<string, unknown> {
  const command = '"${CLAUDE_PROJECT_DIR}/.claude/hooks/agentguard-protect.sh"';
  const events = supportsModelSwitch
    ? [...CLAUDE_BASE_EVENTS, 'PreModelSwitch', 'PostModelSwitch'] as ClaudeHookEvent[]
    : CLAUDE_BASE_EVENTS;
  const hooks = Object.fromEntries(events.map((event) => [event, [{
    hooks: [{
      type: 'command',
      command,
      timeout: 30,
    }],
  }]]));
  const exactDenies = protectedPaths
    .filter(isExactClaudeProtectedPath)
    .map((path) => path.startsWith('~') || isAbsolute(path) ? path : resolve(projectRoot, path))
    .map((path) => `Read(${path})`);
  return {
    hooks,
    ...(exactDenies.length > 0 ? { permissions: { deny: exactDenies } } : {}),
  };
}

function isExactClaudeProtectedPath(path: string): boolean {
  return path.length > 0 && !/[?*\[\]{}()|]/.test(path) && !/[\r\n]/.test(path);
}

interface ClaudeVersionProbe {
  version?: string;
  supportsModelSwitch: boolean;
  status: 'enabled' | 'unsupported' | 'unverified';
}

function probeClaudeVersion(): ClaudeVersionProbe {
  const result = spawnSync('claude', ['--version'], { encoding: 'utf8' });
  if (result.error || result.status !== 0) return { supportsModelSwitch: false, status: 'unverified' };
  const match = String(result.stdout || result.stderr || '').match(/\b(\d+)\.(\d+)\.(\d+)\b/);
  if (!match) return { supportsModelSwitch: false, status: 'unverified' };
  const version = `${match[1]}.${match[2]}.${match[3]}`;
  const supportsModelSwitch = compareVersions([Number(match[1]), Number(match[2]), Number(match[3])], [2, 1, 251]) >= 0;
  return { version, supportsModelSwitch, status: supportsModelSwitch ? 'enabled' : 'unsupported' };
}

function compareVersions(left: number[], right: number[]): number {
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function claudeInstallMessages(probe: ClaudeVersionProbe, protectedPathCount: number): string[] {
  const enabled = [...CLAUDE_BASE_EVENTS, ...(probe.supportsModelSwitch ? ['PreModelSwitch', 'PostModelSwitch'] : [])];
  const gated = probe.supportsModelSwitch ? [] : ['PreModelSwitch', 'PostModelSwitch'];
  return [
    `Claude Code version: ${probe.version ?? 'not detected'} (${probe.status}).`,
    `Claude Code enabled events: ${enabled.join(', ')}.`,
    `Claude Code gated events: ${gated.length > 0 ? gated.join(', ') : 'none'}.`,
    'Claude Code coverage: prompt/tool/context partial; model transport, final endpoint, credentials, and complete payload unsupported.',
    `Claude Code @file coverage: ${protectedPathCount} exact Read deny path(s) configured; every unconfigured @file path is unsupported.`,
    'Claude Code command-hook timeout/failure behavior is host fail-open; monitor SECURITY_GATE_ERROR and do not treat timeouts as fail-closed.',
  ];
}

function mergeClaudeSettings(
  path: string,
  addition: Record<string, unknown>,
  previousManagedDenies: string[],
): string[] {
  let existing: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
      existing = parsed as Record<string, unknown>;
    } catch {
      throw new Error(`Cannot merge Claude Code settings: ${path} is not a valid JSON object. Existing file was left unchanged.`);
    }
  }
  const currentHooks = existing.hooks;
  if (currentHooks !== undefined && (!currentHooks || typeof currentHooks !== 'object' || Array.isArray(currentHooks))) {
    throw new Error(`Cannot merge Claude Code settings: ${path} has a non-object hooks value. Existing file was left unchanged.`);
  }
  const hooks = { ...((currentHooks || {}) as Record<string, unknown>) };
  const additions = addition.hooks as Record<ClaudeHookEvent, unknown[]>;
  const managedEvents = [...CLAUDE_BASE_EVENTS, 'PreModelSwitch', 'PostModelSwitch'] as ClaudeHookEvent[];
  for (const event of managedEvents) {
    const existingGroups = hooks[event];
    if (existingGroups !== undefined && !Array.isArray(existingGroups)) {
      throw new Error(`Cannot merge Claude Code settings: ${event} is not an array. Existing file was left unchanged.`);
    }
    const groups = ((existingGroups || []) as unknown[]).flatMap(removeClaudeManagedHandlers);
    if (additions[event]) groups.push(...additions[event]);
    if (groups.length > 0) hooks[event] = groups;
    else delete hooks[event];
  }

  const merged: Record<string, unknown> = { ...existing, hooks };
  const newPermissions = addition.permissions as { deny?: string[] } | undefined;
  let managedReadDenies: string[] = [];
  if (newPermissions?.deny?.length || previousManagedDenies.length > 0) {
    const currentPermissions = existing.permissions;
    if (currentPermissions !== undefined && (!currentPermissions || typeof currentPermissions !== 'object' || Array.isArray(currentPermissions))) {
      throw new Error(`Cannot merge Claude Code settings: ${path} has a non-object permissions value. Existing file was left unchanged.`);
    }
    const permissions = { ...((currentPermissions || {}) as Record<string, unknown>) };
    const currentDeny = permissions.deny;
    if (currentDeny !== undefined && !Array.isArray(currentDeny)) {
      throw new Error(`Cannot merge Claude Code settings: ${path} has a non-array permissions.deny value. Existing file was left unchanged.`);
    }
    const denyWithoutManaged = [...(currentDeny || []) as unknown[]];
    for (const rule of previousManagedDenies) {
      const index = denyWithoutManaged.indexOf(rule);
      if (index >= 0) denyWithoutManaged.splice(index, 1);
    }
    managedReadDenies = (newPermissions?.deny ?? []).filter((rule) => !denyWithoutManaged.includes(rule));
    permissions.deny = [...denyWithoutManaged, ...managedReadDenies];
    merged.permissions = permissions;
  }
  const content = `${JSON.stringify(merged, null, 2)}\n`;
  mkdirSync(dirname(path), { recursive: true });
  if (!existsSync(path) || readFileSync(path, 'utf8') !== content) writeFileSync(path, content);
  return managedReadDenies;
}

function readClaudeManagedDenies(path: string): string[] {
  if (!existsSync(path)) return [];
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as { managedReadDenies?: unknown };
    return Array.isArray(parsed.managedReadDenies)
      ? parsed.managedReadDenies.filter((rule): rule is string =>
          typeof rule === 'string' && /^Read\([^\r\n]+\)$/.test(rule))
      : [];
  } catch {
    return [];
  }
}

function removeClaudeManagedHandlers(group: unknown): unknown[] {
  if (!group || typeof group !== 'object' || Array.isArray(group)) return [group];
  const candidate = group as Record<string, unknown>;
  if (!Array.isArray(candidate.hooks)) return [group];
  const hooks = candidate.hooks.filter((hook) => !isClaudeManagedHandler(hook));
  if (hooks.length === 0) return [];
  return [{ ...candidate, hooks }];
}

function isClaudeManagedHandler(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const command = (value as Record<string, unknown>).command;
  return typeof command === 'string' && command.includes('.claude/hooks/agentguard-protect.sh');
}

function codexSkillTemplate(): string {
  return `# AgentGuard

This Skill documents the AgentGuard workflow. It is not a security boundary.
Enforcement comes from the synchronous native hooks in \`.codex/hooks.json\`
after the user reviews and trusts them with \`/hooks\`.

When a hook denies an action that requires approval, show the action id and
redacted reason to the user. The user may approve it from their own terminal
with \`agentguard approve --action-id <id> --once\`, then explicitly retry the
original action. Never run \`agentguard approve\` directly or indirectly,
including through a tool, wrapper, script, or delegated agent. Approval is a
human action performed outside the agent session.
`;
}

type CodexHookEvent =
  | 'UserPromptSubmit'
  | 'PreToolUse'
  | 'PermissionRequest'
  | 'PostToolUse'
  | 'PreCompact'
  | 'PostCompact';

function codexHookTemplate(paths: {
  userPromptPath: string;
  preToolPath: string;
  postToolPath: string;
}): Record<string, unknown> {
  return {
    hooks: {
      UserPromptSubmit: [codexMatcherGroup(paths.userPromptPath, 'Checking prompt privacy')],
      PreToolUse: [codexMatcherGroup(paths.preToolPath, 'Checking tool action')],
      PermissionRequest: [codexMatcherGroup(paths.preToolPath, 'Checking approval request')],
      PostToolUse: [codexMatcherGroup(paths.postToolPath, 'Checking tool result')],
      PreCompact: [codexMatcherGroup(paths.postToolPath, 'Recording compact policy state')],
      PostCompact: [codexMatcherGroup(paths.postToolPath, 'Recording compact policy state')],
    },
  };
}

function codexMatcherGroup(scriptPath: string, statusMessage: string): Record<string, unknown> {
  return {
    hooks: [{
      type: 'command',
      command: JSON.stringify(scriptPath),
      timeout: 30,
      statusMessage,
    }],
  };
}

function codexHookScript(wrapper: 'user-prompt' | 'pre-tool' | 'post-tool'): string {
  return `#!/bin/sh
set -u

if AGENTGUARD_AGENT_HOST=codex AGENTGUARD_CODEX_WRAPPER=${wrapper} agentguard protect 2>/dev/null; then
  exit 0
fi

printf '%s\\n' 'AgentGuard hook evaluation failed; action denied.' >&2
exit 2
`;
}

function mergeCodexHooks(path: string, addition: Record<string, unknown>): void {
  let existing: Record<string, unknown> = {};
  if (existsSync(path)) {
    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object');
      existing = parsed as Record<string, unknown>;
    } catch {
      throw new Error(`Cannot merge Codex hooks: ${path} is not a valid JSON object. Existing file was left unchanged.`);
    }
  }

  const currentHooks = existing.hooks;
  if (currentHooks !== undefined && (!currentHooks || typeof currentHooks !== 'object' || Array.isArray(currentHooks))) {
    throw new Error(`Cannot merge Codex hooks: ${path} has a non-object hooks value. Existing file was left unchanged.`);
  }
  const hooks = { ...((currentHooks || {}) as Record<string, unknown>) };
  const additions = addition.hooks as Record<CodexHookEvent, Array<Record<string, unknown>>>;
  for (const [event, groupsToAdd] of Object.entries(additions)) {
    const existingGroups = hooks[event];
    if (existingGroups !== undefined && !Array.isArray(existingGroups)) {
      throw new Error(`Cannot merge Codex hooks: ${event} is not an array. Existing file was left unchanged.`);
    }
    const groups = [...((existingGroups || []) as unknown[])];
    for (const group of groupsToAdd) {
      const managedIndexes = groups.flatMap((candidate, index) =>
        containsCodexManagedHandler(candidate, group) ? [index] : []
      );
      if (managedIndexes.length === 0) {
        groups.push(group);
        continue;
      }
      const primaryIndex = managedIndexes.find((index) => sameCodexHookGroup(groups[index], group))
        ?? managedIndexes.find((index) => isRepairableCodexHookGroup(groups[index], group));
      for (const index of managedIndexes.reverse()) {
        const repaired = repairCodexManagedHandlers(groups[index], group, index === primaryIndex);
        if (repaired === undefined) groups.splice(index, 1);
        else groups[index] = repaired;
      }
      if (primaryIndex === undefined) groups.push(group);
    }
    hooks[event] = groups;
  }

  const merged = { ...existing, hooks };
  mkdirSync(dirname(path), { recursive: true });
  const content = `${JSON.stringify(merged, null, 2)}\n`;
  if (!existsSync(path) || readFileSync(path, 'utf8') !== content) writeFileSync(path, content);
}

function sameCodexHookGroup(left: unknown, right: Record<string, unknown>): boolean {
  if (!left || typeof left !== 'object' || Array.isArray(left)) return false;
  const candidate = left as Record<string, unknown>;
  const leftHooks = candidate.hooks;
  const rightHooks = right.hooks as Array<Record<string, unknown>>;
  if (Object.keys(candidate).length !== 1 || !Array.isArray(leftHooks) || leftHooks.length !== 1
      || !Array.isArray(rightHooks) || rightHooks.length !== 1) return false;
  const leftHook = leftHooks[0];
  const rightHook = rightHooks[0];
  if (!leftHook || typeof leftHook !== 'object' || Array.isArray(leftHook)) return false;
  const actual = leftHook as Record<string, unknown>;
  return Object.keys(actual).length === Object.keys(rightHook).length
    && actual.type === rightHook.type
    && actual.command === rightHook.command
    && actual.timeout === rightHook.timeout
    && actual.statusMessage === rightHook.statusMessage;
}

function isRepairableCodexHookGroup(left: unknown, right: Record<string, unknown>): boolean {
  if (!left || typeof left !== 'object' || Array.isArray(left)) return false;
  const candidate = left as Record<string, unknown>;
  if (Object.keys(candidate).some((key) => key !== 'hooks')) return false;
  const expectedCommand = ((right.hooks as Array<Record<string, unknown>>)[0] || {}).command;
  const hooks = Array.isArray(candidate.hooks) ? candidate.hooks : [candidate.hooks];
  return hooks.length === 1 && hooks.some((hook) => Boolean(hook) && typeof hook === 'object' && !Array.isArray(hook)
    && (hook as Record<string, unknown>).command === expectedCommand);
}

function containsCodexManagedHandler(left: unknown, right: Record<string, unknown>): boolean {
  if (!left || typeof left !== 'object' || Array.isArray(left)) return false;
  const candidate = left as Record<string, unknown>;
  const expectedCommand = ((right.hooks as Array<Record<string, unknown>>)[0] || {}).command;
  const hooks = Array.isArray(candidate.hooks) ? candidate.hooks : [candidate.hooks];
  return hooks.some((hook) => Boolean(hook) && typeof hook === 'object' && !Array.isArray(hook)
    && (hook as Record<string, unknown>).command === expectedCommand);
}

function repairCodexManagedHandlers(
  left: unknown,
  right: Record<string, unknown>,
  keepManagedHandler: boolean,
): Record<string, unknown> | undefined {
  const candidate = left as Record<string, unknown>;
  const expectedHook = (right.hooks as Array<Record<string, unknown>>)[0];
  const hooks = Array.isArray(candidate.hooks) ? candidate.hooks : [candidate.hooks];
  let keptManagedHandler = false;
  const repairedHooks = hooks.flatMap((hook) => {
    const managed = Boolean(hook) && typeof hook === 'object' && !Array.isArray(hook)
      && (hook as Record<string, unknown>).command === expectedHook.command;
    if (!managed) return [hook];
    if (keepManagedHandler && !keptManagedHandler) {
      keptManagedHandler = true;
      return [expectedHook];
    }
    return [];
  });
  return repairedHooks.length > 0 ? { ...candidate, hooks: repairedHooks } : undefined;
}

function codexInstallMessages(): string[] {
  const minimum = '0.148.0-alpha.15';
  const feature = spawnSync('codex', ['features', 'list'], { encoding: 'utf8' });
  const messages = [
    `Codex ${minimum} or newer with the hooks feature is required.`,
    'Open /hooks in Codex to review and trust the new project hooks; untrusted project hooks are skipped.',
    'Legacy .codex/agentguard-hook.json is not active; an existing file is preserved for migration safety.',
  ];
  if (feature.error || feature.status !== 0) {
    messages.push('Warning: could not run `codex features list`; verify that `hooks` is available before relying on this integration.');
  } else if (!/^\s*hooks\s+\S+\s+true\s*$/m.test(feature.stdout || '')) {
    messages.push('Warning: this Codex installation does not report the `hooks` feature as enabled.');
  }
  return messages;
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
