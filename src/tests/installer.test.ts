import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { installAgentTemplates } from '../installers.js';

describe('Agent template installers', () => {
  it('writes Claude Code hook and settings templates', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-'));
    const result = installAgentTemplates('claude-code', { cwd: dir });

    assert.equal(result.files.length, 2);
    assert.ok(existsSync(join(dir, '.claude', 'hooks', 'agentguard-protect.sh')));
    assert.ok(readFileSync(join(dir, '.claude', 'settings.local.json'), 'utf8').includes('agentguard-protect.sh'));
  });

  it('writes Codex skill and AgentGuard hook config', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-codex-'));
    installAgentTemplates('codex', { cwd: dir });

    assert.ok(existsSync(join(dir, '.codex', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(readFileSync(join(dir, '.codex', 'agentguard-hook.json'), 'utf8').includes('AGENTGUARD_AGENT_HOST=codex'));
  });

  it('installs and enables the native Hermes plugin by default', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-plugin-'));
    const result = installAgentTemplates('hermes', { cwd: dir });
    const pluginDir = join(dir, '.hermes', 'plugins', 'agentguard');
    const configPath = join(dir, '.hermes', 'config.yaml');
    const config = readFileSync(configPath, 'utf8');

    assert.equal(result.agent, 'hermes');
    assert.ok(existsSync(join(pluginDir, 'plugin.yaml')));
    assert.ok(existsSync(join(pluginDir, '__init__.py')));
    assert.ok(existsSync(join(pluginDir, 'bridge.py')));
    assert.ok(readFileSync(join(pluginDir, 'plugin.yaml'), 'utf8').includes('name: agentguard'));
    // Tests are excluded from the bundled copy.
    assert.ok(!existsSync(join(pluginDir, 'tests')));
    assert.ok(result.files.includes(pluginDir));
    assert.ok(result.files.includes(configPath));
    // The bundled skill is still installed for the engine fallback / auto-scan.
    assert.ok(existsSync(join(dir, '.hermes', 'skills', 'agentguard', 'SKILL.md')));
    assert.match(config, /^plugins:\n  enabled:\n    - agentguard\n$/);
    assert.ok(!config.includes('pre_tool_call:'));
  });

  it('preserves existing Hermes native plugin config while enabling AgentGuard', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-plugin-existing-'));
    const configPath = join(dir, '.hermes', 'config.yaml');
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, [
      'theme: dark',
      'plugins:',
      '  enabled:',
      '    - other-plugin',
      '  disabled:',
      '    - old-plugin',
      '',
    ].join('\n'));

    installAgentTemplates('hermes', { cwd: dir });

    const config = readFileSync(configPath, 'utf8');
    assert.ok(config.includes('theme: dark'));
    assert.ok(config.includes('  enabled:\n    - other-plugin\n    - agentguard'));
    assert.ok(config.includes('  disabled:\n    - old-plugin'));
    assert.ok(!config.includes('pre_tool_call:'));
  });

  it('writes Hermes skill and enables hook config with --shell-hooks', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-'));
    const result = installAgentTemplates('hermes', { cwd: dir, shellHooks: true });
    const config = readFileSync(join(dir, '.hermes', 'config.yaml'), 'utf8');

    assert.equal(result.agent, 'hermes');
    assert.ok(existsSync(join(dir, '.hermes', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(readFileSync(join(dir, '.hermes', 'agentguard-hooks.example.yaml'), 'utf8').includes('hermes-hook.js'));
    assert.ok(config.includes('pre_tool_call:'));
    assert.ok(config.includes('hermes-hook.js'));
    assert.ok(config.includes('hooks_auto_accept: false'));
  });

  it('uses HERMES_HOME for explicit Hermes installs without a workspace cwd', () => {
    const hermesHome = mkdtempSync(join(tmpdir(), 'agentguard-hermes-home-'));
    const originalHermesHome = process.env.HERMES_HOME;
    process.env.HERMES_HOME = hermesHome;
    try {
      const result = installAgentTemplates('hermes', { shellHooks: true });
      const config = readFileSync(join(hermesHome, 'config.yaml'), 'utf8');

      assert.equal(result.agent, 'hermes');
      assert.ok(result.files.includes(join(hermesHome, 'config.yaml')));
      assert.ok(existsSync(join(hermesHome, 'skills', 'agentguard', 'SKILL.md')));
      assert.ok(config.includes('hermes-hook.js'));
    } finally {
      if (originalHermesHome === undefined) delete process.env.HERMES_HOME;
      else process.env.HERMES_HOME = originalHermesHome;
    }
  });

  it('merges Hermes hooks into an existing config', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-existing-'));
    const configPath = join(dir, '.hermes', 'config.yaml');
    mkdirSync(join(dir, '.hermes'), { recursive: true });
    writeFileSync(configPath, 'theme: dark\nhooks:\n  custom_event:\n    - command: "echo keep"\n');

    installAgentTemplates('hermes', { cwd: dir, shellHooks: true });

    const config = readFileSync(configPath, 'utf8');
    assert.ok(config.includes('theme: dark'));
    assert.ok(config.includes('custom_event:'));
    assert.ok(config.includes('pre_tool_call:'));
    assert.ok(config.includes('hermes-hook.js'));
  });

  it('enables Hermes hooks in profile configs under ~/.hermes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-profiles-'));
    const rootConfigPath = join(dir, '.hermes', 'config.yaml');
    const profileConfigPath = join(dir, '.hermes', 'profiles', 'agent2', 'config.yaml');
    mkdirSync(dirname(profileConfigPath), { recursive: true });
    mkdirSync(dirname(rootConfigPath), { recursive: true });
    writeFileSync(rootConfigPath, 'theme: dark\n');
    writeFileSync(profileConfigPath, 'profile: agent2\nhooks: {}\n');

    const result = installAgentTemplates('hermes', { cwd: dir, shellHooks: true });

    const rootConfig = readFileSync(rootConfigPath, 'utf8');
    const profileConfig = readFileSync(profileConfigPath, 'utf8');
    assert.ok(result.files.includes(profileConfigPath));
    assert.ok(rootConfig.includes('hermes-hook.js'));
    assert.ok(profileConfig.includes('profile: agent2'));
    assert.ok(profileConfig.includes('pre_tool_call:'));
    assert.ok(profileConfig.includes('hermes-hook.js'));
  });

  it('does not scan unrelated nested Hermes home config files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-nested-home-'));
    const rootConfigPath = join(dir, '.hermes', 'config.yaml');
    const nestedConfigPath = join(dir, '.hermes', 'home', 'project', 'config.yaml');
    mkdirSync(dirname(rootConfigPath), { recursive: true });
    mkdirSync(dirname(nestedConfigPath), { recursive: true });
    writeFileSync(rootConfigPath, 'theme: dark\n');
    writeFileSync(nestedConfigPath, 'project: keep\n');

    const result = installAgentTemplates('hermes', { cwd: dir, shellHooks: true });

    const rootConfig = readFileSync(rootConfigPath, 'utf8');
    const nestedConfig = readFileSync(nestedConfigPath, 'utf8');
    assert.ok(result.files.includes(rootConfigPath));
    assert.ok(!result.files.includes(nestedConfigPath));
    assert.ok(rootConfig.includes('hermes-hook.js'));
    assert.equal(nestedConfig, 'project: keep\n');
  });

  it('updates every top-level Hermes hooks section when duplicate keys exist', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-duplicate-hooks-'));
    const configPath = join(dir, '.hermes', 'config.yaml');
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, [
      'theme: dark',
      'hooks:',
      '  custom_event:',
      '    - command: "echo keep"',
      'model: local',
      'hooks: {}',
      '',
    ].join('\n'));

    installAgentTemplates('hermes', { cwd: dir, shellHooks: true });

    const config = readFileSync(configPath, 'utf8');
    assert.equal((config.match(/^hooks:$/gm) ?? []).length, 2);
    assert.equal((config.match(/^  pre_tool_call:$/gm) ?? []).length, 2);
    assert.ok(config.includes('custom_event:'));
  });

  it('writes QClaw skill template and enables plugin', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-qclaw-'));
    const result = installAgentTemplates('qclaw', { cwd: dir });
    const pluginDir = join(dir, '.qclaw', 'plugins', 'agentguard');
    const packageJson = JSON.parse(readFileSync(join(pluginDir, 'package.json'), 'utf8'));
    const config = JSON.parse(readFileSync(join(dir, '.qclaw', 'qclaw.json'), 'utf8'));

    assert.equal(result.agent, 'qclaw');
    assert.ok(result.files.includes(join(dir, '.qclaw', 'skills', 'agentguard')));
    assert.ok(existsSync(join(dir, '.qclaw', 'skills', 'agentguard', 'SKILL.md')));
    assert.deepEqual(packageJson.qclaw.extensions, ['./index.js']);
    assert.equal(config.plugins.entries.agentguard.enabled, true);
    assert.deepEqual(config.plugins.load.paths, [pluginDir]);
  });

  it('writes OpenClaw skill and enables plugin template', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-'));
    const result = installAgentTemplates('openclaw', { cwd: dir });

    const pluginDir = join(dir, '.openclaw', 'plugins', 'agentguard');
    const packageJson = JSON.parse(readFileSync(join(pluginDir, 'package.json'), 'utf8'));
    const template = readFileSync(join(pluginDir, 'index.js'), 'utf8');
    const manifest = readFileSync(join(pluginDir, 'openclaw.plugin.json'), 'utf8');
    const config = JSON.parse(readFileSync(join(dir, '.openclaw', 'openclaw.json'), 'utf8'));

    assert.equal(result.files.length, 5);
    assert.ok(result.files.includes(join(dir, '.openclaw', 'skills', 'agentguard')));
    assert.ok(existsSync(join(dir, '.openclaw', 'skills', 'agentguard', 'SKILL.md')));
    assert.deepEqual(packageJson.openclaw.extensions, ['./index.js']);
    assert.deepEqual(packageJson.openclaw.runtimeExtensions, ['./index.js']);
    assert.ok(template.includes('registerOpenClawPlugin'));
    assert.ok(template.includes('skipAutoScan: false'));
    assert.ok(template.includes('register: { enumerable: true, value: register }'));
    assert.ok(manifest.includes('"id": "agentguard"'));
    assert.equal(config.plugins.entries.agentguard.enabled, true);
    assert.deepEqual(config.plugins.load.paths, [pluginDir]);
    assert.ok(!template.includes("level: 'balanced'"));
  });

  it('also enables the main OpenClaw config when init runs from workspace state', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-workspace-state-'));
    const mainRoot = join(dir, '.openclaw');
    const workspaceRoot = join(mainRoot, 'workspace', '.openclaw');
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    const previousConfigPath = process.env.OPENCLAW_CONFIG_PATH;

    try {
      process.env.OPENCLAW_STATE_DIR = workspaceRoot;
      delete process.env.OPENCLAW_CONFIG_PATH;

      const result = installAgentTemplates('openclaw');
      const mainPluginDir = join(mainRoot, 'plugins', 'agentguard');
      const workspacePluginDir = join(workspaceRoot, 'plugins', 'agentguard');
      const mainConfig = JSON.parse(readFileSync(join(mainRoot, 'openclaw.json'), 'utf8'));
      const workspaceConfig = JSON.parse(readFileSync(join(workspaceRoot, 'openclaw.json'), 'utf8'));

      assert.ok(result.files.includes(join(mainRoot, 'openclaw.json')));
      assert.ok(existsSync(join(mainRoot, 'skills', 'agentguard', 'SKILL.md')));
      assert.ok(existsSync(join(workspaceRoot, 'skills', 'agentguard', 'SKILL.md')));
      assert.ok(existsSync(join(mainPluginDir, 'openclaw.plugin.json')));
      assert.ok(existsSync(join(workspacePluginDir, 'openclaw.plugin.json')));
      assert.deepEqual(mainConfig.plugins.load.paths, [mainPluginDir]);
      assert.deepEqual(workspaceConfig.plugins.load.paths, [workspacePluginDir]);
      assert.ok(existsSync(join(mainRoot, 'skills', 'agentguard', 'SKILL.md')));
      assert.ok(existsSync(join(workspaceRoot, 'skills', 'agentguard', 'SKILL.md')));
    } finally {
      if (previousStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
      else process.env.OPENCLAW_STATE_DIR = previousStateDir;
      if (previousConfigPath === undefined) delete process.env.OPENCLAW_CONFIG_PATH;
      else process.env.OPENCLAW_CONFIG_PATH = previousConfigPath;
    }
  });

  it('also enables the workspace OpenClaw config when init runs from main state', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-main-state-'));
    const mainRoot = join(dir, '.openclaw');
    const workspace = join(mainRoot, 'workspace');
    const workspaceRoot = join(workspace, '.openclaw');
    const previousStateDir = process.env.OPENCLAW_STATE_DIR;
    const previousConfigPath = process.env.OPENCLAW_CONFIG_PATH;
    mkdirSync(workspace, { recursive: true });
    mkdirSync(mainRoot, { recursive: true });
    writeFileSync(join(mainRoot, 'openclaw.json'), JSON.stringify({
      agents: {
        defaults: {
          workspace,
        },
      },
    }, null, 2));

    try {
      process.env.OPENCLAW_STATE_DIR = mainRoot;
      delete process.env.OPENCLAW_CONFIG_PATH;

      installAgentTemplates('openclaw');
      const mainPluginDir = join(mainRoot, 'plugins', 'agentguard');
      const workspacePluginDir = join(workspaceRoot, 'plugins', 'agentguard');
      const mainConfig = JSON.parse(readFileSync(join(mainRoot, 'openclaw.json'), 'utf8'));
      const workspaceConfig = JSON.parse(readFileSync(join(workspaceRoot, 'openclaw.json'), 'utf8'));

      assert.deepEqual(mainConfig.plugins.load.paths, [mainPluginDir]);
      assert.deepEqual(workspaceConfig.plugins.load.paths, [workspacePluginDir]);
    } finally {
      if (previousStateDir === undefined) delete process.env.OPENCLAW_STATE_DIR;
      else process.env.OPENCLAW_STATE_DIR = previousStateDir;
      if (previousConfigPath === undefined) delete process.env.OPENCLAW_CONFIG_PATH;
      else process.env.OPENCLAW_CONFIG_PATH = previousConfigPath;
    }
  });

  it('adds AgentGuard to an existing OpenClaw plugin allowlist', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-existing-'));
    const configPath = join(dir, '.openclaw', 'openclaw.json');
    mkdirSync(join(dir, '.openclaw'), { recursive: true });
    writeFileSync(configPath, JSON.stringify({ plugins: { allow: ['existing'] } }, null, 2));

    installAgentTemplates('openclaw', { cwd: dir });

    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    assert.deepEqual(config.plugins.allow, ['existing', 'agentguard']);
    assert.equal(config.plugins.entries.agentguard.enabled, true);
  });
});
