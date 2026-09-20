import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { installAgentTemplates } from '../installers.js';

describe('Agent template installers', () => {
  it('writes Claude Code hook and settings templates', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-'));
    const result = installAgentTemplates('claude-code', { cwd: dir });

    assert.equal(result.files.length, 3);
    assert.ok(existsSync(join(dir, '.claude', 'hooks', 'agentguard-protect.sh')));
    assert.ok(readFileSync(join(dir, '.claude', 'settings.local.json'), 'utf8').includes('agentguard-protect.sh'));
    assert.ok(existsSync(join(dir, '.claude', 'agentguard-managed.json')));
  });

  it('merges Claude Code lifecycle hooks without replacing user settings and stays idempotent', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-merge-'));
    const claudeDir = join(dir, '.claude');
    const settingsPath = join(claudeDir, 'settings.local.json');
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({
      model: 'keep-model',
      futureSetting: { keep: true },
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: '/usr/local/bin/user-hook' }] }],
        FutureEvent: [{ hooks: [{ type: 'command', command: '/usr/local/bin/future-hook' }] }],
      },
      permissions: { deny: ['Write(/keep/existing.txt)'] },
    }, null, 2));

    installAgentTemplates('claude-code', { cwd: dir, force: true });
    const once = readFileSync(settingsPath, 'utf8');
    installAgentTemplates('claude-code', { cwd: dir, force: true });
    const twice = readFileSync(settingsPath, 'utf8');
    const settings = JSON.parse(twice);

    assert.equal(twice, once);
    assert.equal(settings.model, 'keep-model');
    assert.deepEqual(settings.futureSetting, { keep: true });
    assert.deepEqual(settings.hooks.FutureEvent, [{ hooks: [{ type: 'command', command: '/usr/local/bin/future-hook' }] }]);
    assert.ok(settings.hooks.PreToolUse.some((group: { hooks?: Array<{ command?: string }> }) =>
      group.hooks?.some((hook) => hook.command === '/usr/local/bin/user-hook')));
    assert.ok(settings.permissions.deny.includes('Write(/keep/existing.txt)'));
    assert.deepEqual(Object.keys(settings.hooks).sort(), [
      'ConfigChange', 'FutureEvent', 'InstructionsLoaded', 'MessageDisplay', 'PostCompact', 'PostToolBatch',
      'PostToolUse', 'PostToolUseFailure', 'PreCompact', 'PreToolUse', 'Stop', 'UserPromptExpansion',
      'UserPromptSubmit',
    ].sort());
    for (const [event, groups] of Object.entries(settings.hooks) as Array<[string, Array<{ hooks?: Array<Record<string, unknown>> }>]>) {
      if (event === 'FutureEvent') continue;
      const managed = groups.flatMap((group) => group.hooks || []).filter((hook) =>
        String(hook.command || '').includes('agentguard-protect.sh'));
      assert.equal(managed.length, 1, event);
      assert.equal(managed[0]!.type, 'command', event);
      assert.equal(managed[0]!.timeout, 30, event);
      assert.match(String(managed[0]!.command), /\$\{CLAUDE_PROJECT_DIR\}\/\.claude\/hooks\/agentguard-protect\.sh/, event);
    }
  });

  it('reports absent and unsupported Claude versions as unverified without model-switch hooks', () => {
    const originalPath = process.env.PATH;
    const emptyBin = mkdtempSync(join(tmpdir(), 'agentguard-no-claude-'));
    process.env.PATH = emptyBin;
    try {
      const absent = installAgentTemplates('claude-code', { cwd: mkdtempSync(join(tmpdir(), 'agentguard-claude-absent-')) });
      assert.ok(absent.messages?.some((message) => /unverified/i.test(message)));

      const fake = join(emptyBin, 'claude');
      writeFileSync(fake, '#!/bin/sh\nprintf \'%s\\n\' \'2.1.250 (Claude Code)\'\n');
      chmodSync(fake, 0o755);
      const oldDir = mkdtempSync(join(tmpdir(), 'agentguard-claude-old-'));
      const oldResult = installAgentTemplates('claude-code', { cwd: oldDir });
      const oldSettings = JSON.parse(readFileSync(join(oldDir, '.claude', 'settings.local.json'), 'utf8'));
      assert.equal(oldSettings.hooks.PreModelSwitch, undefined);
      assert.equal(oldSettings.hooks.PostModelSwitch, undefined);
      assert.ok(oldResult.messages?.some((message) => /2\.1\.250/.test(message) && /unsupported/i.test(message)));
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
    }
  });

  it('registers model-switch hooks for Claude Code 2.1.251 and newer', () => {
    const originalPath = process.env.PATH;
    const bin = mkdtempSync(join(tmpdir(), 'agentguard-claude-supported-bin-'));
    const fake = join(bin, 'claude');
    writeFileSync(fake, '#!/bin/sh\nprintf \'%s\\n\' \'2.1.251 (Claude Code)\'\n');
    chmodSync(fake, 0o755);
    process.env.PATH = bin;
    try {
      const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-supported-'));
      const result = installAgentTemplates('claude-code', { cwd: dir });
      const settings = JSON.parse(readFileSync(join(dir, '.claude', 'settings.local.json'), 'utf8'));
      assert.ok(settings.hooks.PreModelSwitch);
      assert.ok(settings.hooks.PostModelSwitch);
      assert.ok(result.messages?.some((message) => /2\.1\.251/.test(message) && /enabled/i.test(message)));
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
    }
  });

  it('adds Read denies only for explicitly supplied exact protected paths', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-protected-paths-'));
    const exact = join(dir, 'private', 'identity.txt');
    installAgentTemplates('claude-code', {
      cwd: dir,
      protectedPaths: [exact, 'private/relative.txt', '**/.env*', join(dir, '**', 'credentials*'), '/tmp/bad)matcher'],
    });

    const settings = JSON.parse(readFileSync(join(dir, '.claude', 'settings.local.json'), 'utf8'));
    assert.deepEqual(settings.permissions.deny, [
      `Read(${exact})`,
      `Read(${join(dir, 'private', 'relative.txt')})`,
    ]);
    assert.ok(!settings.permissions.deny.some((rule: string) => /\*|workspace/i.test(rule)));
  });

  it('replaces only previously owned exact Read denies when protected paths change', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-owned-denies-'));
    const claudeDir = join(dir, '.claude');
    const settingsPath = join(claudeDir, 'settings.local.json');
    const firstPath = join(dir, 'private', 'first.txt');
    const secondPath = join(dir, 'private', 'second.txt');
    const userRead = `Read(${join(dir, 'user-owned.txt')})`;
    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({
      permissions: { deny: [userRead, 'Write(/keep/user-rule)'] },
    }, null, 2));

    const first = installAgentTemplates('claude-code', { cwd: dir, protectedPaths: [firstPath] });
    assert.ok(first.files.includes(join(claudeDir, 'agentguard-managed.json')));
    installAgentTemplates('claude-code', { cwd: dir, protectedPaths: [secondPath] });

    const changed = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.deepEqual(changed.permissions.deny, [
      userRead,
      'Write(/keep/user-rule)',
      `Read(${secondPath})`,
    ]);

    installAgentTemplates('claude-code', { cwd: dir, protectedPaths: [] });
    const removed = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.deepEqual(removed.permissions.deny, [userRead, 'Write(/keep/user-rule)']);
  });

  it('preserves an identical user Read deny when managed ownership is released', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-claude-identical-deny-'));
    const claudeDir = join(dir, '.claude');
    const settingsPath = join(claudeDir, 'settings.local.json');
    const protectedPath = join(dir, 'private', 'identity.txt');
    const identicalRule = `Read(${protectedPath})`;

    installAgentTemplates('claude-code', { cwd: dir, protectedPaths: [protectedPath] });
    const installed = JSON.parse(readFileSync(settingsPath, 'utf8'));
    installed.permissions.deny.push(identicalRule);
    writeFileSync(settingsPath, `${JSON.stringify(installed, null, 2)}\n`);

    installAgentTemplates('claude-code', { cwd: dir, protectedPaths: [] });

    const removed = JSON.parse(readFileSync(settingsPath, 'utf8'));
    assert.deepEqual(removed.permissions.deny, [identicalRule]);
    const managed = JSON.parse(readFileSync(join(claudeDir, 'agentguard-managed.json'), 'utf8'));
    assert.deepEqual(managed.managedReadDenies, []);
  });

  it('writes native synchronous Codex hooks with stable wrapper paths', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-codex-'));
    const result = installAgentTemplates('codex', { cwd: dir });
    const configPath = join(dir, '.codex', 'hooks.json');
    const config = JSON.parse(readFileSync(configPath, 'utf8'));

    assert.ok(existsSync(join(dir, '.codex', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(existsSync(join(dir, '.codex', 'hooks', 'agentguard-user-prompt.sh')));
    assert.ok(existsSync(join(dir, '.codex', 'hooks', 'agentguard-pre-tool.sh')));
    assert.ok(existsSync(join(dir, '.codex', 'hooks', 'agentguard-post-tool.sh')));
    assert.ok(!existsSync(join(dir, '.codex', 'agentguard-hook.json')));
    assert.ok(result.files.includes(configPath));
    assert.deepEqual(Object.keys(config.hooks).sort(), [
      'PermissionRequest', 'PostCompact', 'PostToolUse', 'PreCompact', 'PreToolUse', 'UserPromptSubmit',
    ].sort());
    for (const groups of Object.values(config.hooks) as Array<Array<{ hooks: Array<Record<string, unknown>> }>>) {
      for (const group of groups) {
        for (const hook of group.hooks) {
          assert.equal(hook.type, 'command');
          assert.equal(hook.async, undefined);
          assert.match(String(hook.command), /^"\//);
        }
      }
    }
  });

  it('preserves user Codex hooks, unknown keys, and legacy files while merging idempotently', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-codex-merge-'));
    const codexDir = join(dir, '.codex');
    const configPath = join(codexDir, 'hooks.json');
    const legacyPath = join(codexDir, 'agentguard-hook.json');
    mkdirSync(codexDir, { recursive: true });
    writeFileSync(configPath, JSON.stringify({
      description: 'keep me',
      futureKey: { enabled: true },
      hooks: {
        PreToolUse: [{ matcher: '^Bash$', hooks: [{ type: 'command', command: '/usr/local/bin/user-hook' }] }],
        FutureEvent: [{ future: true }],
      },
    }, null, 2));
    writeFileSync(legacyPath, '{"legacy":"untouched"}\n');

    installAgentTemplates('codex', { cwd: dir, force: true });
    const once = readFileSync(configPath, 'utf8');
    installAgentTemplates('codex', { cwd: dir, force: true });
    const twice = readFileSync(configPath, 'utf8');
    const config = JSON.parse(twice);

    assert.equal(twice, once);
    assert.equal(config.description, 'keep me');
    assert.deepEqual(config.futureKey, { enabled: true });
    assert.deepEqual(config.hooks.FutureEvent, [{ future: true }]);
    assert.ok(config.hooks.PreToolUse.some((group: { hooks?: Array<{ command?: string }> }) =>
      group.hooks?.some((hook) => hook.command === '/usr/local/bin/user-hook')));
    assert.equal(readFileSync(legacyPath, 'utf8'), '{"legacy":"untouched"}\n');
  });

  it('repairs same-command Codex entries with async, wrong-type, or malformed definitions', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-codex-repair-'));
    const codexDir = join(dir, '.codex');
    const configPath = join(codexDir, 'hooks.json');
    const userPromptCommand = JSON.stringify(join(dir, '.codex', 'hooks', 'agentguard-user-prompt.sh'));
    const preToolCommand = JSON.stringify(join(dir, '.codex', 'hooks', 'agentguard-pre-tool.sh'));
    const postToolCommand = JSON.stringify(join(dir, '.codex', 'hooks', 'agentguard-post-tool.sh'));
    mkdirSync(codexDir, { recursive: true });
    writeFileSync(configPath, JSON.stringify({
      hooks: {
        UserPromptSubmit: [{ hooks: { type: 'command', command: userPromptCommand } }],
        PreToolUse: [{ hooks: [{ type: 'prompt', command: preToolCommand, timeout: 30, statusMessage: 'Checking tool action' }] }],
        PostToolUse: [{ hooks: [{ type: 'command', command: postToolCommand, timeout: 30, statusMessage: 'Checking tool result', async: true }] }],
        PermissionRequest: [
          { hooks: [{ type: 'command', command: preToolCommand, timeout: 30, statusMessage: 'Checking approval request' }] },
          { hooks: [{ type: 'command', command: preToolCommand, timeout: 30, statusMessage: 'Checking approval request', async: true }] },
        ],
      },
    }, null, 2));

    installAgentTemplates('codex', { cwd: dir, force: true });
    const config = JSON.parse(readFileSync(configPath, 'utf8')) as {
      hooks: Record<string, Array<{ hooks: Array<Record<string, unknown>> }>>;
    };
    for (const [event, command, statusMessage] of [
      ['UserPromptSubmit', userPromptCommand, 'Checking prompt privacy'],
      ['PreToolUse', preToolCommand, 'Checking tool action'],
      ['PostToolUse', postToolCommand, 'Checking tool result'],
      ['PermissionRequest', preToolCommand, 'Checking approval request'],
    ] as const) {
      assert.equal(config.hooks[event].length, 1, event);
      assert.deepEqual(config.hooks[event][0], {
        hooks: [{ type: 'command', command, timeout: 30, statusMessage }],
      }, event);
    }
  });

  it('repairs an AgentGuard handler in a mixed Codex group without deleting user handlers or metadata', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-codex-mixed-repair-'));
    const codexDir = join(dir, '.codex');
    const configPath = join(codexDir, 'hooks.json');
    const preToolCommand = JSON.stringify(join(dir, '.codex', 'hooks', 'agentguard-pre-tool.sh'));
    const userHook = {
      type: 'command',
      command: '/usr/local/bin/user-pre-tool-hook',
      timeout: 12,
      userOption: 'preserve',
    };
    mkdirSync(codexDir, { recursive: true });
    writeFileSync(configPath, JSON.stringify({
      hooks: {
        PreToolUse: [{
          matcher: '^mcp__',
          futureMetadata: { preserve: true },
          hooks: [
            {
              type: 'prompt',
              command: preToolCommand,
              timeout: 1,
              statusMessage: 'stale',
              async: true,
            },
            userHook,
          ],
        }],
      },
    }, null, 2));

    installAgentTemplates('codex', { cwd: dir, force: true });
    const once = readFileSync(configPath, 'utf8');
    installAgentTemplates('codex', { cwd: dir, force: true });
    const twice = readFileSync(configPath, 'utf8');
    const config = JSON.parse(twice) as {
      hooks: { PreToolUse: Array<Record<string, unknown>> };
    };

    assert.equal(twice, once);
    assert.deepEqual(config.hooks.PreToolUse, [
      {
        matcher: '^mcp__',
        futureMetadata: { preserve: true },
        hooks: [userHook],
      },
      {
        hooks: [{
          type: 'command',
          command: preToolCommand,
          timeout: 30,
          statusMessage: 'Checking tool action',
        }],
      },
    ]);
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
