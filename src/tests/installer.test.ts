import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
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

  it('writes Codex skill and hook templates', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-codex-'));
    installAgentTemplates('codex', { cwd: dir });

    assert.ok(existsSync(join(dir, '.codex', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(readFileSync(join(dir, '.codex', 'agentguard-hook.example.json'), 'utf8').includes('AGENTGUARD_AGENT_HOST=codex'));
  });

  it('writes Hermes skill and hook config example', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-hermes-'));
    const result = installAgentTemplates('hermes', { cwd: dir });

    assert.equal(result.agent, 'hermes');
    assert.ok(existsSync(join(dir, '.hermes', 'skills', 'agentguard', 'SKILL.md')));
    assert.ok(readFileSync(join(dir, '.hermes', 'agentguard-hooks.example.yaml'), 'utf8').includes('hermes-hook.js'));
  });

  it('writes QClaw skill template', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-qclaw-'));
    const result = installAgentTemplates('qclaw', { cwd: dir });

    assert.equal(result.agent, 'qclaw');
    assert.ok(existsSync(join(dir, '.qclaw', 'skills', 'agentguard', 'SKILL.md')));
  });

  it('writes and enables OpenClaw plugin template', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-'));
    const result = installAgentTemplates('openclaw', { cwd: dir });

    const pluginDir = join(dir, '.openclaw', 'plugins', 'agentguard');
    const packageJson = JSON.parse(readFileSync(join(pluginDir, 'package.json'), 'utf8'));
    const template = readFileSync(join(pluginDir, 'index.js'), 'utf8');
    const manifest = readFileSync(join(pluginDir, 'openclaw.plugin.json'), 'utf8');
    const config = JSON.parse(readFileSync(join(dir, '.openclaw', 'openclaw.json'), 'utf8'));

    assert.equal(result.files.length, 4);
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
