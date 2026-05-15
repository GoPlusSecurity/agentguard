import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, mkdtempSync } from 'node:fs';
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

  it('writes OpenClaw plugin template', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-openclaw-'));
    installAgentTemplates('openclaw', { cwd: dir });

    const template = readFileSync(join(dir, 'openclaw.agentguard.plugin.ts'), 'utf8');
    assert.ok(template.includes('registerOpenClawPlugin'));
    assert.ok(!template.includes("level: 'balanced'"));
  });
});
