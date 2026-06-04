import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ClaudeCodeAdapter } from '../adapters/claude-code.js';
import { OpenClawAdapter } from '../adapters/openclaw.js';
import { HermesAdapter } from '../adapters/hermes.js';
import {
  isSensitivePath,
  shouldDenyAtLevel,
  shouldAskAtLevel,
  isActionAllowedByCapabilities,
} from '../adapters/common.js';

// ─────────────────────────────────────────────────────────────────────────────
// ClaudeCodeAdapter
// ─────────────────────────────────────────────────────────────────────────────

describe('ClaudeCodeAdapter', () => {
  const adapter = new ClaudeCodeAdapter();

  it('should have name "claude-code"', () => {
    assert.equal(adapter.name, 'claude-code');
  });

  describe('parseInput', () => {
    it('should parse PreToolUse event', () => {
      const raw = {
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo hello' },
        session_id: 'sess-1',
        cwd: '/home/user',
      };
      const input = adapter.parseInput(raw);
      assert.equal(input.toolName, 'Bash');
      assert.equal(input.eventType, 'pre');
      assert.deepEqual(input.toolInput, { command: 'echo hello' });
      assert.equal(input.sessionId, 'sess-1');
      assert.equal(input.cwd, '/home/user');
    });

    it('should parse PostToolUse event', () => {
      const raw = {
        hook_event_name: 'PostToolUse',
        tool_name: 'Write',
        tool_input: { file_path: '/tmp/test.txt' },
      };
      const input = adapter.parseInput(raw);
      assert.equal(input.eventType, 'post');
      assert.equal(input.toolName, 'Write');
    });

    it('should handle missing fields gracefully', () => {
      const input = adapter.parseInput({});
      assert.equal(input.toolName, '');
      assert.deepEqual(input.toolInput, {});
      assert.equal(input.eventType, 'pre');
    });
  });

  describe('mapToolToActionType', () => {
    it('should map Bash to exec_command', () => {
      assert.equal(adapter.mapToolToActionType('Bash'), 'exec_command');
    });

    it('should map Write to write_file', () => {
      assert.equal(adapter.mapToolToActionType('Write'), 'write_file');
    });

    it('should map Edit to write_file', () => {
      assert.equal(adapter.mapToolToActionType('Edit'), 'write_file');
    });

    it('should map WebFetch to network_request', () => {
      assert.equal(adapter.mapToolToActionType('WebFetch'), 'network_request');
    });

    it('should map WebSearch to web_search', () => {
      assert.equal(adapter.mapToolToActionType('WebSearch'), 'web_search');
    });

    it('should return null for unknown tools', () => {
      assert.equal(adapter.mapToolToActionType('Read'), null);
      assert.equal(adapter.mapToolToActionType('UnknownTool'), null);
    });
  });

  describe('buildEnvelope', () => {
    it('should build exec_command envelope', () => {
      const input = adapter.parseInput({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'ls -la' },
        session_id: 'sess-1',
        cwd: '/home/user',
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'exec_command');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).command, 'ls -la');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).cwd, '/home/user');
    });

    it('should build write_file envelope', () => {
      const input = adapter.parseInput({
        hook_event_name: 'PreToolUse',
        tool_name: 'Write',
        tool_input: { file_path: '/tmp/test.txt' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'write_file');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).path, '/tmp/test.txt');
    });

    it('should build network_request envelope from WebFetch', () => {
      const input = adapter.parseInput({
        hook_event_name: 'PreToolUse',
        tool_name: 'WebFetch',
        tool_input: { url: 'https://example.com' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'network_request');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).url, 'https://example.com');
    });

    it('should build web_search envelope from WebSearch', () => {
      const input = adapter.parseInput({
        hook_event_name: 'PreToolUse',
        tool_name: 'WebSearch',
        tool_input: { query: 'test query' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'web_search');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).query, 'test query');
    });

    it('should return null for unmapped tools', () => {
      const input = adapter.parseInput({
        hook_event_name: 'PreToolUse',
        tool_name: 'Read',
        tool_input: { file_path: '/tmp/test.txt' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.equal(envelope, null);
    });

    it('should include initiating skill in actor', () => {
      const input = adapter.parseInput({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        tool_input: { command: 'echo hi' },
      });
      const envelope = adapter.buildEnvelope(input, 'my-skill');
      assert.ok(envelope);
      assert.equal(envelope!.actor.skill.id, 'my-skill');
      assert.equal(envelope!.actor.skill.source, 'my-skill');
    });
  });

  describe('inferInitiatingSkill', () => {
    it('should return null when no transcript path', async () => {
      const input = adapter.parseInput({ tool_name: 'Bash', tool_input: {} });
      const skill = await adapter.inferInitiatingSkill(input);
      assert.equal(skill, null);
    });

    it('should return null for non-existent transcript', async () => {
      const input = adapter.parseInput({
        tool_name: 'Bash',
        tool_input: {},
        transcript_path: '/nonexistent/path.jsonl',
      });
      const skill = await adapter.inferInitiatingSkill(input);
      assert.equal(skill, null);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// OpenClawAdapter
// ─────────────────────────────────────────────────────────────────────────────

describe('OpenClawAdapter', () => {
  const adapter = new OpenClawAdapter();

  it('should have name "openclaw"', () => {
    assert.equal(adapter.name, 'openclaw');
  });

  describe('parseInput', () => {
    it('should parse OpenClaw event', () => {
      const event = {
        toolName: 'exec',
        params: { command: 'ls -la' },
        toolCallId: 'call-1',
      };
      const input = adapter.parseInput(event);
      assert.equal(input.toolName, 'exec');
      assert.deepEqual(input.toolInput, { command: 'ls -la' });
      assert.equal(input.eventType, 'pre');
    });

    it('should handle missing params', () => {
      const input = adapter.parseInput({ toolName: 'exec' });
      assert.equal(input.toolName, 'exec');
      assert.deepEqual(input.toolInput, {});
    });

    it('should fall back to args/cmd payloads', () => {
      const input = adapter.parseInput({
        toolName: 'terminal',
        args: { cmd: 'agentguard disconnect' },
      });
      assert.equal(input.toolName, 'terminal');
      assert.deepEqual(input.toolInput, { cmd: 'agentguard disconnect' });
    });

    it('should handle empty event', () => {
      const input = adapter.parseInput({});
      assert.equal(input.toolName, '');
      assert.deepEqual(input.toolInput, {});
    });
  });

  describe('mapToolToActionType', () => {
    it('should map exec to exec_command', () => {
      assert.equal(adapter.mapToolToActionType('exec'), 'exec_command');
    });

    it('should map write to write_file', () => {
      assert.equal(adapter.mapToolToActionType('write'), 'write_file');
    });

    it('should map read to read_file', () => {
      assert.equal(adapter.mapToolToActionType('read'), 'read_file');
    });

    it('should map web_fetch to network_request', () => {
      assert.equal(adapter.mapToolToActionType('web_fetch'), 'network_request');
    });

    it('should map browser to network_request', () => {
      assert.equal(adapter.mapToolToActionType('browser'), 'network_request');
    });

    it('should support prefix matching', () => {
      assert.equal(adapter.mapToolToActionType('exec_python'), 'exec_command');
      assert.equal(adapter.mapToolToActionType('web_fetch_json'), 'network_request');
    });

    it('should return null for unknown tools', () => {
      assert.equal(adapter.mapToolToActionType('unknown'), null);
      assert.equal(adapter.mapToolToActionType('think'), null);
    });
  });

  describe('buildEnvelope', () => {
    it('should build exec_command envelope', () => {
      const input = adapter.parseInput({
        toolName: 'exec',
        params: { command: 'ls -la' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'exec_command');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).command, 'ls -la');
    });

    it('should build write_file envelope', () => {
      const input = adapter.parseInput({
        toolName: 'write',
        params: { path: '/tmp/test.txt' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'write_file');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).path, '/tmp/test.txt');
    });

    it('should build read_file envelope', () => {
      const input = adapter.parseInput({
        toolName: 'read',
        params: { path: '/etc/passwd' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'read_file');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).path, '/etc/passwd');
    });

    it('should build network_request envelope', () => {
      const input = adapter.parseInput({
        toolName: 'web_fetch',
        params: { url: 'https://api.example.com', method: 'POST', body: '{"key":"val"}' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'network_request');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).url, 'https://api.example.com');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).method, 'POST');
    });

    it('should return null for unmapped tools', () => {
      const input = adapter.parseInput({ toolName: 'think', params: {} });
      assert.equal(adapter.buildEnvelope(input), null);
    });

    it('should support file_path alias for write', () => {
      const input = adapter.parseInput({
        toolName: 'write',
        params: { file_path: '/tmp/out.txt' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).path, '/tmp/out.txt');
    });
  });

  describe('inferInitiatingSkill', () => {
    it('should return null (not yet supported)', async () => {
      const input = adapter.parseInput({ toolName: 'exec', params: {} });
      const skill = await adapter.inferInitiatingSkill(input);
      assert.equal(skill, null);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HermesAdapter
// ─────────────────────────────────────────────────────────────────────────────

describe('HermesAdapter', () => {
  const adapter = new HermesAdapter();

  it('should have name "hermes"', () => {
    assert.equal(adapter.name, 'hermes');
  });

  describe('parseInput', () => {
    it('should parse pre_tool_call payload', () => {
      const raw = {
        hook_event_name: 'pre_tool_call',
        tool_name: 'terminal',
        tool_input: { command: 'echo hello' },
        session_id: 'sess-1',
        cwd: '/workspace',
      };
      const input = adapter.parseInput(raw);
      assert.equal(input.toolName, 'terminal');
      assert.equal(input.eventType, 'pre');
      assert.deepEqual(input.toolInput, { command: 'echo hello' });
      assert.equal(input.sessionId, 'sess-1');
      assert.equal(input.cwd, '/workspace');
    });

    it('should parse post_tool_call payload', () => {
      const input = adapter.parseInput({
        hook_event_name: 'post_tool_call',
        tool_name: 'write_file',
        tool_input: { path: '/tmp/test.txt' },
      });
      assert.equal(input.eventType, 'post');
      assert.equal(input.toolName, 'write_file');
    });

    it('should fall back to args for direct plugin-style payloads', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'terminal',
        args: { command: 'pwd' },
      });
      assert.deepEqual(input.toolInput, { command: 'pwd' });
    });
  });

  describe('mapToolToActionType', () => {
    it('should map terminal to exec_command', () => {
      assert.equal(adapter.mapToolToActionType('terminal'), 'exec_command');
    });

    it('should map write tools to write_file', () => {
      assert.equal(adapter.mapToolToActionType('write_file'), 'write_file');
      assert.equal(adapter.mapToolToActionType('patch'), 'write_file');
      assert.equal(adapter.mapToolToActionType('skill_manage'), 'write_file');
    });

    it('should map read_file to read_file', () => {
      assert.equal(adapter.mapToolToActionType('read_file'), 'read_file');
    });

    it('should split search queries from URL-bearing web and browser tools', () => {
      assert.equal(adapter.mapToolToActionType('web_search'), 'web_search');
      assert.equal(adapter.mapToolToActionType('web_extract'), 'network_request');
      assert.equal(adapter.mapToolToActionType('browser_navigate'), 'network_request');
    });

    it('should return null for unknown tools', () => {
      assert.equal(adapter.mapToolToActionType('browser_click'), null);
      assert.equal(adapter.mapToolToActionType('browser_console'), null);
      assert.equal(adapter.mapToolToActionType('todo'), null);
      assert.equal(adapter.mapToolToActionType('unknown'), null);
    });
  });

  describe('buildEnvelope', () => {
    it('should build exec_command envelope', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'terminal',
        tool_input: { command: 'ls -la', workdir: '/repo' },
        session_id: 'sess-1',
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'exec_command');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).command, 'ls -la');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).cwd, '/repo');
      assert.equal(envelope!.context.session_id, 'sess-1');
    });

    it('should build write_file envelope from patch path', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'patch',
        tool_input: { path: '/project/.env' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'write_file');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).path, '/project/.env');
    });

    it('should build read_file envelope', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'read_file',
        tool_input: { path: '/tmp/readme.md' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'read_file');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).path, '/tmp/readme.md');
    });

    it('should build network_request envelope from web_extract URL', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'web_extract',
        tool_input: { url: 'https://example.com/page' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'network_request');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).url, 'https://example.com/page');
    });

    it('should build web_search envelope from web_search query', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'web_search',
        tool_input: { query: 'MiniMax model list' },
      });
      const envelope = adapter.buildEnvelope(input);
      assert.ok(envelope);
      assert.equal(envelope!.action.type, 'web_search');
      assert.equal((envelope!.action.data as unknown as Record<string, unknown>).query, 'MiniMax model list');
    });

    it('should return null for unmapped tools', () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'todo',
        tool_input: {},
      });
      assert.equal(adapter.buildEnvelope(input), null);
    });
  });

  describe('inferInitiatingSkill', () => {
    it('should infer skill from extra metadata when present', async () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'terminal',
        tool_input: { command: 'echo hi' },
        extra: { initiating_skill: 'my-hermes-skill' },
      });
      const skill = await adapter.inferInitiatingSkill(input);
      assert.equal(skill, 'my-hermes-skill');
    });

    it('should return null when Hermes provides no skill metadata', async () => {
      const input = adapter.parseInput({
        hook_event_name: 'pre_tool_call',
        tool_name: 'terminal',
        tool_input: { command: 'echo hi' },
      });
      const skill = await adapter.inferInitiatingSkill(input);
      assert.equal(skill, null);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Common utilities
// ─────────────────────────────────────────────────────────────────────────────

describe('Adapter Common Utilities', () => {
  describe('isSensitivePath', () => {
    it('should detect .env files', () => {
      assert.ok(isSensitivePath('/project/.env'));
      assert.ok(isSensitivePath('/project/.env.local'));
      assert.ok(isSensitivePath('/project/.env.production'));
    });

    it('should detect SSH keys', () => {
      assert.ok(isSensitivePath('/home/user/.ssh/id_rsa'));
      assert.ok(isSensitivePath('/home/user/.ssh/id_ed25519'));
    });

    it('should detect AWS credentials', () => {
      assert.ok(isSensitivePath('/home/user/.aws/credentials'));
      assert.ok(isSensitivePath('/home/user/.aws/config'));
    });

    it('should detect credentials.json', () => {
      assert.ok(isSensitivePath('/project/credentials.json'));
      assert.ok(isSensitivePath('/project/serviceAccountKey.json'));
    });

    it('should detect .npmrc and .netrc', () => {
      assert.ok(isSensitivePath('/home/user/.npmrc'));
      assert.ok(isSensitivePath('/home/user/.netrc'));
    });

    it('should detect .kube/config', () => {
      assert.ok(isSensitivePath('/home/user/.kube/config'));
    });

    it('should allow normal paths', () => {
      assert.ok(!isSensitivePath('/project/src/index.ts'));
      assert.ok(!isSensitivePath('/project/package.json'));
      assert.ok(!isSensitivePath('/project/README.md'));
    });

    it('should handle empty path', () => {
      assert.ok(!isSensitivePath(''));
    });

    it('should normalize Windows paths', () => {
      assert.ok(isSensitivePath('C:\\Users\\user\\.ssh\\id_rsa'));
      assert.ok(isSensitivePath('C:\\project\\.env'));
    });
  });

  describe('shouldDenyAtLevel', () => {
    it('strict: deny on deny', () => {
      assert.ok(shouldDenyAtLevel({ decision: 'deny' }, { level: 'strict' }));
    });

    it('strict: deny on confirm', () => {
      assert.ok(shouldDenyAtLevel({ decision: 'confirm' }, { level: 'strict' }));
    });

    it('strict: allow on allow', () => {
      assert.ok(!shouldDenyAtLevel({ decision: 'allow' }, { level: 'strict' }));
    });

    it('balanced: deny on deny', () => {
      assert.ok(shouldDenyAtLevel({ decision: 'deny' }, { level: 'balanced' }));
    });

    it('balanced: allow on confirm', () => {
      assert.ok(!shouldDenyAtLevel({ decision: 'confirm' }, { level: 'balanced' }));
    });

    it('permissive: deny only on critical deny', () => {
      assert.ok(shouldDenyAtLevel({ decision: 'deny', risk_level: 'critical' }, { level: 'permissive' }));
      assert.ok(!shouldDenyAtLevel({ decision: 'deny', risk_level: 'high' }, { level: 'permissive' }));
    });

    it('defaults to balanced when no level specified', () => {
      assert.ok(shouldDenyAtLevel({ decision: 'deny' }, {}));
      assert.ok(!shouldDenyAtLevel({ decision: 'confirm' }, {}));
    });
  });

  describe('shouldAskAtLevel', () => {
    it('strict: never ask', () => {
      assert.ok(!shouldAskAtLevel({ decision: 'confirm' }, { level: 'strict' }));
      assert.ok(!shouldAskAtLevel({ decision: 'deny' }, { level: 'strict' }));
    });

    it('balanced: ask on confirm', () => {
      assert.ok(shouldAskAtLevel({ decision: 'confirm' }, { level: 'balanced' }));
    });

    it('balanced: no ask on deny', () => {
      assert.ok(!shouldAskAtLevel({ decision: 'deny' }, { level: 'balanced' }));
    });

    it('permissive: ask on non-critical deny', () => {
      assert.ok(shouldAskAtLevel({ decision: 'deny', risk_level: 'high' }, { level: 'permissive' }));
    });

    it('permissive: no ask on critical deny (already denied)', () => {
      assert.ok(!shouldAskAtLevel({ decision: 'deny', risk_level: 'critical' }, { level: 'permissive' }));
    });

    it('permissive: ask on high/critical confirm', () => {
      assert.ok(shouldAskAtLevel({ decision: 'confirm', risk_level: 'high' }, { level: 'permissive' }));
      assert.ok(shouldAskAtLevel({ decision: 'confirm', risk_level: 'critical' }, { level: 'permissive' }));
    });

    it('permissive: no ask on low confirm', () => {
      assert.ok(!shouldAskAtLevel({ decision: 'confirm', risk_level: 'low' }, { level: 'permissive' }));
    });
  });

  describe('isActionAllowedByCapabilities', () => {
    it('should block exec when can_exec is false', () => {
      assert.ok(!isActionAllowedByCapabilities('exec_command', { can_exec: false }));
    });

    it('should allow exec when can_exec is true', () => {
      assert.ok(isActionAllowedByCapabilities('exec_command', { can_exec: true }));
    });

    it('should block network when can_network is false', () => {
      assert.ok(!isActionAllowedByCapabilities('network_request', { can_network: false }));
    });

    it('should block web search when can_network is false', () => {
      assert.ok(!isActionAllowedByCapabilities('web_search', { can_network: false }));
    });

    it('should block write when can_write is false', () => {
      assert.ok(!isActionAllowedByCapabilities('write_file', { can_write: false }));
    });

    it('should block read when can_read is false', () => {
      assert.ok(!isActionAllowedByCapabilities('read_file', { can_read: false }));
    });

    it('should block web3 when can_web3 is false', () => {
      assert.ok(!isActionAllowedByCapabilities('web3_tx', { can_web3: false }));
      assert.ok(!isActionAllowedByCapabilities('web3_sign', { can_web3: false }));
    });

    it('should allow unknown action types by default', () => {
      assert.ok(isActionAllowedByCapabilities('unknown_action', {}));
    });
  });
});
