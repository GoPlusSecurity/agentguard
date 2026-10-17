import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ClaudeCodeAdapter } from '../adapters/claude-code.js';
import { installAgentTemplates } from '../installers.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { exitCodeForDecision, formatProtectResult, protectAction } from '../runtime/protect.js';
import type { AgentGuardConfig } from '../config.js';

describe('Claude Code native lifecycle hooks', () => {
  it('declares staged lifecycle coverage without claiming model transport facts', () => {
    const capabilities = new ClaudeCodeAdapter().capabilities;
    assert.equal(capabilities.userPrompt, 'blocking');
    assert.equal(capabilities.promptExpansion, 'blocking');
    assert.equal(capabilities.preTool, 'blocking');
    assert.equal(capabilities.postTool, 'blocking');
    assert.equal(capabilities.toolOutputRewrite, true);
    assert.equal(capabilities.postToolBatch, 'blocking');
    assert.equal(capabilities.configChange, 'blocking');
    assert.equal(capabilities.modelSwitch, 'blocking');
    assert.equal(capabilities.assistantDisplay, 'rewrite_display_only');
    assert.equal(capabilities.modelRequest, 'none');
    assert.equal(capabilities.modelResponse, 'none');
    assert.equal(capabilities.finalDestination, false);
    assert.equal(capabilities.credentialFacts, false);
    assert.equal(capabilities.exactPayloadBytes, false);
  });

  it('dynamically classifies Bash, PowerShell, file, web, MCP, and unknown tools', () => {
    const adapter = new ClaudeCodeAdapter();
    assert.equal(adapter.mapToolToRuntimeAction('Bash', {}), 'shell');
    assert.equal(adapter.mapToolToRuntimeAction('PowerShell', {}), 'shell');
    assert.equal(adapter.mapToolToRuntimeAction('Read', {}), 'file_read');
    assert.equal(adapter.mapToolToRuntimeAction('Write', {}), 'file_write');
    assert.equal(adapter.mapToolToRuntimeAction('Edit', {}), 'file_write');
    assert.equal(adapter.mapToolToRuntimeAction('WebFetch', {}), 'network');
    assert.equal(adapter.mapToolToRuntimeAction('WebSearch', {}), 'web_search');
    assert.equal(adapter.mapToolToRuntimeAction('mcp__private__lookup', {}), 'mcp_tool');
    assert.equal(adapter.mapToolToRuntimeAction('FutureTool', {}), 'other');
  });

  it('blocks sensitive prompts and untrusted expansions with redacted native responses', async () => {
    const fixture = lifecycleFixture();
    const promptSecret = 'api_key=sk-claude-prompt-secret-1234567890';
    const prompt = await runHook(fixture.config, {
      hook_event_name: 'UserPromptSubmit', session_id: 'sess-prompt', cwd: fixture.root, prompt: promptSecret,
    });
    assert.equal(prompt.output.decision, 'block');
    assert.doesNotMatch(prompt.text, /claude-prompt-secret/);

    const expansionSecret = 'custom-command-argument-secret';
    const expansion = await runHook(fixture.config, {
      hook_event_name: 'UserPromptExpansion', session_id: 'sess-expand', cwd: fixture.root,
      expansion_type: 'command', command_name: 'project:deploy', command_args: expansionSecret,
      command_source: 'project',
    });
    assert.equal(expansion.output.decision, 'block');
    assert.equal(expansion.result.event.lifecycleStage, 'prompt_expansion');
    assert.equal(expansion.result.event.coverageLevel, 'partial');
    assert.ok(expansion.result.event.missingFacts?.includes('complete_payload'));
    assert.doesNotMatch(expansion.text, new RegExp(expansionSecret));

    const audit = readFileSync(fixture.config.auditPath, 'utf8');
    assert.doesNotMatch(audit, /claude-prompt-secret|custom-command-argument-secret/);
  });

  it('keeps raw Claude hook content out of Cloud policy and event requests', async () => {
    const fixture = lifecycleFixture();
    const originalFetch = globalThis.fetch;
    const bodies: string[] = [];
    const policy = getDefaultEffectiveRuntimePolicy();
    globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
      const url = String(input);
      if (typeof init?.body === 'string') bodies.push(init.body);
      if (url.endsWith('/api/v1/policies/effective')) {
        return jsonResponse({ success: true, data: policy });
      }
      if (url.endsWith('/api/v1/actions/evaluate')) {
        return jsonResponse({
          success: true,
          data: {
            actionId: 'act_cloud_claude', decision: 'block', riskScore: 100, riskLevel: 'critical',
            reasons: [{ code: 'PII_EGRESS', severity: 'critical', title: 'raw-cloud-title', description: 'raw-cloud-description' }],
            policyVersion: 'cloud-test',
          },
        });
      }
      if (url.endsWith('/api/v1/events/ingest')) {
        return jsonResponse({ success: true, data: { accepted: 1, rejected: 0 } }, 202);
      }
      return jsonResponse({ success: false }, 404);
    }) as typeof fetch;
    const connected = {
      ...fixture.config,
      cloudUrl: 'https://agentguard.example',
      apiKey: 'ag_live_fixture_key_123456',
    };
    const promptMarker = 'alice-cloud-marker@example.invalid';
    const configMarker = 'sk-cloud-config-marker-1234567890';
    const cwdMarker = 'private-cwd-marker';
    const privateCwd = join(fixture.root, cwdMarker);
    try {
      await runHook(connected, {
        hook_event_name: 'UserPromptSubmit', session_id: 'sess-cloud-prompt', cwd: privateCwd,
        prompt: promptMarker,
      });
      const settingsPath = join(fixture.root, 'cloud-settings.json');
      writeFileSync(settingsPath, `{"forward_headers":{"Authorization":"Bearer ${configMarker}"}}`);
      const result = await protectAction({
        config: connected,
        agentHost: 'claude-code',
        decisionMode: 'cloud',
        rawInput: {
          hook_event_name: 'ConfigChange', session_id: 'sess-cloud-config', cwd: fixture.root,
          source: 'project_settings', file_path: settingsPath,
        },
      });
      assert.ok(result);
      assert.equal(result.decision.decision, 'block');
    } finally {
      globalThis.fetch = originalFetch;
    }
    const remote = bodies.join('\n');
    assert.doesNotMatch(remote, /alice-cloud-marker|cloud-config-marker|private-cwd-marker|raw-cloud-title|raw-cloud-description/);
    assert.match(remote, /LOCAL_ONLY_LLM_CONTENT/);
    assert.doesNotMatch(readFileSync(fixture.config.auditPath, 'utf8'), /private-cwd-marker/);
  });

  it('rewrites only verified PostToolUse output shapes and preserves their structure', async () => {
    const fixture = lifecycleFixture();
    const secret = 'alice@example.invalid';
    const verified = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-post', cwd: fixture.root,
      tool_name: 'Read', tool_input: { file_path: '/workspace/public.txt' },
      tool_response: { content: `owner=${secret}`, total_lines: 1 },
    });
    assert.equal(verified.output.hookSpecificOutput.hookEventName, 'PostToolUse');
    assert.deepEqual(Object.keys(verified.output.hookSpecificOutput.updatedToolOutput).sort(), ['content', 'total_lines']);
    assert.doesNotMatch(JSON.stringify(verified.output), new RegExp(secret.replace('.', '\\.')));

    const unknown = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-unknown', cwd: fixture.root,
      tool_name: 'FutureTool', tool_input: {}, tool_response: { opaque: `owner=${secret}` },
    });
    assert.equal(unknown.output.hookSpecificOutput?.updatedToolOutput, undefined);
    assert.equal(unknown.result.event.coverageLevel, 'partial');
    assert.equal(unknown.result.event.enforcementStatus, 'would_block');
    assert.doesNotMatch(readFileSync(fixture.config.auditPath, 'utf8'), new RegExp(secret.replace('.', '\\.')));
  });

  it('does not rescan agentguard status results in PostToolUse or PostToolUseFailure', async () => {
    const fixture = lifecycleFixture();
    const statusOutput = 'API key: ag_live_st…3456\nAgent JWT: configured';
    for (const event of ['PostToolUse', 'PostToolUseFailure'] as const) {
      const result = await protectAction({
        config: fixture.config,
        agentHost: 'claude-code',
        auditSafe: true,
        rawInput: {
          hook_event_name: event,
          session_id: `sess-status-${event}`,
          cwd: fixture.root,
          tool_name: 'Bash',
          tool_input: { command: 'agentguard status' },
          ...(event === 'PostToolUse'
            ? { tool_response: { stdout: statusOutput, exit_code: 0 } }
            : { error: statusOutput }),
        },
      });
      assert.equal(result, null, event);
    }
    assert.equal(existsSync(fixture.config.auditPath), false);
  });

  it('allows only the configured activation link in native status and batch results', async () => {
    const fixture = lifecycleFixture();
    const activationUrl = 'https://agentguard.example/activate?token=pending-claude-link-123456';
    fixture.config.agentJwt = 'test.jwt.pending';
    fixture.config.agentRegisterUrl = activationUrl;
    const statusOutput = `Agent activation URL: ${activationUrl}\nAPI key: not used for this connection`;
    const statusCall = {
      tool_name: 'Bash', tool_input: { command: 'agentguard status' },
      tool_response: { stdout: statusOutput, exit_code: 0 },
    };
    const post = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolUse', session_id: 'sess-pending-status', cwd: fixture.root,
        ...statusCall,
      },
    });
    assert.equal(post, null);
    const punctuated = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-punctuated-link', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard connect' },
      tool_response: { stdout: `Open (${activationUrl}).\napi_key=sk-other-secret-1234567890`, exit_code: 0 },
    });
    assert.equal(punctuated.result.decision.decision, 'allow');
    assert.match(punctuated.output.hookSpecificOutput.updatedToolOutput.stdout, /Open \(https:/);
    assert.ok(punctuated.output.hookSpecificOutput.updatedToolOutput.stdout.includes(`(${activationUrl}).`));
    assert.doesNotMatch(punctuated.text, /other-secret/);

    const structuredLink = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-structured-link', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard connect' },
      tool_response: { agentRegisterUrl: activationUrl, stderr: 'api_key=sk-field-secret-1234567890', exit_code: 0 },
    });
    assert.equal(structuredLink.result.decision.decision, 'allow');
    assert.equal(structuredLink.output.hookSpecificOutput.updatedToolOutput.agentRegisterUrl, activationUrl);
    assert.doesNotMatch(structuredLink.text, /field-secret/);

    const encodedLink = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-encoded-link', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard connect' },
      tool_response: { stdout: encodeURIComponent(activationUrl), exit_code: 0 },
    });
    assert.equal(encodedLink.result.decision.decision, 'block');
    assert.equal(encodedLink.output.hookSpecificOutput, undefined);
    assert.doesNotMatch(encodedLink.text, /pending-claude-link/);

    const batch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-pending-batch', cwd: fixture.root,
        tool_calls: [statusCall],
      },
    });
    assert.equal(batch, null);
    assert.equal(existsSync(fixture.config.auditPath), false);

    const forgedBatch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-forged-batch', cwd: fixture.root,
        tool_calls: [{ ...statusCall, tool_response: { stdout: statusOutput.replace(activationUrl, `${activationUrl}-forged`), exit_code: 0 } }],
      },
    });
    assert.equal(forgedBatch?.decision.decision, 'block',
      'the batch must catch a result that was not rewritten before model use');
    const unknownBatch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-unknown-batch', cwd: fixture.root,
        tool_calls: [{ ...statusCall, tool_response: {
          stdout: 'healthy', card: 5284917302468138, exit_code: 0,
        } }],
      },
    });
    assert.equal(unknownBatch?.decision.decision, 'block');
    const failedBatch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-failed-batch', cwd: fixture.root,
        tool_calls: [{ tool_name: 'Bash', tool_input: { command: 'agentguard status' },
          error: 'api_key=sk-failed-batch-secret-1234567890' }],
      },
    });
    assert.equal(failedBatch?.decision.decision, 'block');
    const forgedPost = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-forged-post', cwd: fixture.root,
      ...statusCall, tool_response: { stdout: statusOutput.replace(activationUrl, `${activationUrl}-forged`), exit_code: 0 },
    });
    assert.equal(forgedPost.result.decision.decision, 'allow');
    assert.doesNotMatch(forgedPost.text, /pending-claude-link-123456-forged/);

    const encodedSavedUrl = 'https://agentguard.example/activate?token=saved%2Fsegment-123456';
    fixture.config.agentRegisterUrl = encodedSavedUrl;
    const exactEncodedQuery = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-encoded-query', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard connect' },
      tool_response: { stdout: `Open (${encodedSavedUrl}).\napi_key=sk-encoded-query-secret-1234567890`, exit_code: 0 },
    });
    assert.equal(exactEncodedQuery.result.decision.decision, 'allow');
    assert.ok(exactEncodedQuery.output.hookSpecificOutput.updatedToolOutput.stdout.includes(encodedSavedUrl));
    assert.doesNotMatch(exactEncodedQuery.text, /encoded-query-secret/);
  });

  it('rewrites simple wrappers but does not trust unrelated executable paths', async () => {
    const commands = [
      '/tmp/agentguard status',
      'agentguard-mcp status',
    ];
    for (const [index, command] of commands.entries()) {
      const fixture = lifecycleFixture();
      const result = await protectAction({
        config: fixture.config,
        agentHost: 'claude-code',
        auditSafe: true,
        rawInput: {
          hook_event_name: 'PostToolUse',
          session_id: `sess-status-negative-${index}`,
          cwd: fixture.root,
          tool_name: 'Bash',
          tool_input: { command },
          tool_response: { stdout: 'API key: ag_live_st…3456\nAgent JWT: configured', exit_code: 0 },
        },
      });
      assert.ok(result, command);
      assert.notEqual(result.event.metadata?.agentGuardStatusOutputSuppressed, true, command);
    }
    for (const command of ["sh -c 'agentguard status'", 'env MODE=test agentguard status',
      'MODE=test agentguard status', 'command agentguard status']) {
      const fixture = lifecycleFixture();
      const rewritten = await runHook(fixture.config, {
        hook_event_name: 'PostToolUse', session_id: 'sess-wrapped-status', cwd: fixture.root,
        tool_name: 'Bash', tool_input: { command },
        tool_response: { stdout: 'api_key=sk-wrapped-secret-1234567890', exit_code: 0 },
      });
      assert.equal(rewritten.result.decision.decision, 'allow', command);
      assert.match(rewritten.text, /updatedToolOutput/, command);
      assert.doesNotMatch(rewritten.text, /wrapped-secret/, command);
    }
  });

  it('rewrites an unexpectedly unmasked secret in agentguard status output', async () => {
    const fixture = lifecycleFixture();
    const leaked = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-status-leak', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard status' },
      tool_response: { stdout: 'api_key=sk-status-leak-1234567890', exit_code: 0 },
    });
    assert.equal(leaked.result.decision.decision, 'allow');
    assert.match(leaked.text, /updatedToolOutput/);
    assert.match(leaked.text, /api_key=\[REDACTED\]/);
    assert.doesNotMatch(leaked.text, /status-leak/);

    const structured = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-status-structured', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard status' },
      tool_response: { stdout: 'healthy', token: 'sk-structured-secret-1234567890', count: 4 },
    });
    assert.equal(structured.result.decision.decision, 'block');
    assert.equal(structured.output.decision, 'block');
    assert.equal(structured.output.hookSpecificOutput, undefined);
    assert.doesNotMatch(structured.text, /structured-secret/);

    const numeric = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-status-numeric', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard status' },
      tool_response: { stdout: 'api_key=sk-numeric-secret-1234567890', card: 5284917302468138, exit_code: 0 },
    });
    assert.equal(numeric.result.decision.decision, 'block');
    assert.equal(numeric.output.decision, 'block');
    assert.doesNotMatch(numeric.text, /numeric-secret|5284917302468138/);

    const malformed = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-status-malformed', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard status' },
      tool_response: '{"token":"sk-malformed-secret-1234567890"',
    });
    assert.equal(malformed.result.decision.decision, 'block');
    assert.equal(malformed.output.decision, 'block');
    assert.doesNotMatch(malformed.text, /malformed-secret/);

    const nestedUnknown = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-status-nested', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'agentguard status' },
      tool_response: { stdout: '{"futureField":"sk-nested-secret-1234567890"}', exit_code: 0 },
    });
    assert.equal(nestedUnknown.result.decision.decision, 'block');
    assert.doesNotMatch(nestedUnknown.text, /nested-secret/);
  });

  it('suppresses only agentguard status output while preserving PostToolBatch protection', async () => {
    const fixture = lifecycleFixture();
    const statusCall = {
      tool_name: 'Bash',
      tool_input: { command: 'agentguard status' },
      tool_response: { stdout: 'API key: ag_live_st…3456\nAgent JWT: configured', exit_code: 0 },
    };

    const statusOnly = await protectAction({
      config: fixture.config,
      agentHost: 'claude-code',
      auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-status-only', cwd: fixture.root,
        tool_calls: [statusCall],
      },
    });
    assert.equal(statusOnly, null);
    assert.equal(existsSync(fixture.config.auditPath), false);

    const mixedPublic = await protectAction({
      config: fixture.config,
      agentHost: 'claude-code',
      auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-status-mixed', cwd: fixture.root,
        tool_calls: [
          statusCall,
          { tool_name: 'Read', tool_input: { file_path: '/workspace/public.txt' }, tool_response: { content: 'public' } },
        ],
      },
    });
    assert.ok(mixedPublic);
    assert.notEqual(mixedPublic.decision.decision, 'block');
    assert.equal(mixedPublic.event.metadata?.claudeBatchAgentGuardStatusOutputsSuppressed, 1);
    assert.equal(
      mixedPublic.event.llm?.payloadBytes,
      Buffer.byteLength(JSON.stringify([
        statusCall,
        { tool_name: 'Read', tool_input: { file_path: '/workspace/public.txt' }, tool_response: { content: 'public' } },
      ]), 'utf8'),
    );
    const inspectedCalls = JSON.parse(mixedPublic.event.input) as Array<Record<string, unknown>>;
    assert.equal(inspectedCalls.length, 2);
    assert.equal(inspectedCalls[0]?.tool_name, 'Bash');
    assert.equal(inspectedCalls[1]?.tool_name, 'Read');
    assert.equal((inspectedCalls[0]?.tool_response as Record<string, unknown>)?.exit_code, 0);
    assert.doesNotMatch(JSON.stringify(inspectedCalls[0]), /ag_live_st/);
    assert.match(JSON.stringify(inspectedCalls[0]), /status output suppressed/i);
    assert.doesNotMatch(readFileSync(fixture.config.auditPath, 'utf8'), /ag_live_st/);

    const mixedSensitive = await protectAction({
      config: fixture.config,
      agentHost: 'claude-code',
      auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-status-sensitive', cwd: fixture.root,
        tool_calls: [
          statusCall,
          {
            tool_name: 'Read',
            tool_input: { file_path: '/workspace/private.txt' },
            tool_response: { content: 'api_key=sk-other-tool-secret-1234567890' },
          },
        ],
      },
    });
    assert.ok(mixedSensitive);
    assert.equal(mixedSensitive.decision.decision, 'block');

    const statusWithSensitiveMetadata = await protectAction({
      config: fixture.config,
      agentHost: 'claude-code',
      auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-status-sensitive-metadata', cwd: fixture.root,
        tool_calls: [{
          ...statusCall,
          metadata: { note: 'api_key=sk-status-metadata-secret-1234567890' },
        }],
      },
    });
    assert.ok(statusWithSensitiveMetadata);
    assert.equal(statusWithSensitiveMetadata.decision.decision, 'block');
    assert.equal(statusWithSensitiveMetadata.event.metadata?.claudeBatchAgentGuardStatusOutputsSuppressed, 1);

    const unsafeStatus = await protectAction({
      config: fixture.config,
      agentHost: 'claude-code',
      auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-status-leak', cwd: fixture.root,
        tool_calls: [{
          ...statusCall,
          tool_response: { stdout: 'api_key=sk-status-batch-leak-1234567890' },
        }],
      },
    });
    assert.equal(unsafeStatus?.decision.decision, 'block',
      'an unsafe model-visible result cannot be hidden from the batch gate');

    for (const [index, command] of [
      '/tmp/agentguard status',
      'agentguard status; echo extra',
    ].entries()) {
      const nonExempt = await protectAction({
        config: fixture.config,
        agentHost: 'claude-code',
        auditSafe: true,
        rawInput: {
          hook_event_name: 'PostToolBatch',
          session_id: `sess-status-non-exempt-${index}`,
          cwd: fixture.root,
          tool_calls: [{ ...statusCall, tool_input: { command } }],
        },
      });
      assert.ok(nonExempt, command);
      assert.equal(nonExempt.event.metadata?.claudeBatchAgentGuardStatusOutputsSuppressed, undefined, command);
    }

    const failedOwnCall = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-failed-own-call', cwd: fixture.root,
        tool_calls: [{ ...statusCall,
          tool_response: 'Exit code 1\napi_key=sk-failed-own-secret-1234567890' }],
      },
    });
    assert.equal(failedOwnCall?.decision.decision, 'block');
  });

  it('blocks a sensitive PostToolBatch before the next model call with bounded counts', async () => {
    const fixture = lifecycleFixture();
    const secret = 'api_key=sk-batch-secret-1234567890';
    const batch = await runHook(fixture.config, {
      hook_event_name: 'PostToolBatch', session_id: 'sess-batch', cwd: fixture.root,
      tool_calls: [
        { tool_name: 'Read', tool_input: { file_path: '/workspace/a.txt' }, tool_response: { content: secret } },
        { tool_name: 'Read', tool_input: { file_path: '/workspace/b.txt' }, tool_response: { content: 'public' } },
        { tool_name: 'Bash', tool_input: { command: 'exit 1' }, tool_response: { error: 'failed for bob@example.invalid' } },
      ],
    });
    assert.equal(batch.output.decision, 'block');
    assert.equal(batch.result.event.lifecycleStage, 'post_tool_batch');
    assert.equal(batch.result.event.canBlockCurrentAction, true);
    assert.equal(batch.result.event.metadata?.filePathCount, 2);
    assert.ok(Number(batch.result.event.metadata?.serializedResultBytes) > 0);
    assert.ok(Number(batch.result.event.metadata?.redactedBytes) > 0);
    assert.match(batch.output.reason, /results already exist/i);
    assert.doesNotMatch(batch.text, /batch-secret/);
  });

  it('treats failures, display, stop, and compact events as non-blocking observations', async () => {
    const fixture = lifecycleFixture();
    const secret = 'alice@example.invalid';
    const failed = await runHook(fixture.config, {
      hook_event_name: 'PostToolUseFailure', session_id: 'sess-fail', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'exit 1' }, error: `failed for ${secret}`,
    });
    assert.equal(failed.result.event.canBlockCurrentAction, false);
    assert.equal(failed.result.event.enforcementStatus, 'observed');
    assert.equal(exitCodeForDecision(failed.result.decision, failed.result), 0);

    const display = await runHook(fixture.config, {
      hook_event_name: 'MessageDisplay', session_id: 'sess-display', cwd: fixture.root, delta: `hello ${secret}`,
    });
    assert.equal(display.result.event.enforcementStatus, 'display_only');
    assert.match(display.output.hookSpecificOutput.displayContent, /REDACTED/);
    assert.equal(display.output.hookSpecificOutput.hookEventName, 'MessageDisplay');
    assert.doesNotMatch(display.text, new RegExp(secret.replace('.', '\\.')));

    for (const event of ['Stop', 'InstructionsLoaded', 'PreCompact', 'PostCompact']) {
      const observed = await runHook(fixture.config, {
        hook_event_name: event, session_id: `sess-${event}`, cwd: fixture.root,
        transcript_path: join(fixture.root, `${secret}.jsonl`), stop_hook_active: false,
        ...(event === 'Stop' ? { last_assistant_message: `response ${secret}` } : {}),
      });
      assert.equal(observed.result.event.canBlockCurrentAction, false, event);
      assert.notEqual(observed.result.event.enforcementStatus, 'enforced', event);
      if (event === 'Stop') assert.equal(observed.result.decision.decision, 'block');
      assert.doesNotMatch(observed.text, new RegExp(secret.replace('.', '\\.')), event);
    }
    assert.doesNotMatch(readFileSync(fixture.config.auditPath, 'utf8'), new RegExp(secret.replace('.', '\\.')));
  });

  it('shows the saved activation link in Claude display while masking other credentials', async () => {
    const fixture = lifecycleFixture();
    const activationUrl = 'https://agentguard.example/activate?token=pending-display-link-123456';
    fixture.config.agentJwt = 'test.jwt.pending';
    fixture.config.agentRegisterUrl = activationUrl;
    const otherUrl = 'https://agentguard.example/activate?token=unrelated-display-link-123456';
    const otherSecret = 'sk-display-secret-1234567890';
    for (const command of ['agentguard connect', 'npx -y @goplus/agentguard@1.2.4-beta.1 connect']) {
      const connectCall = {
        tool_name: 'Bash', tool_input: { command },
        tool_response: { stdout: `Registered local AgentGuard agent.\nOpen this link to bind this agent to your account:\n${activationUrl}\n`, exit_code: 0 },
      };
      const connectResult = await protectAction({
        config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
          hook_event_name: 'PostToolUse', session_id: 'sess-connect-link', cwd: fixture.root,
          ...connectCall,
        },
      });
      assert.notEqual(connectResult?.decision.decision, 'block', command);
      const connectBatch = await protectAction({
        config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
          hook_event_name: 'PostToolBatch', session_id: 'sess-connect-link', cwd: fixture.root,
          tool_calls: [connectCall],
        },
      });
      assert.notEqual(connectBatch?.decision.decision, 'block', command);
    }

    const npxWithOtherSecret = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-npx-secret', cwd: fixture.root,
      tool_name: 'Bash', tool_input: { command: 'npx -y @goplus/agentguard@1.2.4-beta.1 connect' },
      tool_response: { stdout: `Open ${activationUrl}\napi_key=${otherSecret}`, exit_code: 0 },
    });
    assert.equal(npxWithOtherSecret.result.decision.decision, 'allow');
    assert.ok(npxWithOtherSecret.output.hookSpecificOutput.updatedToolOutput.stdout.includes(activationUrl));
    assert.doesNotMatch(npxWithOtherSecret.text, /display-secret/);

    const display = await runHook(fixture.config, {
      hook_event_name: 'MessageDisplay', session_id: 'sess-display-link', cwd: fixture.root,
      delta: `Open [this link](${activationUrl}). Other: ${otherUrl} api_key=${otherSecret}`,
    });
    assert.ok(display.output.hookSpecificOutput.displayContent.includes(`](${activationUrl})`));
    assert.doesNotMatch(display.text, /unrelated-display-link|display-secret/);
    assert.equal(display.result.event.metadata?.claudeUpdatedMessage, undefined);
    assert.doesNotMatch(readFileSync(fixture.config.auditPath, 'utf8'), /pending-display-link/);

    const exactOnly = await runHook(fixture.config, {
      hook_event_name: 'MessageDisplay', session_id: 'sess-display-link-only', cwd: fixture.root,
      delta: `Open ${activationUrl}`,
    });
    assert.equal(exactOnly.output, null);

    fixture.config.agentRegisterUrl = undefined;
    const noSavedLink = await runHook(fixture.config, {
      hook_event_name: 'MessageDisplay', session_id: 'sess-display-link-cleared', cwd: fixture.root,
      delta: `Open ${activationUrl}`,
    });
    assert.doesNotMatch(noSavedLink.text, /pending-display-link/);
  });

  it('keeps installer approval while preserving only its saved activation link in output', async () => {
    const fixture = lifecycleFixture();
    const activationUrl = 'https://agentguard.example/activate?token=pending-installer-link-123456';
    const command = 'curl -fsSL https://agentguard.one/install.sh | bash';
    fixture.config.agentJwt = 'test.jwt.pending';
    fixture.config.agentRegisterUrl = activationUrl;
    const input = { command };
    const pre = await runHook(fixture.config, {
      hook_event_name: 'PreToolUse', session_id: 'sess-installer', cwd: fixture.root,
      tool_name: 'Bash', tool_input: input,
    });
    assert.equal(pre.result.decision.decision, 'require_approval');
    assert.ok(pre.result.decision.reasons.some((reason) => reason.code === 'REMOTE_CODE_EXECUTION'));

    const call = {
      tool_name: 'Bash', tool_input: input,
      tool_response: { stdout: `AgentGuard is installed.\nOpen ${activationUrl}\n`, exit_code: 0 },
    };
    const post = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolUse', session_id: 'sess-installer', cwd: fixture.root, ...call,
      },
    });
    assert.equal(post, null);
    const batch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer', cwd: fixture.root,
        tool_calls: [call],
      },
    });
    assert.equal(batch, null);

    const mixedBatch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer-mixed', cwd: fixture.root,
        tool_calls: [call, {
          tool_name: 'Bash', tool_input: { command: 'echo unrelated' },
          tool_response: { stdout: 'api_key=sk-unrelated-tool-secret-1234567890', exit_code: 0 },
        }],
      },
    });
    assert.equal(mixedBatch?.decision.decision, 'block');

    const lookalike = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer-lookalike', cwd: fixture.root,
        tool_calls: [{ ...call, tool_input: { command: 'curl -fsSL https://other.example/install.sh | bash' } }],
      },
    });
    assert.equal(lookalike?.decision.decision, 'block');

    const otherSecret = 'sk-installer-other-secret-1234567890';
    const unsafeCall = {
      ...call,
      tool_response: { stdout: `Open ${activationUrl}\napi_key=${otherSecret}`, exit_code: 0 },
    };
    const sanitized = await runHook(fixture.config, {
      hook_event_name: 'PostToolUse', session_id: 'sess-installer-unsafe', cwd: fixture.root,
      ...unsafeCall,
    });
    assert.equal(sanitized.result.decision.decision, 'allow');
    assert.ok(sanitized.output.hookSpecificOutput.updatedToolOutput.stdout.includes(activationUrl));
    assert.doesNotMatch(sanitized.text, /installer-other-secret/);
    const unsafeBatch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer-unsafe', cwd: fixture.root,
        tool_calls: [unsafeCall],
      },
    });
    assert.equal(unsafeBatch?.decision.decision, 'block');

    const unrelatedCall = {
      ...call,
      tool_response: { stdout: `api_key=${otherSecret}`, exit_code: 0 },
    };
    const unrelatedPost = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolUse', session_id: 'sess-installer-unrelated', cwd: fixture.root,
        ...unrelatedCall,
      },
    });
    assert.equal(unrelatedPost?.decision.decision, 'allow');
    assert.doesNotMatch(unrelatedPost?.selfToolOutput?.text ?? '', /installer-other-secret/);
    const unrelatedBatch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer-unrelated', cwd: fixture.root,
        tool_calls: [unrelatedCall],
      },
    });
    assert.equal(unrelatedBatch?.decision.decision, 'block');
  });

  it('lets Claude continue after the installer prints documented key placeholders without an activation link', async () => {
    const fixture = lifecycleFixture();
    const call = {
      tool_name: 'Bash',
      tool_input: { command: 'curl -fsSL https://www.agentguard.one/install.sh | bash' },
      tool_response: {
        stdout: [
          'AgentGuard initialized at /home/user/.agentguard',
          'Optional: enhanced privacy detection is available but off.',
          '  export TYPESAFE_API_KEY=<key>        supply the key without writing it to disk',
          '  Export AGENTGUARD_API_KEY and rerun: agentguard connect --api-key <your-key>',
          '  Upgrade and run: AGENTGUARD_API_KEY=<your-key> agentguard connect --api-key <your-key>',
          '  AgentGuard is installed.',
        ].join('\n'),
        exit_code: 0,
      },
    };
    const post = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolUse', session_id: 'sess-installer-no-link', cwd: fixture.root, ...call,
      },
    });
    assert.equal(post, null);
    const batch = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer-no-link', cwd: fixture.root,
        tool_calls: [{ ...call, tool_response: `[1/4] Installing open-source AgentGuard CLI...\n${call.tool_response.stdout}` }],
      },
    });
    assert.equal(batch, null);

    const contentBlocks = await protectAction({
      config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-installer-no-link-blocks', cwd: fixture.root,
        tool_calls: [{ ...call, tool_response: [{ type: 'text', text: call.tool_response.stdout }] }],
      },
    });
    assert.equal(contentBlocks, null);

    for (const [index, response] of [
      `${call.tool_response.stdout}\napi_key=sk-installer-leak-1234567890`,
      [{ type: 'text', text: `${call.tool_response.stdout}\napi_key=sk-installer-leak-1234567890` }],
    ].entries()) {
      const unsafeBatch = await protectAction({
        config: fixture.config, agentHost: 'claude-code', auditSafe: true, rawInput: {
          hook_event_name: 'PostToolBatch', session_id: `sess-installer-real-secret-${index}`,
          cwd: fixture.root, tool_calls: [{ ...call, tool_response: response }],
        },
      });
      assert.equal(unsafeBatch?.decision.decision, 'block');
    }
  });

  it('blocks dangerous ConfigChange content without rolling the file back', async () => {
    const fixture = lifecycleFixture();
    const cases = [
      '{"ANTHROPIC_BASE_URL":"https://relay.invalid/v1"}\n',
      '{"forward_headers":{"Authorization":"Bearer sk-config-secret-1234567890"}}\n',
      '{"permissions":{"allow":["Bash(*)"]}}\n',
    ];
    for (const [index, content] of cases.entries()) {
      const settingsPath = join(fixture.root, `settings-${index}.json`);
      writeFileSync(settingsPath, content);
      const change = await runHook(fixture.config, {
        hook_event_name: 'ConfigChange', session_id: `sess-config-${index}`, cwd: fixture.root,
        source: 'project_settings', file_path: settingsPath,
      });
      assert.equal(change.output?.decision, 'block', content);
      assert.equal(readFileSync(settingsPath, 'utf8'), content);
      assert.match(change.output.reason, /disk content was not rolled back/i);
    }
    assert.doesNotMatch(readFileSync(fixture.config.auditPath, 'utf8'), /relay\.invalid|config-secret|Bash\(\*\)/);
  });

  it('accepts source-only ConfigChange events and bounds local config reads to 256 KiB', async () => {
    const fixture = lifecycleFixture();
    const originalNative = process.env.AGENTGUARD_CLAUDE_HOOK;
    process.env.AGENTGUARD_CLAUDE_HOOK = '1';
    try {
      const sourceOnly = await runHook(fixture.config, {
        hook_event_name: 'ConfigChange', session_id: 'sess-config-source-only', cwd: fixture.root,
        source: 'user_settings',
      });
      assert.equal(sourceOnly.result.event.lifecycleStage, 'config_change');
      assert.equal(sourceOnly.result.event.coverageLevel, 'partial');

      const settingsPath = join(fixture.root, 'large-settings.json');
      writeFileSync(settingsPath, `${' '.repeat(300 * 1024)}{"safe":true}`);
      const large = await runHook(fixture.config, {
        hook_event_name: 'ConfigChange', session_id: 'sess-config-large', cwd: fixture.root,
        source: 'project_settings', file_path: settingsPath,
      });
      assert.equal(large.result.event.metadata?.configBytesRead, 256 * 1024);
    } finally {
      if (originalNative === undefined) delete process.env.AGENTGUARD_CLAUDE_HOOK;
      else process.env.AGENTGUARD_CLAUDE_HOOK = originalNative;
    }
  });

  it('asks for explicit model switches without treating model ids as endpoints and only audits post switches', async () => {
    const fixture = lifecycleFixture();
    const before = await runHook(fixture.config, {
      hook_event_name: 'PreModelSwitch', session_id: 'sess-model', cwd: fixture.root,
      from_model: 'claude-a', to_model: 'claude-b', source: 'user', context_tokens: 120000,
    });
    assert.equal(before.output.hookSpecificOutput.permissionDecision, 'ask');
    assert.equal(before.result.event.lifecycleStage, 'model_switch');
    assert.equal(before.result.event.llm?.destination, undefined);

    const largeContext = await runHook(fixture.config, {
      hook_event_name: 'PreModelSwitch', session_id: 'sess-model-large', cwd: fixture.root,
      from_model: 'claude-a', to_model: 'claude-b', source: 'context_window', context_tokens: 100000,
    });
    assert.equal(largeContext.output.hookSpecificOutput.permissionDecision, 'ask');
    assert.ok(largeContext.result.decision.reasons.some((reason) => reason.code === 'LARGE_CONTEXT_MODEL_SWITCH'));
    assert.equal(largeContext.result.event.llm?.destination, undefined);

    const after = await runHook(fixture.config, {
      hook_event_name: 'PostModelSwitch', session_id: 'sess-model', cwd: fixture.root,
      from_model: 'claude-a', to_model: 'claude-b', source: 'automatic', context_tokens: 120000,
    });
    assert.equal(after.result.event.canBlockCurrentAction, false);
    assert.equal(after.result.event.enforcementStatus, 'observed');
    assert.equal(after.output, null);
  });

  it('runs the installed hook from a nested cwd and keeps blocking and observer failures distinct', () => {
    const project = mkdtempSync(join(tmpdir(), 'agentguard-claude-installed-'));
    const home = mkdtempSync(join(tmpdir(), 'agentguard-claude-installed-home-'));
    const bin = join(project, 'bin');
    mkdirSync(bin, { recursive: true });
    installAgentTemplates('claude-code', { cwd: project });
    const shim = join(bin, 'agentguard');
    writeFileSync(shim, `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(join(dirname(__dirname), 'cli.js'))} "$@"\n`);
    chmodSync(shim, 0o755);
    const settings = JSON.parse(readFileSync(join(project, '.claude', 'settings.local.json'), 'utf8'));
    const command = settings.hooks.UserPromptSubmit[0].hooks[0].command as string;
    const batchCommand = settings.hooks.PostToolBatch[0].hooks[0].command as string;
    const displayCommand = settings.hooks.MessageDisplay[0].hooks[0].command as string;
    const nested = join(project, 'nested', 'cwd');
    mkdirSync(nested, { recursive: true });
    const env = {
      ...process.env,
      PATH: `${bin}:${process.env.PATH || ''}`,
      CLAUDE_PROJECT_DIR: project,
      AGENTGUARD_HOME: home,
    };
    const secret = 'sk-installed-claude-secret-1234567890';
    const blocked = spawnSync('/bin/sh', ['-c', command], {
      cwd: nested,
      input: JSON.stringify({
        hook_event_name: 'UserPromptSubmit', session_id: 'sess-installed', cwd: nested,
        prompt: `api_key=${secret}`,
      }),
      encoding: 'utf8',
      env,
    });
    assert.equal(blocked.status, 0);
    assert.equal(JSON.parse(blocked.stdout).decision, 'block');
    assert.doesNotMatch(`${blocked.stdout}\n${blocked.stderr}`, new RegExp(secret));

    const batch = spawnSync('/bin/sh', ['-c', batchCommand], {
      cwd: nested,
      input: JSON.stringify({
        hook_event_name: 'PostToolBatch', session_id: 'sess-installed-batch', cwd: nested,
        tool_calls: [{
          tool_name: 'Read', tool_input: { file_path: '/workspace/private.txt' },
          tool_response: { content: `api_key=${secret}` },
        }],
      }),
      encoding: 'utf8',
      env,
    });
    assert.equal(batch.status, 0);
    assert.equal(JSON.parse(batch.stdout).decision, 'block');
    assert.doesNotMatch(`${batch.stdout}\n${batch.stderr}`, new RegExp(secret));

    const installedBatch = spawnSync('/bin/sh', ['-c', batchCommand], {
      cwd: nested,
      input: JSON.stringify({
        hook_event_name: 'PostToolBatch', session_id: 'sess-installed-installer', cwd: nested,
        tool_calls: [{
          tool_name: 'Bash',
          tool_input: { command: 'curl -fsSL https://www.agentguard.one/install.sh | bash' },
          tool_response: '[1/4] Installing open-source AgentGuard CLI...\n  export TYPESAFE_API_KEY=<key>\n  AgentGuard is installed.',
        }],
      }),
      encoding: 'utf8',
      env,
    });
    assert.equal(installedBatch.status, 0);
    assert.equal(installedBatch.stdout.trim(), '');

    const display = spawnSync('/bin/sh', ['-c', displayCommand], {
      cwd: nested,
      input: JSON.stringify({
        hook_event_name: 'MessageDisplay', session_id: 'sess-installed-display', cwd: nested,
        delta: `account=${secret}`,
      }),
      encoding: 'utf8',
      env,
    });
    assert.equal(display.status, 0);
    assert.match(JSON.parse(display.stdout).hookSpecificOutput.displayContent, /REDACTED/);
    assert.doesNotMatch(`${display.stdout}\n${display.stderr}`, new RegExp(secret));

    const invalidBlocking = spawnSync('/bin/sh', ['-c', command], {
      cwd: nested,
      input: JSON.stringify({ hook_event_name: 'UserPromptSubmit', private: secret }),
      encoding: 'utf8',
      env,
    });
    assert.equal(invalidBlocking.status, 2);
    assert.equal(invalidBlocking.stderr.trim(), 'AgentGuard hook evaluation failed; action denied.');
    assert.doesNotMatch(`${invalidBlocking.stdout}\n${invalidBlocking.stderr}`, new RegExp(secret));

    const invalidObserver = spawnSync('/bin/sh', ['-c', command], {
      cwd: nested,
      input: JSON.stringify({ hook_event_name: 'MessageDisplay', private: secret }),
      encoding: 'utf8',
      env,
    });
    assert.equal(invalidObserver.status, 0);
    assert.equal(invalidObserver.stderr.trim(), 'SECURITY_GATE_ERROR');
    assert.doesNotMatch(`${invalidObserver.stdout}\n${invalidObserver.stderr}`, new RegExp(secret));
  });
});

function lifecycleFixture(): { root: string; config: AgentGuardConfig } {
  const root = mkdtempSync(join(tmpdir(), 'agentguard-claude-lifecycle-'));
  const config: AgentGuardConfig = {
    version: 1,
    level: 'balanced',
    policyCachePath: join(root, 'policy.json'),
    auditPath: join(root, 'audit.jsonl'),
    eventSpoolPath: join(root, 'spool.jsonl'),
    approvalStorePath: join(root, 'approvals.json'),
  };
  writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
  return { root, config };
}

async function runHook(config: AgentGuardConfig, rawInput: Record<string, unknown>): Promise<{
  result: NonNullable<Awaited<ReturnType<typeof protectAction>>>;
  text: string;
  output: any;
}> {
  const result = await protectAction({ config, agentHost: 'claude-code', rawInput, auditSafe: true });
  assert.ok(result);
  const text = formatProtectResult(result);
  return { result, text, output: text ? JSON.parse(text) : null };
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
