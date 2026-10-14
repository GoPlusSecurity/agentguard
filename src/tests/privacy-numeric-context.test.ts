import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extractCandidates } from '../privacy/candidates.js';
import { chunkLocator, splitChunks } from '../privacy/chunks.js';
import { AgentGuardCloudClient } from '../cloud/client.js';
import { observeDshToolResult, protectDshToolCall, protectDshToolResult } from '../dsh/runtime.js';
import { buildDshLlmRequestAction } from '../dsh/llm-privacy.js';
import { resetPublicSearchProvenanceForTests } from '../runtime/public-search.js';
import { hasSensitivePublicSearchResult, redactPublicSearchResult } from '../runtime/public-search.js';
import { shouldReportAuditEventToCloud } from '../runtime/audit.js';
import { redactText, summarizeSensitiveData } from '../runtime/redaction.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { formatProtectResult, protectAction } from '../runtime/protect.js';
import type { AgentGuardConfig } from '../config.js';

const candidatesOf = (text: string) => {
  const chunks = splitChunks(text);
  return extractCandidates(text, chunkLocator(chunks));
};

describe('Numeric PII context', () => {
  it('excludes real decimal fractions but never globally exempts technical-looking keys', () => {
    const decimals = [
      '{"price":"0.110105199001010002"}', // Valid ID checksum inside a fractional price.
      '{"price":"0.1234567890123452"}', // Luhn-valid fractional price.
      '{"tokenPrice":"0.1234567890123452"}',
      '1234567890123452.50',
    ];
    for (const text of decimals) {
      assert.equal(redactText(text), text, text);
      assert.deepEqual(summarizeSensitiveData(text), [], text);
      assert.deepEqual(candidatesOf(text), [], text);
    }
    for (const text of [
      '{"price":"5284917302468138"}',
      '{"rank":"110105199001010002"}',
      '{"id":"110105199001010002"}',
      '{"description":"客户的银行卡是 price: 5284917302468138"}',
      '银行卡号.5284917302468138',
      '银行卡号 .5284917302468138',
      '身份证号.110105199001010002',
    ]) {
      assert.notEqual(redactText(text), text, text);
      assert.ok(candidatesOf(text).length > 0, text);
    }
  });

  it('still protects labeled and bare real identifiers, including labels next to technical fields', () => {
    for (const [text, category] of [
      ['{"card_number":"5284917302468138"}', 'bank_account'],
      ['{"national_id":"11010519491231002X"}', 'national_id'],
      ['5284917302468138', 'bank_account'],
      ['11010519491231002X', 'national_id'],
      ['id: 110105199001010002', 'national_id'],
      ['{"price":"5284917302468138"}', 'bank_account'],
      [JSON.stringify({ price: '0.110105199001010002', card_number: '5284917302468138' }), 'bank_account'],
    ]) {
      assert.notEqual(redactText(text), text, text);
      assert.ok(summarizeSensitiveData(text).some((item) => item.kind === category), text);
      assert.ok(candidatesOf(text).some((item) => item.category === category), text);
    }
  });

  it('never exempts numeric identifiers in unknown nested search fields or embedded JSON', () => {
    const card = '5284917302468138';
    const id = '2026101215253008';
    const structured = { content: [{ type: 'text', text: 'Public market result', id,
      customer: { payment: { pan: card } } }] };
    const nested = redactPublicSearchResult(structured) as typeof structured;
    assert.equal(nested.content[0]?.id, id);
    assert.equal(nested.content[0]?.customer.payment.pan, '[REDACTED:PII_BANK_ACCOUNT]');
    assert.equal(hasSensitivePublicSearchResult(structured), true);

    const sameKeyAtDifferentDepth = redactPublicSearchResult({
      results: [{ id, customer: { id: card } }],
    }) as { results: Array<{ id: string; customer: { id: string } }> };
    assert.equal(sameKeyAtDifferentDepth.results[0]?.id, id);
    assert.equal(sameKeyAtDifferentDepth.results[0]?.customer.id, '[REDACTED:PII_BANK_ACCOUNT]');

    const text = JSON.stringify({ results: [{ id, customer: { payment: { pan: card } } }] });
    const embedded = redactPublicSearchResult({ content: text }) as { content: string };
    assert.equal(JSON.parse(embedded.content).results[0].id, id);
    assert.equal(JSON.parse(embedded.content).results[0].customer.payment.pan, '[REDACTED:PII_BANK_ACCOUNT]');
    assert.equal(hasSensitivePublicSearchResult({ content: JSON.stringify({ id, rank: '1234567890123452' }) }), false);
  });

  it('does not block coin-price search results or the following model continuation', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-numeric-privacy-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(root, 'policy.json'),
      auditPath: join(root, 'audit.jsonl'),
      eventSpoolPath: join(root, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
    const content = JSON.stringify({
      price: '0.110105199001010002',
      timestamp: '1700000000000001',
      id: '2026101215253008',
      rank: '1234567890123452',
      status: 200,
      url: 'https://example.com/search?q=bitcoin',
    });
    const toolCall = {
      tool_name: 'WebSearch',
      tool_input: { query: 'token price' },
      tool_response: { content },
    };
    const postTool = await protectAction({
      config, agentHost: 'claude-code', auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolUse', session_id: 'sess-numeric', cwd: root,
        ...toolCall,
      },
    });
    assert.ok(postTool);
    assert.equal(postTool.decision.decision, 'allow');
    assert.equal(postTool.decision.riskScore, 0);
    assert.ok(!postTool.decision.reasons.some((reason) => reason.code === 'PII_EGRESS'));
    assert.equal(shouldReportAuditEventToCloud(postTool.event), false);
    const output = JSON.parse(formatProtectResult(postTool));
    assert.equal(output.hookSpecificOutput.updatedToolOutput.content, content);

    const structuredPrice = await protectAction({ config, agentHost: 'claude-code', auditSafe: true, rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-numeric', tool_name: 'WebSearch',
      tool_input: { query: 'token price' },
      tool_response: { content: 'Public market data', token: 'Wrapped Bitcoin', id: '2026101215253008' },
    } });
    assert.equal(structuredPrice?.decision.decision, 'allow');
    assert.ok(structuredPrice);
    assert.equal(shouldReportAuditEventToCloud(structuredPrice.event), false);

    const batch = await protectAction({
      config, agentHost: 'claude-code', auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-numeric', cwd: root,
        tool_calls: [toolCall],
      },
    });
    assert.ok(batch);
    // PostToolBatch independently warns when the host cannot supply its final
    // model destination or complete payload. Those existing visibility warnings
    // are not a numeric-PII finding and must not escalate to block 100.
    assert.equal(batch.decision.decision, 'warn');
    assert.ok(batch.decision.riskScore < 100);
    assert.equal(batch.decision.ruleEvaluations?.find((rule) => rule.ruleId === 'PII_EGRESS')?.detected, false);
    assert.equal(batch.decision.reasons.find((reason) => reason.code === 'PII_EGRESS')?.title,
      'LLM payload visibility incomplete');
    assert.equal(shouldReportAuditEventToCloud(batch.event), false);
    assert.equal(batch.event.metadata?.redactedBytes, 0);
    assert.doesNotMatch(formatProtectResult(batch), /"decision":"block"/);

    const originalFetch = globalThis.fetch;
    const uploads: string[] = [];
    globalThis.fetch = (async (url: Parameters<typeof fetch>[0]) => {
      uploads.push(String(url));
      throw new Error('An allowed public search result must never reach Cloud');
    }) as typeof fetch;
    try {
      const client = new AgentGuardCloudClient({ cloudUrl: 'https://agentguard.example', apiKey: 'ag_live_test_key_123456' });
      await client.ingestEvents([postTool.event, batch.event]);
      assert.deepEqual(uploads, []);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('keeps the public-search exception out of prompts, local files and mixed batches', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-numeric-privacy-'));
    const config: AgentGuardConfig = {
      version: 1, level: 'balanced', policyCachePath: join(root, 'policy.json'),
      auditPath: join(root, 'audit.jsonl'), eventSpoolPath: join(root, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
    const opaqueId = '2026101215253008';
    const readOutput = { content: JSON.stringify({ price: '5284917302468138' }) };
    const prompt = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'UserPromptSubmit', session_id: 'sess-private', prompt: JSON.stringify({ price: '5284917302468138' }),
    } });
    assert.equal(prompt?.decision.decision, 'block');

    const query = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PreToolUse', session_id: 'sess-private', tool_name: 'WebSearch',
      tool_input: { query: '银行卡号 5284917302468138' },
    } });
    assert.equal(query?.decision.decision, 'block');

    const postWithSensitiveQuery = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-private', tool_name: 'WebSearch',
      tool_input: { query: '银行卡号 5284917302468138' },
      tool_response: { content: JSON.stringify({ id: '2026101215253008' }) },
    } });
    assert.equal(postWithSensitiveQuery?.decision.decision, 'block');

    const localRead = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-private', tool_name: 'Read',
      tool_input: { file_path: '/workspace/a.txt' }, tool_response: readOutput,
    } });
    assert.equal(localRead?.decision.decision, 'block');

    const batch = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolBatch', session_id: 'sess-private', tool_calls: [
        { tool_name: 'WebSearch', tool_input: { query: 'price' }, tool_response: { content: JSON.stringify({ id: opaqueId }) } },
        { tool_name: 'Read', tool_input: { file_path: '/workspace/a.txt' }, tool_response: readOutput },
      ],
    } });
    assert.equal(batch?.decision.decision, 'block');
    assert.equal(batch?.decision.riskScore, 100);

    const queryInBatch = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolBatch', session_id: 'sess-private', tool_calls: [
        { tool_name: 'WebSearch', tool_input: { query: '银行卡号 5284917302468138' },
          tool_response: { content: JSON.stringify({ id: opaqueId }) } },
      ],
    } });
    assert.equal(queryInBatch?.decision.decision, 'block');

    const unknownShape = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-private', tool_name: 'WebSearch',
      tool_input: { query: 'price' }, tool_response: { opaque: opaqueId },
    } });
    assert.equal(unknownShape?.decision.decision, 'block');

    const structuredResult = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-public', tool_name: 'WebSearch',
      tool_input: { query: 'price' }, tool_response: {
        content: [{ type: 'text', text: 'Public price', id: opaqueId }],
        card_number: '5284917302468138',
      },
    } });
    assert.equal(structuredResult?.decision.decision, 'block');
    assert.ok(structuredResult);
    assert.doesNotMatch(formatProtectResult(structuredResult), /5284917302468138/);

    const credentialValue = 'numeric-review-api-key-1234567890';
    const structuredCredential = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-public', tool_name: 'WebSearch',
      tool_input: { query: 'price' }, tool_response: { content: 'Public price', api_key: credentialValue },
    } });
    assert.equal(structuredCredential?.decision.decision, 'block');
    assert.ok(structuredCredential);
    assert.doesNotMatch(formatProtectResult(structuredCredential), /numeric-review-api-key/);

    const structuredBatch = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolBatch', session_id: 'sess-public', tool_calls: [{
        tool_name: 'WebSearch', tool_input: { query: 'price' },
        tool_response: { content: [{ type: 'text', text: 'Public price', card_number: '5284917302468138' }] },
      }],
    } });
    assert.equal(structuredBatch?.decision.decision, 'block');

    const nestedPan = { content: [{ type: 'text', text: 'Public price', id: opaqueId,
      customer: { payment: { pan: '5284917302468138' } } }] };
    const nestedPost = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-public', tool_name: 'WebSearch',
      tool_input: { query: 'price' }, tool_response: nestedPan,
    } });
    assert.equal(nestedPost?.decision.decision, 'block');
    assert.equal(nestedPost?.decision.riskScore, 100);
    assert.ok(nestedPost);
    assert.doesNotMatch(formatProtectResult(nestedPost), /5284917302468138/);
    assert.match(formatProtectResult(nestedPost), /2026101215253008/);

    const nestedBatch = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolBatch', session_id: 'sess-public', tool_calls: [{
        tool_name: 'WebSearch', tool_input: { query: 'price' }, tool_response: nestedPan,
      }],
    } });
    assert.equal(nestedBatch?.decision.decision, 'block');

    const unsupportedBatch = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolBatch', session_id: 'sess-public', tool_calls: [{
        tool_name: 'WebSearch', tool_input: { query: 'price' },
        tool_response: { opaque: { pan: '5284917302468138' } },
      }],
    } });
    assert.equal(unsupportedBatch?.decision.decision, 'block');
    assert.equal(unsupportedBatch?.event.metadata?.claudeBatchVerified, false);

    const labeledProse = await protectAction({ config, agentHost: 'claude-code', rawInput: {
      hook_event_name: 'PostToolUse', session_id: 'sess-public', tool_name: 'WebSearch',
      tool_input: { query: 'price' }, tool_response: { content: '银行卡号.5284917302468138' },
    } });
    assert.equal(labeledProse?.decision.decision, 'block');
    assert.ok(labeledProse);
    assert.doesNotMatch(formatProtectResult(labeledProse), /5284917302468138/);
  });

  it('continues to block confirmed PII in a search result', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-numeric-privacy-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(root, 'policy.json'),
      auditPath: join(root, 'audit.jsonl'),
      eventSpoolPath: join(root, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
    const result = await protectAction({
      config, agentHost: 'claude-code', auditSafe: true,
      rawInput: {
        hook_event_name: 'PostToolBatch', session_id: 'sess-confirmed', cwd: root,
        tool_calls: [{
          tool_name: 'WebSearch', tool_input: { query: 'search' },
          tool_response: { content: JSON.stringify({ id: '2026101215253008', card_number: '5284917302468138' }) },
        }],
      },
    });
    assert.ok(result);
    assert.equal(result.decision.decision, 'block');
    assert.equal(result.decision.riskScore, 100);
    assert.ok(result.decision.reasons.some((reason) => reason.code === 'PII_EGRESS'));
    assert.equal(shouldReportAuditEventToCloud(result.event), true);
  });

  it('uses observed search results, not search arguments, across Codex, OpenClaw/QClaw, and Hermes', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-cross-agent-search-'));
    const config: AgentGuardConfig = {
      version: 1, level: 'balanced', policyCachePath: join(root, 'policy.json'),
      auditPath: join(root, 'audit.jsonl'), eventSpoolPath: join(root, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
    const number = '2026101215253008';
    for (const [agentHost, toolName, raw] of [
      ['codex', 'web_search', { hook_event_name: 'PostToolUse', tool_name: 'web_search',
        tool_input: { query: 'coin price' }, tool_response: { content: JSON.stringify({ id: number }) } }],
      ['openclaw', 'web_search', { toolName: 'web_search', params: { query: 'coin price' },
        result: { content: JSON.stringify({ id: number }) } }],
      ['qclaw', 'web_search', { toolName: 'web_search', params: { query: 'coin price' },
        result: { content: JSON.stringify({ id: number }) } }],
      ['hermes', 'web_search', { hook_event_name: 'post_tool_call', tool_name: 'web_search',
        status: 'ok', tool_input: { query: 'coin price' }, tool_response: { content: JSON.stringify({ id: number }) } }],
    ] as const) {
      const result = await protectAction({ config, agentHost, actionType: 'web_search', toolName,
        phase: 'post', auditSafe: true, rawInput: { session_id: `sess-${agentHost}`, ...raw } });
      assert.ok(result, agentHost);
      assert.equal(result.decision.decision, 'allow', agentHost);
      assert.equal(result.decision.riskScore, 0, agentHost);
      assert.equal(result.event.metadata?.publicSearchOutput, true, agentHost);
      assert.equal(shouldReportAuditEventToCloud(result.event), false, agentHost);

      const queryOnly = await protectAction({ config, agentHost, actionType: 'web_search', toolName,
        phase: 'pre', auditSafe: true, rawInput: { session_id: `sess-${agentHost}`, ...raw,
          ...(agentHost === 'openclaw' || agentHost === 'qclaw'
            ? { result: undefined, params: { query: '银行卡号 5284917302468138' } }
            : { tool_response: undefined, tool_input: { query: '银行卡号 5284917302468138' },
              hook_event_name: agentHost === 'hermes' ? 'pre_tool_call' : 'PreToolUse' }) } });
      assert.equal(queryOnly?.decision.decision, 'block', `${agentHost}:pre-query`);

      const noResult = await protectAction({ config, agentHost, actionType: 'web_search', toolName,
        phase: 'post', auditSafe: true, rawInput: { session_id: `sess-${agentHost}`, ...raw,
          ...(agentHost === 'openclaw' || agentHost === 'qclaw'
            ? { result: undefined } : { tool_response: undefined }) } });
      if (noResult) assert.equal(shouldReportAuditEventToCloud(noResult.event), false, `${agentHost}:no-result`);

      const privateValue = await protectAction({ config, agentHost, actionType: 'web_search', toolName,
        phase: 'post', auditSafe: true, rawInput: { session_id: `sess-${agentHost}`,
          ...raw, ...(agentHost === 'openclaw' || agentHost === 'qclaw'
            ? { result: { content: 'card_number: 5284917302468138' } }
            : { tool_response: { content: 'card_number: 5284917302468138' } }) } });
      assert.equal(privateValue?.decision.decision, 'block', agentHost);
      if (agentHost !== 'codex') {
        assert.ok(privateValue);
        assert.equal(shouldReportAuditEventToCloud(privateValue.event), false,
          `${agentHost}:observer result was not intercepted`);
      }

      const unverified = await protectAction({ config, agentHost, actionType: 'web_search', toolName,
        phase: 'post', auditSafe: true, rawInput: { session_id: `sess-${agentHost}`,
          ...raw, ...(agentHost === 'openclaw' || agentHost === 'qclaw'
            ? { result: { opaque: number } }
            : { tool_response: { opaque: number } }) } });
      assert.equal(unverified?.event.metadata?.publicSearchOutput, undefined, agentHost);
      assert.equal(unverified?.decision.decision, 'block', agentHost);

      if (agentHost === 'hermes') {
        for (const status of [undefined, 'error'] as const) {
          const unsupportedStatus = await protectAction({ config, agentHost,
            actionType: 'web_search', toolName, phase: 'post', auditSafe: true,
            rawInput: { session_id: `sess-${agentHost}`, ...raw,
              status, tool_response: { content: JSON.stringify({ id: number }) } },
          });
          assert.equal(unsupportedStatus?.event.metadata?.publicSearchOutput, undefined);
          assert.equal(unsupportedStatus?.decision.decision, 'block', `hermes:${status ?? 'missing-status'}`);
        }
      }
    }
  });

  it('inspects DSH search results without exempting a read result or an unclassified image query', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-dsh-search-'));
    const config: AgentGuardConfig = {
      version: 1, level: 'balanced', policyCachePath: join(root, 'policy.json'),
      auditPath: join(root, 'audit.jsonl'), eventSpoolPath: join(root, 'spool.jsonl'),
    };
    writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
    const dependencies = { loadAgentGuardConfig: () => config, fetchPolicyFor: () => undefined, writeAudit() {} };
    const exec = { name: 'web_search', callId: 'call-search', rootCallId: 'root-search',
      arguments: { query: 'bitcoin price' }, agent: { id: 'session-search' } };
    const result = { isError: false, content: [{ type: 'text', text: JSON.stringify({ id: '2026101215253008' }) }] };
    const allowed = await protectDshToolResult(exec, result, dependencies);
    assert.equal(allowed?.evaluation.decision.decision, 'allow');
    assert.equal(allowed?.action.metadata?.publicSearchOutput, true);
    assert.ok(allowed);
    assert.equal(shouldReportAuditEventToCloud(allowed.event), false);

    const searchText = result.content[0]!.text;
    const modelOptions = {
      provider: 'official', model: 'test-model', sessionId: 'session-search',
      messages: [{ role: 'tool', content: [{ type: 'tool-result', content: [{ type: 'text', text: searchText }] }] }],
    };
    const modelRequest = buildDshLlmRequestAction(modelOptions, 'req-search');
    assert.match(modelRequest.input, /PUBLIC_SEARCH_NUMBER/);
    assert.doesNotMatch(modelRequest.input, /2026101215253008/);
    assert.equal(modelOptions.messages[0]!.content[0]!.content[0]!.text, searchText,
      'inspection must not rewrite the actual model payload');

    const withUserMessage = buildDshLlmRequestAction({ ...modelOptions,
      messages: [...modelOptions.messages, { role: 'user', content: [{ type: 'text', text: searchText }] }],
    }, 'req-user');
    assert.match(withUserMessage.input, /PUBLIC_SEARCH_NUMBER/);
    assert.match(withUserMessage.input, /2026101215253008/, 'user content must remain fully inspected');

    const otherSession = buildDshLlmRequestAction({ ...modelOptions, sessionId: 'another-session' }, 'req-other');
    assert.match(otherSession.input, /2026101215253008/);

    const observed = await observeDshToolResult(exec, result, dependencies);
    assert.equal(observed?.evaluation.decision.decision, 'allow');
    const observedSensitive = await observeDshToolResult(exec, {
      isError: false, content: [{ type: 'text', text: 'card_number: 5284917302468138' }],
    }, dependencies);
    assert.ok(observedSensitive);
    assert.equal(observedSensitive.evaluation.decision.decision, 'block');
    assert.equal(shouldReportAuditEventToCloud(observedSensitive.event), false);
    const blocked = await protectDshToolResult(exec, {
      isError: false, content: [{ type: 'text', text: 'card_number: 5284917302468138' }],
    }, dependencies);
    assert.equal(blocked?.evaluation.decision.decision, 'block');
    assert.equal(blocked?.evaluation.decision.riskScore, 100);
    assert.ok(blocked);
    assert.equal(shouldReportAuditEventToCloud(blocked.event), true);

    assert.equal(await protectDshToolResult({ ...exec, name: 'read_file' }, result, dependencies), null);
    assert.equal(await protectDshToolResult({ ...exec, name: 'image_query' }, result, dependencies), null);

    const preQuery = await protectDshToolCall({ ...exec, arguments: { query: '银行卡号 5284917302468138' } },
      dependencies);
    assert.equal(preQuery?.evaluation.decision.decision, 'block');

    const benignResultWithSensitiveQuery = await protectDshToolResult({
      ...exec, arguments: { query: 'price 5284917302468138' },
    }, { isError: false, content: [{ type: 'text', text: 'Bitcoin $1.00' }] }, dependencies);
    assert.equal(benignResultWithSensitiveQuery?.evaluation.decision.decision, 'allow');
    assert.equal(benignResultWithSensitiveQuery?.action.metadata?.publicSearchSensitive, false);

    const nestedSensitiveResult = await protectDshToolResult(exec, {
      isError: false, content: [{ type: 'text', text: JSON.stringify({ results: [{ id: '2026101215253008',
        customer: { payment: { pan: '5284917302468138' } } }] }) }],
    }, dependencies);
    assert.equal(nestedSensitiveResult?.evaluation.decision.decision, 'block');
  });

  it('keeps Hermes and OpenClaw model-request observers from reclassifying exact search results as user PII', async () => {
    resetPublicSearchProvenanceForTests();
    try {
      const root = mkdtempSync(join(tmpdir(), 'agentguard-search-provenance-'));
      const config: AgentGuardConfig = {
        version: 1, level: 'balanced', policyCachePath: join(root, 'policy.json'),
        auditPath: join(root, 'audit.jsonl'), eventSpoolPath: join(root, 'spool.jsonl'),
      };
      writeFileSync(config.policyCachePath, JSON.stringify(getDefaultEffectiveRuntimePolicy()));
      const publicText = JSON.stringify({ id: '2026101215253008' });
      for (const host of ['hermes', 'openclaw', 'qclaw'] as const) {
        const sessionId = `provenance-${host}`;
        const source = await protectAction({ config, agentHost: host, actionType: 'web_search',
          toolName: 'web_search', phase: 'post', rawInput: host === 'hermes'
            ? { hook_event_name: 'post_tool_call', tool_name: 'web_search',
              status: 'ok', session_id: sessionId, tool_input: { query: 'price' }, tool_response: { content: publicText } }
            : { toolName: 'web_search', session_id: sessionId,
              params: { query: 'price' }, result: { content: publicText } },
        });
        assert.equal(source, null, `${host}: routine allowed tool result may skip local audit`);
        const messages = [{ role: 'tool', name: 'web_search', content: publicText }];
        const observed = await protectAction({ config, agentHost: host, actionType: 'llm_request',
          toolName: host === 'hermes' ? 'hermes.pre_api_request' : 'openclaw.llm_input',
          auditSafe: true, rawInput: {
            session_id: sessionId,
            input: JSON.stringify(host === 'hermes' ? messages : { historyMessages: messages }),
            lifecycleStage: 'model_request', canBlockCurrentAction: false, coverageLevel: 'observe_only',
            missingFacts: ['final_destination', 'complete_payload'],
          },
        });
        assert.ok(observed);
        assert.match(observed.event.input, /PUBLIC_SEARCH_NUMBER/);
        assert.ok(!observed.decision.reasons.some((reason) => reason.title.includes('Bank account exposure')), host);
        assert.equal(shouldReportAuditEventToCloud(observed.event), false);

        const privateUser = await protectAction({ config, agentHost: host, actionType: 'llm_request',
          toolName: host === 'hermes' ? 'hermes.pre_api_request' : 'openclaw.llm_input',
          auditSafe: true, rawInput: {
            session_id: sessionId,
            input: JSON.stringify({ messages: [{ role: 'user', content: publicText }] }),
            lifecycleStage: 'model_request', canBlockCurrentAction: false, coverageLevel: 'observe_only',
          },
        });
        assert.match(privateUser?.event.input ?? '', /2026101215253008/, `${host}:user result must not be exempt`);
      }
    } finally {
      resetPublicSearchProvenanceForTests();
    }
  });
});
