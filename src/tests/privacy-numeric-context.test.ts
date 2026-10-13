import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extractCandidates } from '../privacy/candidates.js';
import { chunkLocator, splitChunks } from '../privacy/chunks.js';
import { AgentGuardCloudClient } from '../cloud/client.js';
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
});
