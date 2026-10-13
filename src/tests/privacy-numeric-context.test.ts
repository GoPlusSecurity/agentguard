import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extractCandidates } from '../privacy/candidates.js';
import { chunkLocator, splitChunks } from '../privacy/chunks.js';
import { redactText, summarizeSensitiveData } from '../runtime/redaction.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { formatProtectResult, protectAction } from '../runtime/protect.js';
import type { AgentGuardConfig } from '../config.js';

const candidatesOf = (text: string) => {
  const chunks = splitChunks(text);
  return extractCandidates(text, chunkLocator(chunks));
};

describe('Numeric PII context', () => {
  it('preserves coin prices and WebSearch technical IDs, even when their digits pass a checksum', () => {
    const technical = [
      '{"price":"0.110105199001010002"}', // Valid ID checksum inside a fractional price.
      '{"price":"0.1234567890123452"}', // Luhn-valid fractional price.
      '{"timestamp":"1700000000000001"}',
      '{"id":"2026101215253008"}',
      '{"searchResultId":"2026101215253008"}',
      '{"rank":"1234567890123452"}',
      '{"status_code":"0101010101010103"}',
      '{"statusCode":"0101010101010103"}',
      '{"block_number":"0000000000000018"}',
      '{"tokenPrice":"0.1234567890123452"}',
      'price: 1234567890123452',
      '1234567890123452.50',
      JSON.stringify({ content: JSON.stringify({ id: '2026101215253008', timestamp: '1700000000000001' }) }),
    ];
    for (const text of technical) {
      assert.equal(redactText(text), text, text);
      assert.deepEqual(summarizeSensitiveData(text), [], text);
      assert.deepEqual(candidatesOf(text), [], text);
    }
  });

  it('still protects labeled and bare real identifiers, including labels next to technical fields', () => {
    for (const [text, category] of [
      ['{"card_number":"5284917302468138"}', 'bank_account'],
      ['{"national_id":"11010519491231002X"}', 'national_id'],
      ['5284917302468138', 'bank_account'],
      ['11010519491231002X', 'national_id'],
      ['id: 110105199001010002', 'national_id'],
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
    const output = JSON.parse(formatProtectResult(postTool));
    assert.equal(output.hookSpecificOutput.updatedToolOutput.content, content);

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
    assert.doesNotMatch(formatProtectResult(batch), /"decision":"block"/);
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
  });
});
