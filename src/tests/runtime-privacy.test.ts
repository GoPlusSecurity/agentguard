import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { evaluateLocalAction } from '../runtime/evaluator.js';
import { evaluateLlmPrivacy } from '../runtime/privacy.js';
import { buildAuditEvent, writeAuditLog } from '../runtime/audit.js';
import { redactText } from '../runtime/redaction.js';
import { getDefaultEffectiveRuntimePolicy } from '../runtime/policy.js';
import { exitCodeForDecision, formatProtectResult, protectAction } from '../runtime/protect.js';
import type { AgentGuardConfig } from '../config.js';
import type { LlmEndpointTier, RuntimeAction, RuntimeAuditEvent } from '../runtime/types.js';

describe('Runtime LLM privacy evaluation', () => {
  it('maps visible PII through T0-T4 without auto-allowing medium-severity findings', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const expected = new Map<LlmEndpointTier, string>([
      ['T0', 'allow'],
      ['T1', 'warn'],
      ['T2', 'warn'],
      ['T3', 'require_approval'],
      ['T4', 'block'],
    ]);

    for (const [tier, decision] of expected) {
      const action = llmRequest(tier, 'personal_email="private.person@corp.invalid"');
      const result = await evaluateLocalAction(policy, action);
      assert.equal(result.decision, decision, tier);
      assert.ok(result.riskScore >= 20, tier);
      assert.ok(result.reasons.some((reason) => reason.code === 'PII_EGRESS'), tier);
    }
  });

  it('blocks a credential sent to T3/T4 even when the body has no PII', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    for (const tier of ['T3', 'T4'] as const) {
      const action = llmRequest(tier, '{"message":"hello"}');
      action.llm!.credentialKind = 'api_key';
      action.llm!.credentialPresent = true;
      const result = await evaluateLocalAction(policy, action);
      assert.equal(result.decision, 'block', tier);
      assert.ok(result.reasons.some((reason) => reason.code === 'LLM_KEY_TO_UNKNOWN_HOST'), tier);
    }
  });

  it('reports missing endpoint and credential facts as unsupported instead of allow', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const action = llmRequest('T1', '{"message":"hello"}');
    action.llm!.destination = undefined;
    action.llm!.credentialKind = 'unknown';
    action.llm!.credentialPresent = 'unknown';
    action.missingFacts = ['final_destination', 'credential_kind', 'credential_presence'];

    const privacy = evaluateLlmPrivacy(policy, action);
    assert.equal(privacy.rules.find((rule) => rule.ruleId === 'UNTRUSTED_LLM_ENDPOINT')?.coverageLevel, 'unsupported');
    assert.equal(privacy.rules.find((rule) => rule.ruleId === 'LLM_KEY_TO_UNKNOWN_HOST')?.coverageLevel, 'unsupported');
    assert.deepEqual(privacy.missingFacts.sort(), ['credential_kind', 'credential_presence', 'final_destination']);

    const result = await evaluateLocalAction(policy, action);
    assert.equal(result.decision, 'warn');
    assert.ok(result.reasons.some((reason) => reason.code === 'UNTRUSTED_LLM_ENDPOINT'));
    assert.ok(result.reasons.some((reason) => reason.code === 'LLM_KEY_TO_UNKNOWN_HOST'));
  });

  it('marks incomplete payload, bulk, and response visibility explicitly', () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const request = llmRequest('T1', '{"message":"visible fragment"}');
    request.missingFacts = ['complete_payload', 'exact_payload_bytes', 'attachment_bytes', 'file_path_count'];
    request.llm!.payloadBytes = undefined;
    request.llm!.attachmentBytes = undefined;
    request.llm!.filePathCount = undefined;
    const requestPrivacy = evaluateLlmPrivacy(policy, request);
    assert.equal(requestPrivacy.rules.find((rule) => rule.ruleId === 'PII_EGRESS')?.coverageLevel, 'partial');
    assert.equal(requestPrivacy.rules.find((rule) => rule.ruleId === 'WORKSPACE_BULK_EGRESS')?.coverageLevel, 'partial');

    const response: RuntimeAction = {
      ...request,
      actionType: 'llm_response',
      lifecycleStage: 'model_response',
      missingFacts: ['complete_response', 'response_source'],
      llm: { ...request.llm!, destination: undefined },
    };
    const responsePrivacy = evaluateLlmPrivacy(policy, response);
    assert.equal(responsePrivacy.rules[0].ruleId, 'RELAY_RESPONSE_TAMPERING');
    assert.equal(responsePrivacy.rules[0].coverageLevel, 'unsupported');
    assert.deepEqual(responsePrivacy.rules[0].missingFacts.sort(), ['complete_response', 'response_source']);
  });

  it('records observer block-class decisions as would_block without creating approval state', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-runtime-observer-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
      approvalStorePath: join(dir, 'approvals.json'),
    };
    const raw = llmRequest('T4', 'personal_email="private.person@corp.invalid"');
    raw.canBlockCurrentAction = false;

    const result = await protectAction({ config, rawInput: raw });
    assert.ok(result);
    assert.equal(result.decision.decision, 'block');
    assert.equal(result.event.enforcementStatus, 'would_block');
    assert.equal(result.approvalChannel, undefined);
    assert.equal(result.pendingApproval, undefined);
    assert.equal(exitCodeForDecision(result.decision, result), 0);
    assert.doesNotMatch(formatProtectResult(result), /BLOCKED by AgentGuard/);
    const formatted = JSON.parse(formatProtectResult(result, true));
    assert.equal(formatted.decision, 'warn');
    assert.equal(formatted.policyDecision, 'block');
    assert.equal(formatted.enforcementStatus, 'would_block');
  });

  it('preserves the raw block policy decision in observe mode', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    policy.mode = 'observe';
    const result = await evaluateLocalAction(policy, llmRequest('T4', 'personal_email="private.person@corp.invalid"'));

    assert.equal(result.decision, 'warn');
    assert.equal(result.policyDecision, 'block');
  });

  it('accepts snake_case credential presence from lifecycle integrations', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-runtime-snake-case-'));
    const config: AgentGuardConfig = {
      version: 1,
      level: 'balanced',
      policyCachePath: join(dir, 'policy.json'),
      auditPath: join(dir, 'audit.jsonl'),
      eventSpoolPath: join(dir, 'spool.jsonl'),
      approvalStorePath: join(dir, 'approvals.json'),
    };

    const result = await protectAction({
      config,
      rawInput: {
        session_id: 'sess_snake_case',
        action_type: 'llm_request',
        lifecycle_stage: 'model_request',
        can_block_current_action: true,
        llm_metadata: {
          request_id: 'req_snake_case',
          session_id: 'sess_snake_case',
          lifecycle_stage: 'model_request',
          can_block_current_action: true,
          purpose: 'conversation',
          destination: { scheme: 'https', host: 'relay.corp.invalid', tier: 'T3' },
          credential_kind: 'api_key',
          credential_present: true,
        },
      },
    });

    assert.ok(result);
    assert.equal(result.event.llm?.credentialPresent, true);
    assert.equal(result.decision.decision, 'block');
  });

  it('uses exact payload, attachment, and file-path facts for bulk egress', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const action = llmRequest('T3', '{"message":"bulk"}');
    action.llm!.payloadBytes = policy.privacy.bulkEgressBytes;
    action.llm!.filePathCount = policy.privacy.bulkFilePathCount;
    const result = await evaluateLocalAction(policy, action);
    assert.equal(result.decision, 'require_approval');
    assert.ok(result.reasons.some((reason) => reason.code === 'WORKSPACE_BULK_EGRESS'));

    const attachment = llmRequest('T4', '{"message":"attachment"}');
    attachment.llm!.attachmentBytes = policy.privacy.bulkAttachmentBytes;
    const blocked = await evaluateLocalAction(policy, attachment);
    assert.equal(blocked.decision, 'block');
    assert.ok(blocked.reasons.some((reason) => reason.code === 'WORKSPACE_BULK_EGRESS'));
  });

  it('detects endpoint hijacking and suspicious relay responses without raw evidence', async () => {
    const policy = getDefaultEffectiveRuntimePolicy();
    const hijack = await evaluateLocalAction(policy, {
      sessionId: 'sess_hijack',
      agentHost: 'codex',
      actionType: 'file_write',
      toolName: 'apply_patch',
      input: 'OPENAI_BASE_URL="https://relay.corp.invalid/v1"',
      lifecycleStage: 'pre_tool',
      canBlockCurrentAction: true,
      coverageLevel: 'partial',
    });
    assert.equal(hijack.decision, 'require_approval');
    assert.ok(hijack.reasons.some((reason) => reason.code === 'LLM_ENDPOINT_HIJACK'));

    const response: RuntimeAction = {
      ...llmRequest('T3', '{"tool_calls":[{"name":"shell","arguments":{"command":"npm install unknown-pkg"}}]}'),
      actionType: 'llm_response',
      lifecycleStage: 'model_response',
      canBlockCurrentAction: false,
    };
    const tamper = await evaluateLocalAction(policy, response);
    assert.equal(tamper.decision, 'require_approval');
    assert.ok(tamper.reasons.some((reason) => reason.code === 'RELAY_RESPONSE_TAMPERING'));
    assert.ok(!JSON.stringify(tamper.reasons).includes('unknown-pkg'));
  });

  it('keeps request and response correlation while excluding raw PII and credentials from audit', () => {
    const dir = mkdtempSync(join(tmpdir(), 'agentguard-runtime-privacy-'));
    const auditPath = join(dir, 'audit.jsonl');
    const rawPii = 'personal_email="private.person@corp.invalid"';
    const request = auditEvent({ ...llmRequest('T3', rawPii), actionId: 'act_req' });
    const response = auditEvent({
      ...llmRequest('T3', rawPii),
      actionType: 'llm_response',
      lifecycleStage: 'model_response',
      actionId: 'act_res',
    });

    writeAuditLog(auditPath, request);
    writeAuditLog(auditPath, response);
    const stored = readFileSync(auditPath, 'utf8');
    assert.ok(!stored.includes('private.person@corp.invalid'));
    assert.ok(!stored.includes('sk-live-never-persist'));
    assert.equal(stored.match(/"requestId":"req_shared"/g)?.length, 2);
    assert.equal(buildAuditEvent(request).input, '[LOCAL_ONLY_LLM_CONTENT]');
  });

  it('redacts every supported PII category from non-LLM previews', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'tests', 'fixtures', 'privacy', 'positive.json'), 'utf8');
    const redacted = redactText(source);

    for (const raw of [
      '11010519491231002X',
      '5284917302468138',
      '4f9a12bc83de77aa1099cc55ee661234',
      '"age": 12',
      'hypertension stage two',
      '31.230416',
      '+8613812345678',
      'private.person@corp.invalid',
      'person20@corp.invalid',
    ]) {
      assert.ok(!redacted.includes(raw), raw);
    }
    assert.match(redacted, /\[REDACTED:PII_/);
  });
});

function llmRequest(tier: LlmEndpointTier, input: string): RuntimeAction {
  return {
    sessionId: 'sess_privacy',
    agentHost: 'dsh',
    actionType: 'llm_request',
    toolName: 'llm/stream',
    input,
    lifecycleStage: 'model_request',
    canBlockCurrentAction: true,
    coverageLevel: 'full',
    missingFacts: [],
    llm: {
      schemaVersion: 1,
      requestId: 'req_shared',
      sessionId: 'sess_privacy',
      purpose: 'conversation',
      lifecycleStage: 'model_request',
      canBlockCurrentAction: true,
      destination: {
        scheme: tier === 'T0' ? 'http' : 'https',
        host: hostForTier(tier),
        path: '/v1/messages',
        tier,
      },
      credentialKind: 'none',
      credentialPresent: false,
      payloadBytes: Buffer.byteLength(input, 'utf8'),
      attachmentBytes: 0,
      messageCount: 1,
      filePathCount: 0,
    },
    metadata: { credential: 'sk-live-never-persist' },
  };
}

function hostForTier(tier: LlmEndpointTier): string {
  if (tier === 'T0') return '127.0.0.1';
  if (tier === 'T1') return 'api.openai.com';
  if (tier === 'T2') return 'openrouter.ai';
  if (tier === 'T4') return '203.0.113.9';
  return 'relay.corp.invalid';
}

function auditEvent(action: RuntimeAction & { actionId: string }): RuntimeAuditEvent {
  return {
    ...action,
    decision: 'warn',
    riskScore: 20,
    riskLevel: 'medium',
    reasons: [],
    policyVersion: 'runtime-local-v0.2',
  };
}
