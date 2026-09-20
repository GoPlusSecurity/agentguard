import { classifyLlmEndpoint } from './llm-endpoints.js';
import { detectPiiCategories } from '../scanner/rules/privacy.js';
import type {
  CloudPolicyDecision,
  CoverageLevel,
  EffectiveRuntimePolicy,
  LlmEndpointTier,
  MissingLlmFact,
  PolicyReason,
  RuntimePiiSummary,
  RuntimeAction,
  RuntimePrivacyRuleEvaluation,
  RuntimeSeverity,
} from './types.js';

export interface RuntimePrivacyEvaluation {
  reasons: PolicyReason[];
  rules: RuntimePrivacyRuleEvaluation[];
  coverageLevel: CoverageLevel;
  missingFacts: MissingLlmFact[];
  counts: {
    bodyBytes: number;
    payloadBytes?: number;
    attachmentBytes?: number;
    filePathCount?: number;
    piiCategoryCount: number;
    piiValueCount: number;
  };
  piiSummary: RuntimePiiSummary;
}

export function evaluateLlmPrivacy(policy: EffectiveRuntimePolicy, action: RuntimeAction): RuntimePrivacyEvaluation {
  const reasons: PolicyReason[] = [];
  const rules: RuntimePrivacyRuleEvaluation[] = [];
  const input = action.input || '';
  const endpointTier = endpointTierFor(policy, action);
  const destinationMissing = !action.llm?.destination?.host || endpointTier === 'unknown';
  const declaredMissing = new Set(action.missingFacts ?? []);
  const pii = detectPiiCategories(input).filter((item) => policy.privacy.enabledCategories.includes(item.category));

  if (action.actionType === 'llm_request') {
    evaluateEndpointRule(policy, endpointTier, destinationMissing, reasons, rules);
    evaluatePiiRule(policy, endpointTier, declaredMissing, pii, reasons, rules);
    evaluateCredentialRule(endpointTier, destinationMissing, action, reasons, rules);
    evaluateBulkRule(policy, endpointTier, action, reasons, rules);
  }
  if (action.actionType === 'shell' || action.actionType === 'file_write') {
    evaluateHijackRule(policy, action, reasons, rules);
  }
  if (action.actionType === 'llm_response') {
    evaluateResponseRule(endpointTier, destinationMissing, declaredMissing, action, reasons, rules);
  }

  const missingFacts = uniqueMissingFacts(rules.flatMap((rule) => rule.missingFacts));
  const piiSummary = summarizePii(pii);
  return {
    reasons,
    rules,
    coverageLevel: combinedCoverage(rules),
    missingFacts,
    counts: {
      bodyBytes: Buffer.byteLength(input, 'utf8'),
      payloadBytes: action.llm?.payloadBytes,
      attachmentBytes: action.llm?.attachmentBytes,
      filePathCount: action.llm?.filePathCount ?? metadataFilePathCount(action),
      piiCategoryCount: piiSummary.categories.length,
      piiValueCount: piiSummary.valueCount,
    },
    piiSummary,
  };
}

function summarizePii(pii: ReturnType<typeof detectPiiCategories>): RuntimePiiSummary {
  const counts = new Map<RuntimePiiSummary['categories'][number]['category'], number>();
  for (const item of pii) counts.set(item.category, (counts.get(item.category) ?? 0) + item.count);
  return {
    categories: [...counts.entries()]
      .map(([category, count]) => ({ category, count }))
      .sort((left, right) => left.category.localeCompare(right.category)),
    valueCount: [...counts.values()].reduce((total, count) => total + count, 0),
  };
}

function evaluateEndpointRule(
  policy: EffectiveRuntimePolicy,
  tier: LlmEndpointTier,
  missing: boolean,
  reasons: PolicyReason[],
  rules: RuntimePrivacyRuleEvaluation[],
): void {
  if (missing) {
    reasons.push(privacyReason(
      'UNTRUSTED_LLM_ENDPOINT', 'medium', 'Final LLM destination unavailable',
      'The host did not expose the final model destination, so endpoint trust cannot be determined.',
      'missing=final_destination',
    ));
    rules.push(ruleResult('UNTRUSTED_LLM_ENDPOINT', 'unsupported', ['final_destination'], false, 'warn'));
    return;
  }
  const detected = tier === 'T3' || tier === 'T4';
  if (detected) {
    reasons.push(privacyReason(
      'UNTRUSTED_LLM_ENDPOINT', tier === 'T4' ? 'critical' : 'high', 'Untrusted LLM endpoint',
      'The final model destination is unknown, self-hosted, relayed, or high risk.', `endpointTier=${tier}`,
    ));
  }
  rules.push(ruleResult(
    'UNTRUSTED_LLM_ENDPOINT', 'full', [], detected,
    tier === 'T4' ? 'block' : tier === 'T3' ? policy.network.untrustedLlmEndpoint : 'allow',
  ));
}

function evaluatePiiRule(
  policy: EffectiveRuntimePolicy,
  tier: LlmEndpointTier,
  declaredMissing: Set<MissingLlmFact>,
  pii: ReturnType<typeof detectPiiCategories>,
  reasons: PolicyReason[],
  rules: RuntimePrivacyRuleEvaluation[],
): void {
  const incomplete = declaredMissing.has('complete_payload');
  const missingFacts: MissingLlmFact[] = incomplete ? ['complete_payload'] : [];
  const detected = pii.length > 0;
  if (detected) {
    const count = pii.reduce((total, item) => total + item.count, 0);
    reasons.push(privacyReason(
      'PII_EGRESS', tier === 'T4' ? 'critical' : tier === 'T3' ? 'high' : 'medium',
      'Personal data in visible LLM payload', 'The locally visible model payload contains labeled personal data.',
      `categories=${pii.map((item) => item.category).join(',')};count=${count};masked=[REDACTED:PII]`,
    ));
  } else if (incomplete) {
    reasons.push(privacyReason(
      'PII_EGRESS', 'medium', 'LLM payload visibility incomplete',
      'No PII was found in the visible fragment, but the host did not expose the complete payload.',
      'missing=complete_payload',
    ));
  }
  rules.push(ruleResult(
    'PII_EGRESS', incomplete ? 'partial' : 'full', missingFacts, detected,
    detected ? piiDecision(policy, tier) : incomplete ? 'warn' : 'allow',
  ));
}

function evaluateCredentialRule(
  tier: LlmEndpointTier,
  destinationMissing: boolean,
  action: RuntimeAction,
  reasons: PolicyReason[],
  rules: RuntimePrivacyRuleEvaluation[],
): void {
  const missing: MissingLlmFact[] = [];
  if (destinationMissing) missing.push('final_destination');
  if (!action.llm || action.llm.credentialKind === 'unknown') missing.push('credential_kind');
  if (!action.llm || action.llm.credentialPresent === 'unknown') missing.push('credential_presence');
  if (missing.length > 0) {
    reasons.push(privacyReason(
      'LLM_KEY_TO_UNKNOWN_HOST', 'medium', 'Credential routing facts unavailable',
      'The destination and credential presence must both be visible before credential routing can be evaluated.',
      `missing=${missing.join(',')}`,
    ));
    rules.push(ruleResult('LLM_KEY_TO_UNKNOWN_HOST', 'unsupported', missing, false, 'warn'));
    return;
  }
  const detected = action.llm!.credentialPresent === true && (tier === 'T3' || tier === 'T4');
  if (detected) {
    reasons.push(privacyReason(
      'LLM_KEY_TO_UNKNOWN_HOST', 'critical', 'Model credential routed to an untrusted host',
      'A model credential is present on a request to an unknown or high-risk destination.',
      `credentialKind=${action.llm!.credentialKind};endpointTier=${tier}`,
    ));
  }
  rules.push(ruleResult('LLM_KEY_TO_UNKNOWN_HOST', 'full', [], detected, detected ? 'block' : 'allow'));
}

function evaluateBulkRule(
  policy: EffectiveRuntimePolicy,
  tier: LlmEndpointTier,
  action: RuntimeAction,
  reasons: PolicyReason[],
  rules: RuntimePrivacyRuleEvaluation[],
): void {
  const filePathCount = action.llm?.filePathCount ?? metadataFilePathCount(action);
  const missing: MissingLlmFact[] = [];
  if (action.llm?.payloadBytes === undefined) missing.push('exact_payload_bytes');
  if (action.llm?.attachmentBytes === undefined) missing.push('attachment_bytes');
  if (filePathCount === undefined) missing.push('file_path_count');
  const bulkPayload = action.llm?.payloadBytes !== undefined && filePathCount !== undefined
    && action.llm.payloadBytes >= policy.privacy.bulkEgressBytes
    && filePathCount >= policy.privacy.bulkFilePathCount;
  const bulkAttachment = action.llm?.attachmentBytes !== undefined
    && action.llm.attachmentBytes >= policy.privacy.bulkAttachmentBytes;
  const detected = bulkPayload || bulkAttachment;
  if (detected) {
    reasons.push(privacyReason(
      'WORKSPACE_BULK_EGRESS', tier === 'T4' ? 'critical' : tier === 'T3' ? 'high' : 'medium',
      'Bulk workspace data in LLM request', 'The request crosses the configured payload/file or attachment threshold.',
      `payloadBytes=${action.llm?.payloadBytes ?? 'unknown'};attachmentBytes=${action.llm?.attachmentBytes ?? 'unknown'};filePathCount=${filePathCount ?? 'unknown'}`,
    ));
  } else if (missing.length > 0) {
    reasons.push(privacyReason(
      'WORKSPACE_BULK_EGRESS', 'medium', 'Bulk egress facts incomplete',
      'Exact payload, attachment, or file-count facts are unavailable, so bulk egress cannot be ruled out.',
      `missing=${missing.join(',')}`,
    ));
  }
  rules.push(ruleResult(
    'WORKSPACE_BULK_EGRESS', missing.length > 0 ? 'partial' : 'full', missing, detected,
    detected ? bulkDecision(tier) : missing.length > 0 ? 'warn' : 'allow',
  ));
}

function evaluateHijackRule(
  policy: EffectiveRuntimePolicy,
  action: RuntimeAction,
  reasons: PolicyReason[],
  rules: RuntimePrivacyRuleEvaluation[],
): void {
  const assignment = /(?:OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|GEMINI_BASE_URL|GOOGLE_GEMINI_BASE_URL|LLM_BASE_URL|MODEL_BASE_URL|baseURL|base_url|api_base)\s*["']?\s*[:=]\s*["']?(https?:\/\/[^\s"'`,}]+)/i;
  const match = action.input.match(assignment);
  if (!match) {
    rules.push(ruleResult('LLM_ENDPOINT_HIJACK', 'partial', [], false, 'allow'));
    return;
  }
  const classification = classifyLlmEndpoint(match[1], {
    trustedEndpoints: policy.network.trustedLlmEndpoints,
    blockedDomains: policy.network.blockedDomains,
  });
  const detected = classification.tier === 'T3' || classification.tier === 'T4';
  if (detected) {
    reasons.push(privacyReason(
      'LLM_ENDPOINT_HIJACK', classification.tier === 'T4' ? 'critical' : 'high',
      'LLM endpoint configuration hijack',
      'A blocking tool action attempts to change an LLM endpoint to an unknown or high-risk destination.',
      `endpointTier=${classification.tier}`,
    ));
  }
  rules.push(ruleResult(
    'LLM_ENDPOINT_HIJACK', 'partial', [], detected,
    detected ? classification.tier === 'T4' ? 'block' : 'require_approval' : 'allow',
  ));
}

function evaluateResponseRule(
  tier: LlmEndpointTier,
  destinationMissing: boolean,
  declaredMissing: Set<MissingLlmFact>,
  action: RuntimeAction,
  reasons: PolicyReason[],
  rules: RuntimePrivacyRuleEvaluation[],
): void {
  const missing: MissingLlmFact[] = [];
  if (destinationMissing) missing.push('response_source');
  if (declaredMissing.has('complete_response')) missing.push('complete_response');
  const suspicious = hasSuspiciousResponseAction(action.input);
  if (suspicious) {
    reasons.push(privacyReason(
      'RELAY_RESPONSE_TAMPERING', tier === 'T3' || tier === 'T4' ? 'high' : 'medium',
      'Suspicious action in relay response',
      'The visible model response contains a tool call, command, or package-install pattern requiring local review.',
      'signals=tool_or_command',
    ));
  } else if (missing.length > 0) {
    reasons.push(privacyReason(
      'RELAY_RESPONSE_TAMPERING', 'medium', 'Model response integrity visibility incomplete',
      'The host did not expose the complete response or its final source.', `missing=${missing.join(',')}`,
    ));
  }
  rules.push(ruleResult(
    'RELAY_RESPONSE_TAMPERING', missing.length > 0 ? (suspicious ? 'partial' : 'unsupported') : 'partial',
    missing, suspicious,
    suspicious ? (tier === 'T3' || tier === 'T4' ? 'require_approval' : 'warn') : missing.length > 0 ? 'warn' : 'allow',
  ));
}

function endpointTierFor(policy: EffectiveRuntimePolicy, action: RuntimeAction): LlmEndpointTier {
  const destination = action.llm?.destination;
  if (!destination?.host) return 'unknown';
  const host = destination.host.includes(':') && !destination.host.startsWith('[') ? `[${destination.host}]` : destination.host;
  const port = destination.port ? `:${destination.port}` : '';
  const path = destination.path?.startsWith('/') ? destination.path : `/${destination.path ?? ''}`;
  return classifyLlmEndpoint(`${destination.scheme ?? 'https'}://${host}${port}${path}`, {
    trustedEndpoints: policy.network.trustedLlmEndpoints,
    blockedDomains: policy.network.blockedDomains,
  }).tier;
}

function piiDecision(policy: EffectiveRuntimePolicy, tier: LlmEndpointTier): CloudPolicyDecision {
  if (tier === 'T0') return 'allow';
  if (tier === 'T1' || tier === 'T2') return policy.privacy.piiEgressTrusted;
  if (tier === 'T3') return policy.privacy.piiEgressUntrusted;
  if (tier === 'T4') return 'block';
  return 'warn';
}

function bulkDecision(tier: LlmEndpointTier): CloudPolicyDecision {
  if (tier === 'T4') return 'block';
  if (tier === 'T3') return 'require_approval';
  return 'warn';
}

function metadataFilePathCount(action: RuntimeAction): number | undefined {
  const paths = action.metadata?.filePaths;
  return Array.isArray(paths) ? paths.filter((item) => typeof item === 'string').length : undefined;
}

function hasSuspiciousResponseAction(value: string): boolean {
  const structured = /["'](?:tool_calls?|function_call|command|package)["']\s*:/i.test(value);
  const execution = /\b(?:curl|wget|bash|powershell|rm\s+-|npm\s+(?:install|exec)|pnpm\s+(?:add|dlx)|pip\s+install)\b/i.test(value);
  return structured && execution;
}

function privacyReason(
  code: PolicyReason['code'], severity: RuntimeSeverity, title: string, description: string, evidence: string,
): PolicyReason {
  return { code, severity, title, description, evidence };
}

function ruleResult(
  ruleId: RuntimePrivacyRuleEvaluation['ruleId'], coverageLevel: CoverageLevel,
  missingFacts: MissingLlmFact[], detected: boolean, decision: CloudPolicyDecision,
): RuntimePrivacyRuleEvaluation {
  return { ruleId, coverageLevel, missingFacts, detected, decision };
}

function uniqueMissingFacts(values: MissingLlmFact[]): MissingLlmFact[] {
  return [...new Set(values)];
}

function combinedCoverage(rules: RuntimePrivacyRuleEvaluation[]): CoverageLevel {
  if (rules.length === 0 || rules.every((rule) => rule.coverageLevel === 'unsupported')) return 'unsupported';
  if (rules.some((rule) => rule.coverageLevel !== 'full')) return 'partial';
  return 'full';
}
