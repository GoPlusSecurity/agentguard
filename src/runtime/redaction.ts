import type { LlmEgressRequestMetadata, PolicyReason } from './types.js';
import { redactPiiText } from '../scanner/rules/privacy.js';

const REDACTED = '[REDACTED]';

const SECRET_VALUE_PATTERN =
  /(?:token|api[_-]?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret)=([^&\s'"`]+)/gi;
/**
 * The same secret keys in YAML/JSON form, where the separator is `:`.
 *
 * Quotes and a minimum length are required so that ordinary prose such as
 * `authorization: required` is left alone; only a quoted value long enough to
 * be a credential is redacted.
 */
const SECRET_COLON_PATTERN =
  /((?:token|api[_-]?key|secret[_-]?(?:access[_-]?)?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret)["']?\s*:\s*)["'][^"'\s]{8,}["']/gi;
const SENSITIVE_KEY_PATTERN =
  /(?:token|api[_-]?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret|signature|sig)/i;

/**
 * Prose identifiers the field-anchored rules do not reach.
 *
 * Deliberately narrow. Redaction is destructive and runs over audit logs, so a
 * false positive here silently deletes operational evidence. Only shapes that
 * are specific enough to be unambiguous are listed: a bare 15-19 digit run, for
 * instance, is left alone because build ids and timestamps share it.
 */
const PROSE_PII_PATTERNS: Array<[RegExp, (match: string) => string]> = [
  // Area 000/666/9xx, group 00 and serial 0000 are never issued, so excluding
  // them keeps ordinary dashed number triples (durations, part numbers) intact.
  [/(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g, () => '[REDACTED:PII_NATIONAL_ID]'],
  [
    /[\u4e00-\u9fa5]{2,10}(?:省|市|区|县|镇|街道|路|街|巷)[\u4e00-\u9fa5\d]{0,20}(?:\d+号院?|\d+号楼|\d+室|\d+单元)[\u4e00-\u9fa5\d]{0,10}/g,
    () => '[REDACTED:PII_LOCATION_TRACE]',
  ],
];

const REDACTION_PATTERNS: Array<[RegExp, (match: string) => string]> = [
  [/\bag_live_[A-Za-z0-9_-]{12,}\b/g, () => REDACTED],
  [/\bsk-or-v1-[A-Za-z0-9_-]{12,}\b/g, () => REDACTED],
  [/\bsk-[A-Za-z0-9_-]{12,}\b/g, () => REDACTED],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/gi, () => `Bearer ${REDACTED}`],
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    () => REDACTED,
  ],
  [SECRET_COLON_PATTERN, (match) => `${match.split(':')[0]}: ${REDACTED}`],
  [
    SECRET_VALUE_PATTERN,
    (match) => {
      const [key] = match.split('=');
      return `${key}=${REDACTED}`;
    },
  ],
];

export function redactText(value: unknown): string {
  let redacted = redactPiiText(String(value ?? ''));
  for (const [pattern, replacement] of PROSE_PII_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  for (const [pattern, replacement] of REDACTION_PATTERNS) {
    redacted = redacted.replace(pattern, replacement);
  }
  return redactUrlSecrets(redacted);
}

export function redactPreview(value: unknown, maxLength = 2000): string {
  return redactText(value).slice(0, maxLength);
}

export function redactReasons(reasons: PolicyReason[]): PolicyReason[] {
  return reasons.map((reason) => ({
    ...reason,
    code: redactPreview(reason.code, 120),
    title: redactPreview(reason.title, 240),
    description: redactPreview(reason.description, 500),
    evidence: reason.evidence ? redactPreview(reason.evidence, 240) : reason.evidence,
    remediation: reason.remediation ? redactPreview(reason.remediation, 500) : reason.remediation,
  }));
}

export function redactMetadata(
  value: Record<string, unknown> | undefined,
  maxKeys = 25
): Record<string, unknown> {
  if (!value) return {};
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value).slice(0, maxKeys)) {
    result[redactPreview(key, 120)] = SENSITIVE_KEY_PATTERN.test(key)
      ? REDACTED
      : redactUnknown(item, 0);
  }
  return result;
}

/** Keep only the bounded, non-secret facts defined by the LLM egress contract. */
export function redactLlmMetadata(value: LlmEgressRequestMetadata): LlmEgressRequestMetadata {
  return {
    schemaVersion: 1,
    requestId: redactPreview(value.requestId, 160),
    parentRequestId: value.parentRequestId ? redactPreview(value.parentRequestId, 160) : undefined,
    sessionId: redactPreview(value.sessionId, 160),
    purpose: value.purpose,
    lifecycleStage: value.lifecycleStage,
    canBlockCurrentAction: value.canBlockCurrentAction,
    provider: value.provider ? redactPreview(value.provider, 160) : undefined,
    model: value.model ? redactPreview(value.model, 160) : undefined,
    apiMode: value.apiMode ? redactPreview(value.apiMode, 120) : undefined,
    attempt: boundedInteger(value.attempt),
    isRetry: value.isRetry,
    isFallback: value.isFallback,
    destination: value.destination
      ? {
          scheme: value.destination.scheme ? redactPreview(value.destination.scheme, 24) : undefined,
          host: value.destination.host ? redactPreview(value.destination.host, 253) : undefined,
          port: boundedInteger(value.destination.port),
          path: value.destination.path ? redactPreview(value.destination.path, 500) : undefined,
          service: value.destination.service ? redactPreview(value.destination.service, 120) : undefined,
          region: value.destination.region ? redactPreview(value.destination.region, 120) : undefined,
          tier: value.destination.tier,
        }
      : undefined,
    credentialKind: value.credentialKind,
    credentialPresent: value.credentialPresent,
    payloadBytes: boundedInteger(value.payloadBytes),
    attachmentBytes: boundedInteger(value.attachmentBytes),
    messageCount: boundedInteger(value.messageCount),
    filePathCount: boundedInteger(value.filePathCount),
  };
}

function boundedInteger(value: number | undefined): number | undefined {
  if (value === undefined || !Number.isSafeInteger(value) || value < 0) return undefined;
  return value;
}

function redactUnknown(value: unknown, depth: number): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactPreview(value, 500);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    if (depth >= 2) return '[REDACTED_OBJECT]';
    return value.slice(0, 25).map((item) => redactUnknown(item, depth + 1));
  }
  if (typeof value === 'object') {
    if (depth >= 2) return '[REDACTED_OBJECT]';
    const result: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 25)) {
      result[redactPreview(key, 120)] = SENSITIVE_KEY_PATTERN.test(key)
        ? REDACTED
        : redactUnknown(item, depth + 1);
    }
    return result;
  }
  return redactPreview(String(value), 500);
}

function redactUrlSecrets(value: string): string {
  return value.replace(/https?:\/\/[^\s'"`<>]+/gi, (rawUrl) => {
    try {
      const url = new URL(rawUrl);
      for (const key of [...url.searchParams.keys()]) {
        if (SENSITIVE_KEY_PATTERN.test(key)) {
          url.searchParams.set(key, REDACTED);
        }
      }
      if (url.username) url.username = REDACTED;
      if (url.password) url.password = REDACTED;
      return url.toString();
    } catch {
      return rawUrl;
    }
  });
}
