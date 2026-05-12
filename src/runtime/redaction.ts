import type { PolicyReason } from './types.js';

const REDACTED = '[REDACTED]';

const SECRET_VALUE_PATTERN =
  /(?:token|api[_-]?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret)=([^&\s'"`]+)/gi;
const SENSITIVE_KEY_PATTERN =
  /(?:token|api[_-]?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret|signature|sig)/i;

const REDACTION_PATTERNS: Array<[RegExp, (match: string) => string]> = [
  [/\bag_live_[A-Za-z0-9_-]{12,}\b/g, () => REDACTED],
  [/\bsk-or-v1-[A-Za-z0-9_-]{12,}\b/g, () => REDACTED],
  [/\bsk-[A-Za-z0-9_-]{12,}\b/g, () => REDACTED],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b/gi, () => `Bearer ${REDACTED}`],
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    () => REDACTED,
  ],
  [
    SECRET_VALUE_PATTERN,
    (match) => {
      const [key] = match.split('=');
      return `${key}=${REDACTED}`;
    },
  ],
];

export function redactText(value: unknown): string {
  let redacted = String(value ?? '');
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
