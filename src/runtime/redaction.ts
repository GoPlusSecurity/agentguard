import type { PolicyReason } from './types.js';

const REDACTED = '[REDACTED]';

const SECRET_VALUE_PATTERN =
  /(?:token|api[_-]?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret)=([^&\s'"`]+)/gi;

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
    evidence: reason.evidence ? redactPreview(reason.evidence, 240) : reason.evidence,
  }));
}

function redactUrlSecrets(value: string): string {
  return value.replace(/https?:\/\/[^\s'"`<>]+/gi, (rawUrl) => {
    try {
      const url = new URL(rawUrl);
      for (const key of [...url.searchParams.keys()]) {
        if (/token|key|secret|password|passwd|auth|signature|sig/i.test(key)) {
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
