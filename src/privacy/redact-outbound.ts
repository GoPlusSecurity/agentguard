import { redactText } from '../runtime/redaction.js';

/**
 * Characters of context kept on each side of a candidate span.
 *
 * A judgment needs enough surrounding text to tell a customer's address from a
 * company's, but not the whole sentence. Every extra character is data leaving
 * the machine, and the sentence a span sits in may carry entirely unrelated
 * secrets.
 */
export const CONTEXT_WINDOW_CHARS = 60;

/** Longest chunk sent for sentence-level judgment. */
export const MAX_OUTBOUND_CHUNK_CHARS = 400;

/**
 * Shapes that must never leave the machine, checked on the serialized payload.
 *
 * This is the last line of defence, not the first: contexts are narrowed and
 * redacted before reaching it. It exists because path-based exclusion cannot
 * cover a credential pasted into an ordinary note, and because a privacy
 * feature that exfiltrates credentials is worse than no feature.
 */
const FORBIDDEN_OUTBOUND = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bsk-(?:live|proj|ant|or-v1)?[-_]?[A-Za-z0-9_-]{16,}\b/,
  /\bag_live_[A-Za-z0-9_-]{12,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./,
  // Generic shape: a secret-looking key followed by a long opaque value, in
  // either `=` or `:` form. Catches vendor formats this list does not name.
  /(?:secret|password|passwd|token|api[_-]?key|access[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?[A-Za-z0-9/+=_-]{20,}/i,
];

/** Padding redacted around the emitted window so no secret is cut in half. */
const REDACTION_PADDING_CHARS = 240;

/**
 * Produce the bounded, redacted context sent alongside a candidate span.
 *
 * Order is load-bearing and was originally wrong: narrowing first can slice a
 * secret in half, and the redaction patterns — which need a closing quote or a
 * complete token — then fail to match the fragment that remains. So a generously
 * padded region is redacted first, and the emitted window is cut from text that
 * is already clean.
 */
export function outboundContext(source: string, start: number, end: number): string {
  const padFrom = Math.max(0, start - CONTEXT_WINDOW_CHARS - REDACTION_PADDING_CHARS);
  const padTo = Math.min(source.length, end + CONTEXT_WINDOW_CHARS + REDACTION_PADDING_CHARS);
  const redacted = redactText(source.slice(padFrom, padTo));

  // Redaction rewrites the text, so offsets shift. Locate the span by value in
  // the cleaned text; when it was itself redacted, fall back to the centre.
  const needle = source.slice(start, end);
  const located = redacted.indexOf(needle);
  const centre = located >= 0 ? located : Math.floor(redacted.length / 2);
  const from = Math.max(0, centre - CONTEXT_WINDOW_CHARS);
  const to = Math.min(redacted.length, centre + needle.length + CONTEXT_WINDOW_CHARS);

  const prefix = padFrom > 0 || from > 0 ? '…' : '';
  const suffix = padTo < source.length || to < redacted.length ? '…' : '';
  return `${prefix}${redacted.slice(from, to)}${suffix}`;
}

/** Redact and bound a sentence before it is sent for judgment. */
export function outboundChunk(text: string): string {
  return redactText(text).slice(0, MAX_OUTBOUND_CHUNK_CHARS);
}

/**
 * Reject a payload that still carries a credential shape.
 *
 * Returns the offending pattern index, or null when the payload is clean.
 * Callers must drop the request rather than send it: failing the scan is
 * recoverable, disclosing a key is not.
 */
export function findForbiddenOutbound(payload: string): number | null {
  for (const [index, pattern] of FORBIDDEN_OUTBOUND.entries()) {
    if (pattern.test(payload)) return index;
  }
  return null;
}

/**
 * Files that are credential stores rather than prose.
 *
 * Excluded from semantic analysis entirely: they hold no personal disclosure a
 * judge could usefully rule on, and every byte of them is sensitive.
 */
const CREDENTIAL_FILE_PATTERN =
  /(?:^|[\\/])(?:\.env[^\\/]*|\.netrc|\.npmrc|\.pypirc|credentials|authorized_keys|known_hosts|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?)$|\.(?:pem|key|p12|pfx|jks|keystore)$/i;

export function isCredentialStore(path: string): boolean {
  return CREDENTIAL_FILE_PATTERN.test(path);
}
