import { randomBytes } from 'node:crypto';
import type { AgentGuardConfig } from '../config.js';
import { redactText } from './redaction.js';

const PUBLIC_KEY_EXAMPLE = 'TYPESAFE_API_KEY=<key>';
const SECRET_FIELD = /^(?:token|api[_-]?key|secret|password|passwd|authorization|access[_-]?key|client[_-]?secret|signature|sig|agentJwt)$/i;

/** Locally sanitize AgentGuard-owned results without masking the saved JWT binding link. */
export function redactAgentGuardSelfToolOutput(response: unknown, config: AgentGuardConfig): string {
  const safe = redactAgentGuardSelfToolValue(response, config);
  return typeof safe === 'string' ? safe : JSON.stringify(safe);
}

/** Preserve structured tool results so native hosts can accept the replacement. */
export function redactAgentGuardSelfToolValue(response: unknown, config: AgentGuardConfig): unknown {
  if (typeof response === 'string') return redactSelfText(response, config);
  if (typeof response === 'number') {
    const text = String(response);
    return redactText(text) === text ? response : '[REDACTED]';
  }
  if (Array.isArray(response)) return response.map((item) => redactAgentGuardSelfToolValue(item, config));
  if (response && typeof response === 'object') {
    return Object.fromEntries(Object.entries(response).map(([key, value]) => [
      key,
      SECRET_FIELD.test(key) && typeof value === 'string' && value !== '<key>'
        ? '[REDACTED]'
        : redactAgentGuardSelfToolValue(value, config),
    ]));
  }
  return response;
}

function redactSelfText(text: string, config: AgentGuardConfig): string {
  const trimmed = text.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(text) as unknown;
      if (parsed && typeof parsed === 'object') {
        const safe = redactAgentGuardSelfToolValue(parsed, config);
        return JSON.stringify(safe) === JSON.stringify(parsed) ? text : JSON.stringify(safe);
      }
    } catch { /* Plain text still receives the bounded text redactor. */ }
  }
  const activationUrl = config.agentJwt && config.agentRegisterUrl;
  const marker = randomMarker('AGENTGUARDLINK');
  const exampleMarker = randomMarker('AGENTGUARDEXAMPLE');
  const withExample = text.replaceAll(PUBLIC_KEY_EXAMPLE, exampleMarker);
  if (!activationUrl || activationUrl.length > 2048 || /[\x00-\x1f\x7f]/.test(activationUrl))
    return redactText(withExample).replaceAll(exampleMarker, PUBLIC_KEY_EXAMPLE);
  try {
    const url = new URL(activationUrl);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
      return redactText(withExample).replaceAll(exampleMarker, PUBLIC_KEY_EXAMPLE);
    }
    // The exact URL saved after registration is user-facing and must remain
    // clickable. A fresh per-call marker keeps every other credential subject
    // to normal redaction, even elsewhere in the same result.
    const protectedText = protectExactActivationUrl(withExample, activationUrl, marker);
    return redactText(protectedText).replaceAll(marker, activationUrl)
      .replaceAll(exampleMarker, PUBLIC_KEY_EXAMPLE);
  } catch {
    return redactText(withExample).replaceAll(exampleMarker, PUBLIC_KEY_EXAMPLE);
  }
}

/** Letters cannot accidentally match numeric PII rules during redaction. */
function randomMarker(prefix: string): string {
  const letters = Array.from(randomBytes(16), (byte) =>
    String.fromCharCode(65 + (byte >> 4), 65 + (byte & 15))).join('');
  return `${prefix}${letters}END`;
}

/** Protect only a complete occurrence of the saved URL, not a forged prefix. */
function protectExactActivationUrl(text: string, url: string, marker: string): string {
  let result = '';
  let cursor = 0;
  while (cursor < text.length) {
    const start = text.indexOf(url, cursor);
    if (start < 0) break;
    const end = start + url.length;
    const before = text[start - 1];
    const after = text[end];
    const startsAtBoundary = before === undefined || /[\s"'`(<\[{=:]/.test(before);
    const endsAtBoundary = after === undefined || /[\s"'`<>\])}]/.test(after)
      || /[.,;!?]/.test(after)
        && (text[end + 1] === undefined || /[\s"'`<>\])}]/.test(text[end + 1]!));
    result += text.slice(cursor, start) + (startsAtBoundary && endsAtBoundary ? marker : url);
    cursor = end;
  }
  return result + text.slice(cursor);
}
