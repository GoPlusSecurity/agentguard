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
  const activationUrl = config.agentJwt && config.agentRegisterUrl;
  const marker = `AGENTGUARDLINK${randomBytes(16).toString('hex')}END`;
  const exampleMarker = `AGENTGUARDEXAMPLE${randomBytes(16).toString('hex')}END`;
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
    const protectedText = withExample.replace(/https?:\/\/[^\s\"'`<>\\]+/gi, (candidate) =>
      candidate === activationUrl ? marker : candidate);
    return redactText(protectedText).replaceAll(marker, activationUrl)
      .replaceAll(exampleMarker, PUBLIC_KEY_EXAMPLE);
  } catch {
    return redactText(withExample).replaceAll(exampleMarker, PUBLIC_KEY_EXAMPLE);
  }
}
