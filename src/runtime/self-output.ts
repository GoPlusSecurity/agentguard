import { randomBytes } from 'node:crypto';
import type { AgentGuardConfig } from '../config.js';
import { redactText } from './redaction.js';

/** Locally sanitize AgentGuard-owned results without masking the saved JWT binding link. */
export function redactAgentGuardSelfToolOutput(response: unknown, config: AgentGuardConfig): string {
  const text = typeof response === 'string' ? response : JSON.stringify(response);
  const activationUrl = config.agentJwt && config.agentRegisterUrl;
  if (!activationUrl || activationUrl.length > 2048 || /[\x00-\x1f\x7f]/.test(activationUrl)) {
    return redactText(text);
  }
  try {
    const url = new URL(activationUrl);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
      return redactText(text);
    }
    // The exact URL saved after registration is user-facing and must remain
    // clickable. A fresh per-call marker keeps every other credential subject
    // to normal redaction, even elsewhere in the same result.
    const marker = `AGENTGUARDLINK${randomBytes(16).toString('hex')}END`;
    const protectedText = text.replace(/https?:\/\/[^\s\"'`<>\\]+/gi, (candidate) =>
      candidate === activationUrl ? marker : candidate);
    return redactText(protectedText).replaceAll(marker, activationUrl);
  } catch {
    return redactText(text);
  }
}
