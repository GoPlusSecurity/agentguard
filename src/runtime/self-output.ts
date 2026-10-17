import { randomBytes } from 'node:crypto';
import type { AgentGuardConfig } from '../config.js';
import { redactText } from './redaction.js';

const PUBLIC_KEY_EXAMPLES = ['TYPESAFE_API_KEY=<key>', 'AGENTGUARD_API_KEY=<your-key>'];
/** Mask assistant display text while keeping the saved activation link visible. */
export function redactTextPreservingSavedActivationUrl(text: string, config: AgentGuardConfig): string {
  const activationUrl = config.agentRegisterUrl;
  const marker = randomMarker('AGENTGUARDLINK');
  const examples = PUBLIC_KEY_EXAMPLES.map((example) => ({ example, marker: randomMarker('AGENTGUARDEXAMPLE') }));
  const withExamples = examples.reduce((value, { example, marker: replacement }) =>
    value.replaceAll(example, replacement), text);
  const restoreExamples = (value: string): string => examples.reduce((restored, { example, marker: replacement }) =>
    restored.replaceAll(replacement, example), value);
  if (!activationUrl || activationUrl.length > 2048 || /[\x00-\x1f\x7f]/.test(activationUrl))
    return restoreExamples(redactText(withExamples));
  try {
    const url = new URL(activationUrl);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
      return restoreExamples(redactText(withExamples));
    }
    // The exact URL saved after registration is user-facing and must remain
    // clickable. A fresh per-call marker keeps every other credential subject
    // to normal redaction, even elsewhere in the same display message.
    const protectedText = protectExactActivationUrl(withExamples, activationUrl, marker);
    return restoreExamples(redactText(protectedText).replaceAll(marker, activationUrl));
  } catch {
    return restoreExamples(redactText(withExamples));
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
