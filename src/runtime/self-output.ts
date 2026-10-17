import { randomBytes } from 'node:crypto';
import type { AgentGuardConfig } from '../config.js';
import { redactText } from './redaction.js';

const PUBLIC_KEY_EXAMPLES = ['TYPESAFE_API_KEY=<key>', 'AGENTGUARD_API_KEY=<your-key>'];
// The token charset deliberately stops at separators, so adjacent query
// parameters or prose cannot become part of the exempt span.
const ACTIVATION_URL = /https?:\/\/[^\s"'`<>()\[\]{}\\?,;!]+\/activate\?token=[A-Za-z0-9._~%+=-]+/g;
const ACTIVATION_INSPECTION_MARKER = '[AgentGuard activation URL excluded from inspection]';

/** Replace complete activation URLs in an inspection copy, never in the host's result. */
export function maskActivationUrlsForInspection(text: string): string {
  return replaceActivationUrls(text, () => ACTIVATION_INSPECTION_MARKER);
}

/** Keep activation links in a verified result while applying its normal redactor. */
export function redactTextPreservingActivationUrls(
  text: string, options?: Parameters<typeof redactText>[1],
): string {
  const links = new Map<string, string>();
  const protectedText = replaceActivationUrls(text, (url) => {
    const marker = randomMarker('AGENTGUARDLINK');
    links.set(marker, url);
    return marker;
  });
  return restoreLinks(redactText(protectedText, options), links);
}

/** Mask assistant display text while keeping activation links visible. */
export function redactTextPreservingSavedActivationUrl(text: string, config?: AgentGuardConfig): string {
  const activationUrl = config?.agentRegisterUrl;
  const examples = PUBLIC_KEY_EXAMPLES.map((example) => ({ example, marker: randomMarker('AGENTGUARDEXAMPLE') }));
  const withExamples = examples.reduce((value, { example, marker: replacement }) =>
    value.replaceAll(example, replacement), text);
  const restoreExamples = (value: string): string => examples.reduce((restored, { example, marker: replacement }) =>
    restored.replaceAll(replacement, example), value);
  const links = new Map<string, string>();
  let protectedText = replaceActivationUrls(withExamples, (url) => {
    const marker = randomMarker('AGENTGUARDLINK');
    links.set(marker, url);
    return marker;
  });
  if (!activationUrl || activationUrl.length > 2048 || /[\x00-\x1f\x7f]/.test(activationUrl))
    return restoreExamples(restoreLinks(redactText(protectedText), links));
  try {
    const url = new URL(activationUrl);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
      return restoreExamples(restoreLinks(redactText(protectedText), links));
    }
    const marker = randomMarker('AGENTGUARDLINK');
    protectedText = protectExactActivationUrl(protectedText, activationUrl, marker);
    links.set(marker, activationUrl);
    return restoreExamples(restoreLinks(redactText(protectedText), links));
  } catch {
    return restoreExamples(restoreLinks(redactText(protectedText), links));
  }
}

function restoreLinks(text: string, links: Map<string, string>): string {
  for (const [marker, url] of links) text = text.replaceAll(marker, url);
  return text;
}

function replaceActivationUrls(text: string, replacement: (url: string) => string): string {
  return text.replace(ACTIVATION_URL, (candidate, offset: number) => {
    const before = text[offset - 1];
    if (before !== undefined && /[A-Za-z0-9_/@]/.test(before)) return candidate;
    const url = candidate.replace(/\.+$/, '');
    if (url.length > 2048) return candidate;
    try {
      const parsed = new URL(url);
      if (!parsed.hostname || parsed.username || parsed.password || parsed.hash
          || !parsed.pathname.endsWith('/activate') || !parsed.search.startsWith('?token=')
          || [...parsed.searchParams.keys()].length !== 1 || !parsed.searchParams.get('token')) return candidate;
      return replacement(url) + candidate.slice(url.length);
    } catch {
      return candidate;
    }
  });
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
