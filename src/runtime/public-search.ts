import { createHash } from 'node:crypto';
import type { RuntimeAgentHost } from './types.js';
import { redactText } from './redaction.js';

/** Exact, host-owned search tools only. A name containing "search" is not provenance. */
export function isNativePublicSearchTool(host: RuntimeAgentHost, toolName: string): boolean {
  if (host === 'claude-code') return toolName === 'WebSearch';
  if (host === 'codex') return toolName === 'WebSearch' || toolName === 'web_search';
  if (host === 'openclaw' || host === 'qclaw' || host === 'hermes') return toolName === 'web_search';
  if (host === 'dsh') return toolName === 'web_search' || toolName === 'search_query';
  return false;
}

/** A tool result must be present, not merely a search query or a tool name. */
export function isVisiblePublicSearchResult(value: unknown): boolean {
  if (typeof value === 'string') return value.length > 0;
  if (Array.isArray(value)) return value.length > 0;
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return ['content', 'text', 'results', 'items', 'output', 'body'].some((key) =>
    typeof record[key] === 'string' || Array.isArray(record[key]));
}

const SENSITIVE_IDENTIFIER_FIELD = /(?:card.?number|credit.?card|debit.?card|bank.?account|national.?id|identity.?number|passport|ssn|身份证|银行卡)/i;
// A plain `token` field is often the name of a cryptocurrency, not a credential.
const SENSITIVE_CREDENTIAL_FIELD = /^(?:api[_-]?key|access[_-]?(?:key|token)|authorization|bearer|password|passwd|secret(?:[_-]?key)?|private[_-]?key|client[_-]?secret)$/i;

const RESULT_TTL_MS = 10 * 60_000;
const MAX_SESSIONS = 256;
const MAX_RESULTS_PER_SESSION = 32;
const MAX_TEXT_CHARS = 64 * 1024;
const recentResults = new Map<string, Array<{ digest: string; expiresAt: number }>>();

/** Remember hashes only; raw public-search result bodies never enter this cache. */
export function rememberPublicSearchResult(host: RuntimeAgentHost, sessionId: string, result: unknown): void {
  if (!sessionId) return;
  const key = `${host}\0${sessionId}`;
  const now = Date.now();
  const entries = (recentResults.get(key) ?? []).filter((item) => item.expiresAt > now);
  for (const text of resultTexts(result)) {
    if (text.length === 0 || text.length > MAX_TEXT_CHARS) continue;
    const digest = textDigest(text);
    if (!entries.some((item) => item.digest === digest)) {
      entries.push({ digest, expiresAt: now + RESULT_TTL_MS });
    }
  }
  if (entries.length === 0) return;
  if (!recentResults.has(key) && recentResults.size >= MAX_SESSIONS) {
    recentResults.delete(recentResults.keys().next().value!);
  }
  recentResults.set(key, entries.slice(-MAX_RESULTS_PER_SESSION));
}

/** Only exact, same-session tool-result text may bypass bare-number heuristics. */
export function inspectWithPublicSearchProvenance(
  host: RuntimeAgentHost, sessionId: string, value: unknown,
): { value: unknown; suppressed: number } {
  const entries = recentResults.get(`${host}\0${sessionId}`)?.filter((item) => item.expiresAt > Date.now()) ?? [];
  if (entries.length === 0) return { value, suppressed: 0 };
  const digests = new Set(entries.map((item) => item.digest));
  let suppressed = 0;
  const mask = (text: string): string => {
    if (text.length > MAX_TEXT_CHARS || !digests.has(textDigest(text))) return text;
    const replaced = text.replace(/(?<!\d)\d{12,19}(?!\d)/g, '[PUBLIC_SEARCH_NUMBER]');
    if (replaced !== text) suppressed++;
    return replaced;
  };
  const visit = (current: unknown, inToolResult = false): unknown => {
    if (Array.isArray(current)) return current.map((item) => visit(item, inToolResult));
    if (!current || typeof current !== 'object') return current;
    const record = current as Record<string, unknown>;
    if (record.type === 'tool-result' && Array.isArray(record.content)) {
      return { ...record, content: visit(record.content, true) };
    }
    if (record.role === 'tool' && 'content' in record) {
      return { ...record, content: typeof record.content === 'string'
        ? mask(record.content) : visit(record.content, true) };
    }
    if (inToolResult && record.type === 'text' && typeof record.text === 'string') {
      return { ...record, text: mask(record.text) };
    }
    return Object.fromEntries(Object.entries(record).map(([key, item]) => [key, visit(item, false)]));
  };
  return { value: visit(value), suppressed };
}

export function resetPublicSearchProvenanceForTests(): void {
  recentResults.clear();
}

function textDigest(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function resultTexts(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(resultTexts);
  if (!value || typeof value !== 'object') return [];
  const record = value as Record<string, unknown>;
  const content = ['content', 'text', 'output', 'body', 'results', 'items', 'value']
    .flatMap((key) => resultTexts(record[key]));
  // Tool-result messages often contain the serialized object itself.
  if (isVisiblePublicSearchResult(value)) content.push(JSON.stringify(value));
  return content;
}

/** Skip only bare numeric identifiers in visible public-search output. */
export function redactPublicSearchResult(value: unknown): unknown {
  return redactStructured(value, true);
}

export function hasSensitivePublicSearchResult(value: unknown): boolean {
  return JSON.stringify(redactPublicSearchResult(value)) !== JSON.stringify(value);
}

function redactStructured(value: unknown, publicSearch: boolean): unknown {
  if (typeof value === 'string') return redactText(value, { skipBareNumericIdentifiers: publicSearch });
  if (Array.isArray(value)) return value.map((item) => redactStructured(item, publicSearch));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => [key,
      publicSearch && SENSITIVE_CREDENTIAL_FIELD.test(key) && typeof item === 'string' && item.length >= 8
        ? '[REDACTED]'
        : redactStructured(item, publicSearch && !SENSITIVE_IDENTIFIER_FIELD.test(key)),
    ]));
}
