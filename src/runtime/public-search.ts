import { createHash } from 'node:crypto';
import type { RuntimeAgentHost } from './types.js';
import { redactText } from './redaction.js';
import { redactTextPreservingActivationUrls } from './self-output.js';

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

// A plain `token` field is often the name of a cryptocurrency, not a credential.
const SENSITIVE_CREDENTIAL_FIELD = /^(?:api[_-]?key|access[_-]?(?:key|token)|authorization|bearer|password|passwd|secret(?:[_-]?key)?|private[_-]?key|client[_-]?secret)$/i;
// Only these *leaf values* in verified search results can be ambiguous numeric
// metadata. A parent field never exempts all of its descendants.
const SEARCH_NUMERIC_FIELDS = new Set([
  'id', 'result_id', 'resultid', 'search_id', 'searchid', 'search_result_id',
  'searchresultid', 'timestamp', 'time_stamp', 'created_at', 'updated_at',
  'createdat', 'updatedat', 'rank', 'ranking', 'status', 'status_code',
  'statuscode', 'price', 'token_price', 'tokenprice', 'market_price',
  'marketprice', 'market_cap', 'marketcap', 'volume', 'liquidity', 'rate',
  'block_number', 'blocknumber', 'block_height', 'blockheight', 'decimals',
]);
const SEARCH_TEXT_FIELDS = new Set(['content', 'text', 'output', 'body']);
const SEARCH_RESULT_FIELDS = new Set(['results', 'items', 'metadata']);
const BARE_LONG_NUMBER = /^\d{12,19}$/;

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

/** Only verified search text and exact numeric metadata leaves get the exception. */
export function redactPublicSearchResult(value: unknown): unknown {
  return redactSearchValue(value, true);
}

export function hasSensitivePublicSearchResult(value: unknown): boolean {
  return JSON.stringify(redactPublicSearchResult(value)) !== JSON.stringify(value);
}

function redactSearchText(text: string): string {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === 'object') {
      const redacted = redactSearchValue(parsed, true);
      // JSON.stringify would alter formatting and trigger a false security
      // finding even if nothing actually needed redaction.
      return JSON.stringify(parsed) === JSON.stringify(redacted) ? text : JSON.stringify(redacted);
    }
  } catch { /* Plain search text retains narrow local redaction. */ }
  return redactTextPreservingActivationUrls(text, { skipBareNumericIdentifiers: true });
}

function redactSearchValue(value: unknown, searchResult: boolean, searchText = false): unknown {
  if (typeof value === 'string') return searchText ? redactSearchText(value)
    : redactTextPreservingActivationUrls(value);
  if (Array.isArray(value)) return value.map((item) => redactSearchValue(item, searchResult, searchText));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => [key,
      SENSITIVE_CREDENTIAL_FIELD.test(key) && typeof item === 'string' && item.length >= 8
        ? '[REDACTED]'
        : searchResult && SEARCH_NUMERIC_FIELDS.has(key.toLowerCase())
          && typeof item === 'string' && BARE_LONG_NUMBER.test(item)
          ? redactText(item, { skipBareNumericIdentifiers: true })
          : searchResult && SEARCH_TEXT_FIELDS.has(key.toLowerCase())
            && (typeof item === 'string' || Array.isArray(item))
            ? redactSearchValue(item, true, true)
            : redactSearchValue(item, searchResult && SEARCH_RESULT_FIELDS.has(key.toLowerCase())),
    ]));
}
