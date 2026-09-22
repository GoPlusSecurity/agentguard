import type { PiiChunk } from './types.js';

/**
 * Sentence terminators for Chinese and English prose, plus hard line breaks.
 * Kept deliberately simple: chunk boundaries only need to be stable and
 * roughly sentence-sized, not linguistically correct.
 */
const TERMINATORS = /[。！？\n]|(?<=[.!?])\s+(?=[A-Z"'一-龥])/g;

export const DEFAULT_MAX_CHUNKS = 400;
export const MAX_CHUNK_CHARS = 1_000;

export interface SplitChunksOptions {
  maxChunks?: number;
}

/**
 * Split text into sentence-sized chunks, preserving absolute offsets.
 *
 * Chunks exist for PII that has no extractable span: "上周刚做完手术" carries
 * health information, yet no substring of it is the personal datum. Such text
 * can only be judged, redacted, or refused whole.
 */
export function splitChunks(text: string, options: SplitChunksOptions = {}): PiiChunk[] {
  const max = options.maxChunks ?? DEFAULT_MAX_CHUNKS;
  const chunks: PiiChunk[] = [];
  let cursor = 0;

  const pushChunk = (start: number, end: number): void => {
    const raw = text.slice(start, end);
    if (!raw.trim()) return;
    // Oversized segments (minified data, long log lines) are hard-split so one
    // pathological line cannot dominate the token budget.
    for (let offset = 0; offset < raw.length; offset += MAX_CHUNK_CHARS) {
      if (chunks.length >= max) return;
      const piece = raw.slice(offset, offset + MAX_CHUNK_CHARS);
      if (!piece.trim()) continue;
      chunks.push({ index: chunks.length, text: piece.trim(), start: start + offset, end: start + offset + piece.length });
    }
  };

  const pattern = new RegExp(TERMINATORS.source, TERMINATORS.flags);
  for (const match of text.matchAll(pattern)) {
    const end = (match.index ?? 0) + match[0].length;
    pushChunk(cursor, end);
    cursor = end;
    if (chunks.length >= max) break;
  }
  if (cursor < text.length) pushChunk(cursor, text.length);

  return chunks;
}

/** Build an offset lookup so candidates can name the chunk they belong to. */
export function chunkLocator(chunks: PiiChunk[]): (offset: number) => { index: number; text: string } {
  return (offset: number) => {
    for (const chunk of chunks) {
      if (offset >= chunk.start && offset < chunk.end) return { index: chunk.index, text: chunk.text };
    }
    const last = chunks.at(-1);
    return last ? { index: last.index, text: last.text } : { index: 0, text: '' };
  };
}
