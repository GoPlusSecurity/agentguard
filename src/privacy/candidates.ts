import type { PiiCategory } from '../runtime/types.js';
import type { PiiCandidate } from './types.js';

interface Extractor {
  kind: string;
  category: PiiCategory;
  pattern: RegExp;
  /** 1-based capture group holding the value; 0 means the whole match. */
  group?: number;
}

/**
 * Loose, recall-tuned extractors.
 *
 * These are deliberately imprecise: they over-find, and adjudication removes the
 * noise. Do NOT add precision here (checksums, field-name anchors) — that work
 * belongs to the deterministic scanner rules, and duplicating it would reinstate
 * the recall ceiling this layer exists to lift.
 *
 * Candidate coverage bounds the whole pipeline: a judge can only rule on spans
 * it is handed, so a value no extractor emits can never be found.
 */
const EXTRACTORS: Extractor[] = [
  // Mainland China resident ID: 18 digits with optional X check digit.
  { kind: 'national_id_cn', category: 'national_id', pattern: /(?<!\d)\d{17}[\dXx](?!\d)/g },
  // US SSN, written or bare.
  { kind: 'ssn_us', category: 'national_id', pattern: /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g },
  // Passport-shaped identifiers.
  { kind: 'passport', category: 'national_id', pattern: /\b[A-Z]{1,2}\d{7,9}\b/g },
  // Payment cards and long account numbers.
  { kind: 'account_number', category: 'bank_account', pattern: /(?<!\d)\d{15,19}(?!\d)/g },
  { kind: 'iban', category: 'bank_account', pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g },
  // Mainland China mobile and E.164.
  { kind: 'mobile_cn', category: 'phone_number', pattern: /(?<!\d)1[3-9]\d{9}(?!\d)/g },
  { kind: 'phone_e164', category: 'phone_number', pattern: /\+[1-9]\d{7,14}(?!\d)/g },
  { kind: 'phone_dashed', category: 'phone_number', pattern: /(?<![\d-])\d{3}-\d{3,4}-\d{4}(?![\d-])/g },
  { kind: 'email', category: 'email_address', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // Chinese street addresses, anchored on administrative and building nouns.
  {
    kind: 'address_cn',
    category: 'location_trace',
    pattern: /[一-龥]{2,10}(?:省|市|区|县|镇|街道|路|街|巷)[一-龥\d]{0,20}(?:\d+号院?|\d+号楼|\d+室|\d+单元)[一-龥\d]{0,10}/g,
  },
  // Coordinate pairs; a trace only matters in series, which the caller counts.
  { kind: 'coordinate', category: 'location_trace', pattern: /-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}/g },
  // Personal names introduced by a relational marker. Capture group 1 only:
  // matching the whole phrase yields fragments such as "同事是我们组的".
  {
    kind: 'person_cn',
    category: 'hardcoded_dataset',
    pattern: /(?:收件人|联系人|客户|患者|姓名|同事|员工|负责人)(?:是|叫|为|：|:)\s*([一-龥]{2,4})(?![一-龥])/g,
    group: 1,
  },
  { kind: 'person_en', category: 'hardcoded_dataset', pattern: /\b(?:Mr|Mrs|Ms|Dr)\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/g, group: 1 },
  // Base64 that decodes to a digit run long enough to be an identifier.
  { kind: 'base64_id', category: 'national_id', pattern: /\b[A-Za-z0-9+/]{16,}={0,2}\b/g },
];

/** Base64 candidates only survive when the decoded payload looks like an identifier. */
function base64LooksLikeIdentifier(value: string): boolean {
  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8');
    return /^[\d\sXx-]{8,32}$/.test(decoded) && /\d{8,}/.test(decoded.replace(/\D/g, ''));
  } catch {
    return false;
  }
}

/** Resolve the absolute offset of a capture group inside its match. */
function groupOffset(match: RegExpMatchArray, group: number): number {
  const whole = match[0];
  const captured = match[group];
  if (!captured) return -1;
  const relative = whole.lastIndexOf(captured);
  return relative < 0 ? -1 : (match.index ?? 0) + relative;
}

export interface ExtractCandidatesOptions {
  /** Hard cap; extraction stops once reached so a pathological input cannot blow the budget. */
  maxCandidates?: number;
}

export const DEFAULT_MAX_CANDIDATES = 400;

/**
 * Extract candidate spans from `text`, mapped onto `chunks` for evidence.
 * Overlapping spans from different extractors are merged, keeping the longest.
 */
export function extractCandidates(
  text: string,
  chunkFor: (offset: number) => { index: number; text: string },
  options: ExtractCandidatesOptions = {},
): PiiCandidate[] {
  const max = options.maxCandidates ?? DEFAULT_MAX_CANDIDATES;
  const found: PiiCandidate[] = [];

  for (const extractor of EXTRACTORS) {
    const pattern = new RegExp(extractor.pattern.source, extractor.pattern.flags);
    for (const match of text.matchAll(pattern)) {
      const group = extractor.group ?? 0;
      const value = group === 0 ? match[0] : match[group];
      if (!value) continue;
      if (extractor.kind === 'base64_id' && !base64LooksLikeIdentifier(value)) continue;

      const start = group === 0 ? (match.index ?? 0) : groupOffset(match, group);
      if (start < 0) continue;

      const chunk = chunkFor(start);
      found.push({
        id: `c${found.length}`,
        kind: extractor.kind,
        category: extractor.category,
        value,
        start,
        end: start + value.length,
        chunkIndex: chunk.index,
        context: chunk.text,
      });
      if (found.length >= max * 4) break;
    }
  }

  return dedupeOverlapping(found).slice(0, max);
}

/**
 * Drop spans fully contained in a longer span. Several extractors legitimately
 * match the same digits (an 18-digit id is also an `account_number`), and
 * adjudicating both wastes budget and double-counts the finding.
 */
function dedupeOverlapping(candidates: PiiCandidate[]): PiiCandidate[] {
  const sorted = [...candidates].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: PiiCandidate[] = [];
  for (const candidate of sorted) {
    const covered = kept.some((k) => k.start <= candidate.start && k.end >= candidate.end);
    if (!covered) kept.push(candidate);
  }
  return kept.map((candidate, index) => ({ ...candidate, id: `c${index}` }));
}
