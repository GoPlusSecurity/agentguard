import { readFileSync, statSync } from 'node:fs';
import type { CoverageLevel, PiiCategory } from '../runtime/types.js';
import { analyzePrivacy, MemoryVerdictCache, type SemanticPrivacyReport, type VerdictCache } from './adjudicator.js';
import { splitChunks } from './chunks.js';
import type { AdjudicateOptions, PiiLocalization, PrivacyAdjudicator, PrivacyScope, TokenBudget } from './types.js';

/** Largest file sent for semantic analysis; larger files are reported as skipped. */
export const MAX_SURFACE_FILE_BYTES = 512 * 1024;

export interface SurfaceFinding {
  file: string;
  category: PiiCategory;
  localization: PiiLocalization;
  /** Always masked. The raw value must never reach a report, log or console. */
  evidence: string;
  probability: number;
}

export interface SurfaceScanResult {
  findings: SurfaceFinding[];
  filesExamined: number;
  /** Files not analysed because of size, read errors, or an exhausted budget. */
  filesSkipped: number;
  coverage: CoverageLevel;
  budgetExhausted: boolean;
  chunksSkipped: number;
  usage: { inputTokens: number; outputTokens: number; requests: number };
  errors: string[];
}

export interface SurfaceScanOptions {
  scope: PrivacyScope;
  adjudicator: PrivacyAdjudicator;
  settings: AdjudicateOptions;
  budget?: TokenBudget;
  cache?: VerdictCache;
  maxFileBytes?: number;
}

/**
 * Mask a value so a finding can be shown without reproducing the disclosure.
 *
 * Reporting a leak must not itself be one: a finding travels into the console,
 * the audit log and, when Cloud is connected, off the machine.
 */
export function maskValue(value: string): string {
  if (value.length <= 4) return '*'.repeat(value.length);
  const keep = value.length <= 8 ? 1 : 2;
  return value.slice(0, keep) + '*'.repeat(Math.min(value.length - keep * 2, 10)) + value.slice(-keep);
}

function describeFinding(report: SemanticPrivacyReport, text: string, chunks = splitChunks(text)) {
  return report.findings.map((finding) => {
    if (finding.span) {
      return {
        category: finding.category,
        localization: finding.localization,
        evidence: maskValue(finding.span.value),
        probability: finding.probability,
      };
    }
    // A chunk finding has no span to mask, so only its category and position
    // are reported. Echoing the sentence would republish the disclosure.
    const chunk = chunks[finding.chunkIndex];
    return {
      category: finding.category,
      localization: finding.localization,
      evidence: `sentence ${finding.chunkIndex + 1}${chunk ? ` (${chunk.text.length} chars)` : ''}`,
      probability: finding.probability,
    };
  });
}

/**
 * Run semantic privacy analysis across a set of files under one shared budget.
 *
 * Callers pick the scope from the surface they are scanning: source code has no
 * prose worth judging, whereas chat logs and agent memory are almost entirely
 * prose. The budget is shared so that scanning more files costs more coverage,
 * never more data leaving the machine than the caller allowed.
 */
export async function scanSurfaces(files: string[], options: SurfaceScanOptions): Promise<SurfaceScanResult> {
  const cache = options.cache ?? new MemoryVerdictCache();
  const maxBytes = options.maxFileBytes ?? MAX_SURFACE_FILE_BYTES;
  const result: SurfaceScanResult = {
    findings: [],
    filesExamined: 0,
    filesSkipped: 0,
    coverage: 'full',
    budgetExhausted: false,
    chunksSkipped: 0,
    usage: { inputTokens: 0, outputTokens: 0, requests: 0 },
    errors: [],
  };

  for (const file of files) {
    let text: string;
    try {
      if (statSync(file).size > maxBytes) {
        result.filesSkipped += 1;
        continue;
      }
      text = readFileSync(file, 'utf8');
    } catch {
      result.filesSkipped += 1;
      continue;
    }
    if (!text.trim()) continue;

    const report = await analyzePrivacy(text, {
      ...options.settings,
      adjudicator: options.adjudicator,
      scope: options.scope,
      budget: options.budget,
      cache,
    });

    result.filesExamined += 1;
    result.chunksSkipped += report.chunksSkipped;
    if (report.usage) {
      result.usage.inputTokens += report.usage.inputTokens;
      result.usage.outputTokens += report.usage.outputTokens;
      result.usage.requests += report.usage.requests;
    }
    if (report.errors?.length) result.errors.push(...report.errors);
    if (report.budgetExhausted) {
      result.budgetExhausted = true;
      result.filesSkipped += 1;
    }
    if (report.coverage !== 'full') result.coverage = degrade(result.coverage, report.coverage);

    for (const finding of describeFinding(report, text)) {
      result.findings.push({ file, ...finding });
    }
  }

  return result;
}

/** Coverage only ever gets worse across a multi-file scan. */
function degrade(current: CoverageLevel, next: CoverageLevel): CoverageLevel {
  const order: CoverageLevel[] = ['full', 'partial', 'observe_only', 'unsupported'];
  return order[Math.max(order.indexOf(current), order.indexOf(next))] ?? current;
}
