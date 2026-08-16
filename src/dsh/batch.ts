import type { RiskLevel } from '../types/scanner.js';
import { getDshScannerMetadata } from './metadata.js';
import { scanDshPlugin } from './scan.js';
import type { DshInstallRecommendation, DshPluginScanReport, DshReviewPriority } from './types.js';

export const MAX_DSH_BATCH_TARGETS = 25;

export interface DshBatchTarget {
  target: string;
  ref?: string;
}

export type DshBatchResult =
  | { status: 'ok'; target: string; ref?: string; report: DshPluginScanReport }
  | { status: 'error'; target: string; ref?: string; error: string };

export interface DshBatchScanReport {
  schemaVersion: 1;
  scanner: ReturnType<typeof getDshScannerMetadata>;
  scannedAt: string;
  total: number;
  succeeded: number;
  failed: number;
  highestRisk?: RiskLevel;
  highestRuntimeSurfaceRisk?: RiskLevel;
  riskCounts: Record<RiskLevel, number>;
  runtimeSurfaceRiskCounts: Record<RiskLevel, number>;
  recommendationCounts: Record<DshInstallRecommendation, number>;
  reviewPriorityCounts: Record<DshReviewPriority, number>;
  results: DshBatchResult[];
}

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function highestRisk(values: RiskLevel[]): RiskLevel | undefined {
  return values.reduce<RiskLevel | undefined>((highest, value) =>
    highest === undefined || RISK_ORDER[value] > RISK_ORDER[highest] ? value : highest, undefined);
}

export function parseDshBatchManifest(value: unknown): DshBatchTarget[] {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const unknownKeys = Object.keys(value).filter(key => key !== 'targets');
    if (unknownKeys.length > 0) throw new Error(`Batch manifest has unknown field ${unknownKeys[0]}`);
  }
  const entries = Array.isArray(value)
    ? value
    : value && typeof value === 'object' && Array.isArray((value as { targets?: unknown }).targets)
      ? (value as { targets: unknown[] }).targets
      : undefined;
  if (!entries || entries.length === 0) throw new Error('Batch manifest must contain a non-empty targets array');
  if (entries.length > MAX_DSH_BATCH_TARGETS) {
    throw new Error(`Batch manifest exceeds the ${MAX_DSH_BATCH_TARGETS} target limit`);
  }

  const targets = entries.map((entry, index): DshBatchTarget => {
    if (typeof entry === 'string') {
      if (entry.trim() === '') throw new Error(`Batch target ${index + 1} must not be empty`);
      return { target: entry };
    }
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`Batch target ${index + 1} must be a string or { target, ref? } object`);
    }
    const candidate = entry as Record<string, unknown>;
    const unknownKeys = Object.keys(candidate).filter(key => key !== 'target' && key !== 'ref');
    if (unknownKeys.length > 0) throw new Error(`Batch target ${index + 1} has unknown field ${unknownKeys[0]}`);
    if (typeof candidate.target !== 'string' || candidate.target.trim() === '') {
      throw new Error(`Batch target ${index + 1} must have a non-empty target`);
    }
    if (candidate.ref !== undefined && (typeof candidate.ref !== 'string' || candidate.ref.length === 0)) {
      throw new Error(`Batch target ${index + 1} ref must be a non-empty string`);
    }
    return { target: candidate.target, ref: candidate.ref as string | undefined };
  });
  const seen = new Set<string>();
  for (const target of targets) {
    const key = `${target.target}\0${target.ref ?? ''}`;
    if (seen.has(key)) throw new Error(`Duplicate batch target: ${JSON.stringify(target.target)}`);
    seen.add(key);
  }
  return targets;
}

/** Scan a bounded target list sequentially; one failure does not discard successful reports. */
export async function scanDshPlugins(targetsInput: DshBatchTarget[]): Promise<DshBatchScanReport> {
  const targets = parseDshBatchManifest(targetsInput);
  const results: DshBatchResult[] = [];
  for (const entry of targets) {
    try {
      const report = await scanDshPlugin(entry.target, { ref: entry.ref });
      results.push({ status: 'ok', ...entry, report });
    } catch (error) {
      results.push({ status: 'error', ...entry, error: (error as Error).message });
    }
  }
  const reports = results.flatMap(result => result.status === 'ok' ? [result.report] : []);
  const risks: RiskLevel[] = ['low', 'medium', 'high', 'critical'];
  const recommendations: DshInstallRecommendation[] = [
    'safe-to-try', 'test-in-isolated-profile', 'sandbox-only', 'avoid-on-primary-machine', 'expert-review-required',
  ];
  const priorities: DshReviewPriority[] = ['routine', 'elevated', 'high', 'urgent'];
  return {
    schemaVersion: 1,
    scanner: getDshScannerMetadata(),
    scannedAt: new Date().toISOString(),
    total: targets.length,
    succeeded: reports.length,
    failed: targets.length - reports.length,
    highestRisk: highestRisk(reports.map(report => report.riskLevel)),
    highestRuntimeSurfaceRisk: highestRisk(reports.map(report => report.runtimeSurfaceRiskLevel ?? report.riskLevel)),
    riskCounts: Object.fromEntries(risks.map(risk => [risk, reports.filter(report => report.riskLevel === risk).length])) as Record<RiskLevel, number>,
    runtimeSurfaceRiskCounts: Object.fromEntries(risks.map(risk => [risk, reports.filter(report => (report.runtimeSurfaceRiskLevel ?? report.riskLevel) === risk).length])) as Record<RiskLevel, number>,
    recommendationCounts: Object.fromEntries(recommendations.map(value => [value, reports.filter(report => report.installRecommendation === value).length])) as Record<DshInstallRecommendation, number>,
    reviewPriorityCounts: Object.fromEntries(priorities.map(value => [value, reports.filter(report => report.reviewPriority === value).length])) as Record<DshReviewPriority, number>,
    results,
  };
}
