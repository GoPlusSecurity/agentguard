import type { RiskLevel } from '../types/scanner.js';
import type { DshCapabilityProfile, DshFinding, DshImpactLayer, DshPluginScanReport } from './types.js';

export type DshRiskDirection = 'increased' | 'decreased' | 'unchanged';
export type DshUpdateAssessment = 'unchanged-artifact' | 'no-security-signal-change' | 'security-signals-changed' | 'review-required';

export interface DshCapabilityChange {
  capability: keyof DshCapabilityProfile;
  change: 'added' | 'removed';
}

export interface DshFindingCountChange {
  finding: DshFinding;
  before: number;
  after: number;
}

export interface DshReportComparison {
  schemaVersion: 1;
  comparedAt: string;
  assessment: DshUpdateAssessment;
  sameArtifact: boolean;
  identityChanged: boolean;
  rulesBaselineChanged: boolean;
  risk: { before: RiskLevel; after: RiskLevel; direction: DshRiskDirection };
  runtimeSurfaceRisk: { before: RiskLevel; after: RiskLevel; direction: DshRiskDirection };
  recommendation: { before: string; after: string; changed: boolean };
  reviewPriority: { before: string; after: string; changed: boolean };
  addedRiskTags: string[];
  removedRiskTags: string[];
  addedRuntimeSurfaceRiskTags: string[];
  removedRuntimeSurfaceRiskTags: string[];
  capabilityChanges: DshCapabilityChange[];
  addedImpactLayers: DshImpactLayer[];
  removedImpactLayers: DshImpactLayer[];
  addedFindings: DshFinding[];
  removedFindings: DshFinding[];
  changedFindingCounts: DshFindingCountChange[];
  before: { name: string; version?: string; revision?: string; artifactHash?: string; rulesBaseline?: string };
  after: { name: string; version?: string; revision?: string; artifactHash?: string; rulesBaseline?: string };
}

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const RISK_LEVELS = new Set(Object.keys(RISK_ORDER));

function direction(before: RiskLevel, after: RiskLevel): DshRiskDirection {
  return RISK_ORDER[after] > RISK_ORDER[before] ? 'increased' : RISK_ORDER[after] < RISK_ORDER[before] ? 'decreased' : 'unchanged';
}

function difference<T>(left: T[], right: T[]): T[] {
  const other = new Set(right);
  return [...new Set(left)].filter(value => !other.has(value));
}

function findingKey(finding: DshFinding): string {
  return `${finding.ruleId}\0${finding.file}\0${finding.sourceCategory ?? ''}\0${finding.runtimeRelevance ?? ''}`;
}

function reportIdentity(report: DshPluginScanReport) {
  return {
    name: report.identity.name,
    version: report.identity.version,
    revision: report.source.revision,
    artifactHash: report.identity.artifactHash,
    rulesBaseline: report.scanner?.rulesBaseline,
  };
}

export function parseDshPluginScanReport(value: unknown, label = 'report'): DshPluginScanReport {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a DSH JSON report object`);
  const report = value as Partial<DshPluginScanReport>;
  if (report.schemaVersion !== 1 || !report.identity || typeof report.identity.name !== 'string') throw new Error(`${label} is not a valid DSH schema-v1 report`);
  if (!RISK_LEVELS.has(String(report.riskLevel)) || !Array.isArray(report.riskTags) || !Array.isArray(report.findings)) throw new Error(`${label} has invalid risk fields`);
  if (!report.capabilityProfile || !Array.isArray(report.impactLayers) || !report.source || typeof report.installRecommendation !== 'string') throw new Error(`${label} is missing comparison fields`);
  return report as DshPluginScanReport;
}

/** Compare two reports without rescanning or executing either artifact. */
export function compareDshReports(beforeInput: DshPluginScanReport, afterInput: DshPluginScanReport): DshReportComparison {
  const before = parseDshPluginScanReport(beforeInput, 'before report');
  const after = parseDshPluginScanReport(afterInput, 'after report');
  const beforeRuntimeRisk = before.runtimeSurfaceRiskLevel ?? before.riskLevel;
  const afterRuntimeRisk = after.runtimeSurfaceRiskLevel ?? after.riskLevel;
  const beforeRuntimeTags = before.runtimeSurfaceRiskTags ?? before.riskTags;
  const afterRuntimeTags = after.runtimeSurfaceRiskTags ?? after.riskTags;
  const beforeFindings = new Map(before.findings.map(finding => [findingKey(finding), finding]));
  const afterFindings = new Map(after.findings.map(finding => [findingKey(finding), finding]));
  const capabilityChanges = (Object.keys(after.capabilityProfile) as Array<keyof DshCapabilityProfile>).flatMap(capability =>
    before.capabilityProfile[capability] === after.capabilityProfile[capability]
      ? []
      : [{ capability, change: after.capabilityProfile[capability] ? 'added' : 'removed' } as DshCapabilityChange]);
  const addedRiskTags = difference(after.riskTags, before.riskTags);
  const addedRuntimeSurfaceRiskTags = difference(afterRuntimeTags, beforeRuntimeTags);
  const addedFindings = [...afterFindings].filter(([key]) => !beforeFindings.has(key)).map(([, finding]) => finding);
  const changedFindingCounts = [...afterFindings].flatMap(([key, finding]) => {
    const previous = beforeFindings.get(key);
    const beforeCount = previous?.occurrenceCount ?? 1;
    const afterCount = finding.occurrenceCount ?? 1;
    return previous && beforeCount !== afterCount ? [{ finding, before: beforeCount, after: afterCount }] : [];
  });
  const sameArtifact = Boolean(before.identity.artifactHash && before.identity.artifactHash === after.identity.artifactHash);
  const identityChanged = before.identity.name !== after.identity.name;
  const rulesBaselineChanged = before.scanner?.rulesBaseline !== after.scanner?.rulesBaseline;
  const riskDirection = direction(before.riskLevel, after.riskLevel);
  const runtimeDirection = direction(beforeRuntimeRisk, afterRuntimeRisk);
  const reviewRequired = identityChanged || rulesBaselineChanged || riskDirection === 'increased' || runtimeDirection === 'increased'
    || addedRuntimeSurfaceRiskTags.length > 0
    || capabilityChanges.some(change => change.change === 'added')
    || addedFindings.some(finding => finding.severity === 'high' || finding.severity === 'critical')
    || changedFindingCounts.some(change => change.after > change.before && (change.finding.severity === 'high' || change.finding.severity === 'critical'));
  const anySignalChange = addedRiskTags.length > 0 || difference(before.riskTags, after.riskTags).length > 0
    || addedRuntimeSurfaceRiskTags.length > 0 || difference(beforeRuntimeTags, afterRuntimeTags).length > 0
    || capabilityChanges.length > 0 || addedFindings.length > 0 || changedFindingCounts.length > 0
    || [...beforeFindings].some(([key]) => !afterFindings.has(key));
  return {
    schemaVersion: 1,
    comparedAt: new Date().toISOString(),
    assessment: reviewRequired ? 'review-required' : sameArtifact ? 'unchanged-artifact' : anySignalChange ? 'security-signals-changed' : 'no-security-signal-change',
    sameArtifact,
    identityChanged,
    rulesBaselineChanged,
    risk: { before: before.riskLevel, after: after.riskLevel, direction: riskDirection },
    runtimeSurfaceRisk: { before: beforeRuntimeRisk, after: afterRuntimeRisk, direction: runtimeDirection },
    recommendation: { before: before.installRecommendation, after: after.installRecommendation, changed: before.installRecommendation !== after.installRecommendation },
    reviewPriority: { before: before.reviewPriority ?? 'elevated', after: after.reviewPriority ?? 'elevated', changed: (before.reviewPriority ?? 'elevated') !== (after.reviewPriority ?? 'elevated') },
    addedRiskTags,
    removedRiskTags: difference(before.riskTags, after.riskTags),
    addedRuntimeSurfaceRiskTags,
    removedRuntimeSurfaceRiskTags: difference(beforeRuntimeTags, afterRuntimeTags),
    capabilityChanges,
    addedImpactLayers: difference(after.impactLayers, before.impactLayers),
    removedImpactLayers: difference(before.impactLayers, after.impactLayers),
    addedFindings,
    removedFindings: [...beforeFindings].filter(([key]) => !afterFindings.has(key)).map(([, finding]) => finding),
    changedFindingCounts,
    before: reportIdentity(before),
    after: reportIdentity(after),
  };
}
