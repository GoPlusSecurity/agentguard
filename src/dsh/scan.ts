import { basename, join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { SkillScanner } from '../scanner/index.js';
import { MAX_SCANNABLE_FILE_BYTES } from '../scanner/file-walker.js';
import { ALL_RULES, getRuleById } from '../scanner/rules/index.js';
import { DSH_RULES } from '../scanner/rules/dsh/index.js';
import type { RiskLevel, RiskTag, ScanEvidence, ScanRule } from '../types/scanner.js';
import { buildCapabilityProfile } from './capability-profile.js';
import { classifyImpactLayers } from './classify-impact.js';
import {
  classifyDshPlugin,
  hasHarmlessCapabilityMismatch,
  unexpectedHarmlessCapabilities,
} from './classify-plugin.js';
import { detectDshPlugin } from './detect.js';
import { getDshScannerMetadata } from './metadata.js';
import { inspectRegularFileWithinRoot } from '../scanner/safe-file.js';
import { walkDirectoryWithCoverage } from '../scanner/file-walker.js';
import { addFindingContext, calculateReviewPriority, runtimeSurfaceTags } from './finding-context.js';
import { resolveDshSource } from './source.js';
import type {
  DshCapabilityProfile,
  DshFinding,
  DshInstallRecommendation,
  DshPluginScanReport,
} from './types.js';

const RULES: ScanRule[] = [...ALL_RULES, ...DSH_RULES];
const SEVERITY_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const SECURITY_RELEVANT_CORDIS_ROW = /^(?:llm|agent|tools?|session|storage|credentials?|sandbox|approval|permission|webserver|runtime)$/i;

function severityFor(tag: RiskTag): RiskLevel {
  return DSH_RULES.find(rule => rule.id === tag)?.severity ?? getRuleById(tag)?.severity ?? 'low';
}

function humanMessage(tag: RiskTag): string {
  return DSH_RULES.find(rule => rule.id === tag)?.description
    ?? getRuleById(tag)?.description
    ?? 'Security-relevant behavior detected';
}

function toFindings(evidence: ScanEvidence[]): DshFinding[] {
  const findings = new Map<string, DshFinding>();
  const seen = new Set<string>();
  for (const item of evidence) {
    const evidenceKey = `${item.tag}\0${item.file}\0${item.line}\0${item.match}`;
    if (seen.has(evidenceKey)) continue;
    seen.add(evidenceKey);
    const key = `${item.tag}\0${item.file}`;
    const existing = findings.get(key);
    if (existing) {
      existing.occurrenceCount = (existing.occurrenceCount ?? 1) + 1;
      continue;
    }
    findings.set(key, {
      ruleId: item.tag,
      severity: severityFor(item.tag),
      file: item.file,
      line: item.line || undefined,
      message: humanMessage(item.tag),
      snippet: item.match,
      occurrenceCount: 1,
    });
  }
  return [...findings.values()];
}

function calculateDshRisk(tags: RiskTag[]): RiskLevel {
  const unique = new Set(tags);
  if ([...unique].some(tag => severityFor(tag) === 'critical')) return 'critical';
  const criticalCombination = unique.has('INSTALL_SCRIPT')
    && (unique.has('SHELL_EXEC') || unique.has('REMOTE_LOADER'))
    && (unique.has('READ_ENV_SECRETS') || unique.has('DYNAMIC_CODE_EXECUTION')
      || unique.has('OBFUSCATION') || unique.has('NETWORK_ACCESS'));
  if (criticalCombination) return 'critical';
  return [...unique].reduce<RiskLevel>((current, tag) => {
    const severity = severityFor(tag);
    return SEVERITY_ORDER[severity] > SEVERITY_ORDER[current] ? severity : current;
  }, 'low');
}

function recommendationFor(risk: RiskLevel, capabilities: DshCapabilityProfile): DshInstallRecommendation {
  if (risk === 'critical') return 'expert-review-required';
  if (risk === 'high' && (capabilities.shellExec || capabilities.fileWrite)) return 'avoid-on-primary-machine';
  if (risk === 'high') return 'sandbox-only';
  if (risk === 'medium') return 'test-in-isolated-profile';
  return 'safe-to-try';
}

function recommendationForTags(
  risk: RiskLevel,
  capabilities: DshCapabilityProfile,
  tags: RiskTag[],
): DshInstallRecommendation {
  if (tags.includes('DSH_SCAN_INCOMPLETE')) return 'expert-review-required';
  return recommendationFor(risk, capabilities);
}

function buildSummary(
  isDsh: boolean,
  risk: RiskLevel,
  tags: RiskTag[],
  mismatch: boolean,
): string {
  if (!isDsh) return 'No strong DSH plugin, bundle, profile, or Cordis integration signal was found.';
  if (tags.length === 0) return 'DSH project detected; no security-relevant capabilities were found by the current static rules.';
  const capabilityLabels: Partial<Record<RiskTag, string>> = {
    SHELL_EXEC: 'shell execution',
    DYNAMIC_CODE_EXECUTION: 'dynamic code execution',
    DYNAMIC_MODULE_LOADING: 'dynamic local or package module loading',
    FILE_WRITE_ACCESS: 'file writes',
    FILE_READ_ACCESS: 'file reads',
    NETWORK_ACCESS: 'network access',
    READ_ENV_SECRETS: 'environment access',
    INSTALL_SCRIPT: 'installation scripts',
    DSH_TOOL_REGISTRY_MUTATION: 'tool pipeline changes',
    DSH_PROVIDER_MUTATION: 'model/provider changes',
    DSH_RUNTIME_MUTATION: 'runtime lifecycle changes',
    DSH_SCAN_INCOMPLETE: 'incomplete security-relevant metadata analysis',
    DSH_THEME_ELEVATED_CAPABILITY: 'elevated capabilities inconsistent with its UI/theme purpose',
  };
  const reasons = tags.map(tag => capabilityLabels[tag]).filter((value): value is string => Boolean(value));
  const uniqueReasons = [...new Set(reasons)];
  const mismatchReason = capabilityLabels.DSH_THEME_ELEVATED_CAPABILITY!;
  const prioritizedReasons = mismatch
    ? [mismatchReason, ...uniqueReasons.filter(reason => reason !== mismatchReason)].slice(0, 4)
    : uniqueReasons.slice(0, 4);
  const mismatchText = mismatch ? ' Its benign-looking purpose does not match the elevated capabilities it requests.' : '';
  return `${risk.toUpperCase()} risk: ${prioritizedReasons.join(', ') || 'security-relevant behavior detected'}.${mismatchText}`;
}

async function hasReadmeInstallInstructions(rootDir: string): Promise<boolean> {
  for (const file of ['README.md', 'README.mdx', 'README.zh.md', 'README.zh-CN.md', 'readme.md']) {
    try {
      const path = join(rootDir, file);
      const safeFile = await inspectRegularFileWithinRoot(rootDir, path);
      if (safeFile.size > MAX_SCANNABLE_FILE_BYTES) continue;
      const content = await readFile(safeFile.path, 'utf8');
      if (/(?:^|\n)#{1,4}\s*(?:install|installation|安装)|\b(?:npm|pnpm|yarn)\s+(?:add|install)\b/i.test(content)) {
        return true;
      }
    } catch {
      // A repository need not have every common README spelling.
    }
  }
  return false;
}

export interface ScanDshPluginOptions {
  /** Optional GitHub branch, tag, fully qualified ref, or full commit SHA. */
  ref?: string;
}

/** Scan one local directory or GitHub repository and return a DSH-specific report. */
export async function scanDshPlugin(
  input: string,
  options: ScanDshPluginOptions = {},
): Promise<DshPluginScanReport> {
  const source = await resolveDshSource(input, options);
  try {
    const directory = await walkDirectoryWithCoverage(source.rootDir, { includeGeneratedRuntime: true });
    const detection = await detectDshPlugin(source.rootDir, directory.files);
    const capabilityProfile = await buildCapabilityProfile(source.rootDir, detection, directory.files);
    const pluginKind = await classifyDshPlugin(source.rootDir, detection, capabilityProfile, directory.files);
    const impactLayers = classifyImpactLayers(pluginKind, capabilityProfile, detection);
    const artifactScanner = new SkillScanner({ useExternalScanner: false, additionalRules: DSH_RULES });
    const artifactHash = await artifactScanner.calculateArtifactHash(source.rootDir, directory);
    const scan = await artifactScanner.scan({
      skill: {
        id: detection.package.name ?? basename(source.rootDir),
        source: source.repositoryUrl ?? source.rootDir,
        version_ref: detection.package.version ?? source.revision ?? 'unknown',
        artifact_hash: artifactHash,
      },
      payload: { type: 'dir', ref: source.rootDir },
    }, directory);
    // Cordis overrides are derived from parsed rows below, not regex snippets.
    scan.evidence = scan.evidence.filter(item => item.tag !== 'DSH_PATCH_OVERRIDE');
    scan.risk_tags = [...new Set(scan.evidence.map(item => item.tag))];
    const riskTags = [...new Set(scan.risk_tags)];
    const harmlessMismatch = hasHarmlessCapabilityMismatch(detection, pluginKind, capabilityProfile);
    const findings = toFindings(scan.evidence);
    const scanCoverage = scan.metadata?.coverage ?? directory.coverage;
    const incompleteInputs = [
      ...(detection.package.parseError
        ? [{ file: 'package.json', message: detection.package.parseError }]
        : []),
      ...detection.cordis.parseErrors,
    ];
    if (incompleteInputs.length > 0) {
      if (!riskTags.includes('DSH_SCAN_INCOMPLETE')) riskTags.push('DSH_SCAN_INCOMPLETE');
      for (const incomplete of incompleteInputs) {
        findings.push({
          ruleId: 'DSH_SCAN_INCOMPLETE',
          severity: 'high',
          file: incomplete.file,
          message: 'Security-relevant DSH metadata could not be parsed completely; manual review is required',
        });
      }
    }
    if (!scanCoverage.complete) {
      if (!riskTags.includes('DSH_SCAN_INCOMPLETE')) riskTags.push('DSH_SCAN_INCOMPLETE');
      const skipped = scanCoverage.skippedByReason;
      findings.push({
        ruleId: 'DSH_SCAN_INCOMPLETE',
        severity: 'high',
        file: 'scan-coverage',
        message: `Static analysis skipped ${scanCoverage.skipped} security-relevant file(s); manual review is required`,
        snippet: `fileLimit=${skipped.fileLimit}; oversized=${skipped.oversized}; unreadable=${skipped.unreadable}`,
      });
    }
    const coreOverrides = detection.cordis.rows.filter(row =>
      row.operation === 'replace' && Boolean(row.id && SECURITY_RELEVANT_CORDIS_ROW.test(row.id)),
    );
    if (coreOverrides.length > 0) riskTags.push('DSH_PATCH_OVERRIDE');
    for (const row of coreOverrides) {
      findings.push({
        ruleId: 'DSH_PATCH_OVERRIDE',
        severity: 'high',
        file: row.file,
        message: 'Cordis patch replaces an existing DSH composition row',
        snippet: `id: ${row.id}`,
      });
    }
    if (harmlessMismatch) {
      const unexpected = unexpectedHarmlessCapabilities(capabilityProfile);
      riskTags.push('DSH_THEME_ELEVATED_CAPABILITY');
      findings.push({
        ruleId: 'DSH_THEME_ELEVATED_CAPABILITY',
        severity: 'high',
        file: 'package.json',
        message: `Benign-looking UI purpose conflicts with unexpected capabilities: ${unexpected.join(', ')}`,
        snippet: `name=${JSON.stringify(detection.package.name ?? '')}; capabilities=${unexpected.join(',')}`,
      });
    }
    await addFindingContext(source.rootDir, findings);
    const riskLevel = calculateDshRisk(riskTags);
    const runtimeTags = runtimeSurfaceTags(findings);
    const runtimeSurfaceRiskLevel = calculateDshRisk(runtimeTags);
    const runtimeCapabilities = {
      ...capabilityProfile,
      shellExec: runtimeTags.includes('SHELL_EXEC'),
      fileWrite: runtimeTags.includes('FILE_WRITE_ACCESS'),
    };
    const scannedAt = scan.metadata?.scan_time ?? new Date().toISOString();

    return {
      schemaVersion: 1,
      scanner: getDshScannerMetadata(),
      identity: {
        name: detection.package.name ?? basename(source.repositoryUrl ?? source.rootDir).replace(/\.git$/, ''),
        packageName: detection.package.name,
        version: detection.package.version,
        repoUrl: source.repositoryUrl ?? detection.package.repositoryUrl,
        path: source.kind === 'local' ? source.rootDir : undefined,
        artifactHash,
        pluginKind,
        profileName: detection.package.profileBundles.length > 0 ? detection.package.name : undefined,
        bundleName: detection.package.bundlePatch ? detection.package.name : undefined,
      },
      detection: {
        isDshPlugin: detection.isDshPlugin,
        confidence: detection.confidence,
        signals: detection.signals,
      },
      riskLevel,
      riskTags,
      runtimeSurfaceRiskLevel,
      runtimeSurfaceRiskTags: runtimeTags,
      runtimeSurfaceRecommendation: recommendationForTags(runtimeSurfaceRiskLevel, runtimeCapabilities, runtimeTags),
      reviewPriority: calculateReviewPriority(riskLevel, runtimeSurfaceRiskLevel, runtimeTags),
      capabilityProfile,
      impactLayers,
      findings,
      installRecommendation: recommendationForTags(riskLevel, capabilityProfile, riskTags),
      summary: buildSummary(detection.isDshPlugin, riskLevel, riskTags, harmlessMismatch),
      harmlessMismatch,
      scannedAt,
      filesScanned: scanCoverage.scanned,
      scanCoverage,
      scanDurationMs: scan.metadata?.scan_duration_ms ?? 0,
      source: {
        input,
        kind: source.kind,
        resolvedPath: source.kind === 'local' ? source.rootDir : source.repositoryUrl ?? input,
        repositoryUrl: source.repositoryUrl,
        requestedRef: source.requestedRef,
        revision: source.revision,
        lastCommitAt: source.lastCommitAt,
      },
      project: {
        description: detection.package.description,
        repositoryUrl: detection.package.repositoryUrl ?? source.repositoryUrl,
        hasReadmeInstallInstructions: await hasReadmeInstallInstructions(source.rootDir),
        manifest: {
          bundle: Boolean(detection.package.bundlePatch),
          profile: detection.package.profileBundles.length > 0,
          client: detection.package.hasClientExtension,
          cordisFiles: detection.cordis.files,
        },
      },
      diagnostics: {
        packageParseError: detection.package.parseError,
        cordisParseErrors: detection.cordis.parseErrors,
      },
    };
  } finally {
    await source.cleanup();
  }
}

export { DSH_RULES, RULES as DSH_SCAN_RULES };
