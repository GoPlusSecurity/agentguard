import type { RiskLevel, RiskTag } from '../types/scanner.js';

/** DSH plugin categories inferred from package metadata, Cordis rows, and source code. */
export type DshPluginKind =
  | 'tool'
  | 'ui'
  | 'theme'
  | 'workflow'
  | 'provider'
  | 'runtime'
  | 'bundle'
  | 'profile'
  | 'unknown';

/** DSH runtime areas a plugin can influence. */
export type DshImpactLayer =
  | 'ui'
  | 'tool-registry'
  | 'workflow'
  | 'models-providers'
  | 'session-storage'
  | 'runtime-core';

/** Static capability profile derived from the scanned artifact. */
export interface DshCapabilityProfile {
  fileRead: boolean;
  fileWrite: boolean;
  networkAccess: boolean;
  shellExec: boolean;
  envAccess: boolean;
  providerAccess: boolean;
  uiInjection: boolean;
  sessionAccess: boolean;
  storageAccess: boolean;
  toolRegistryMutation: boolean;
  runtimeMutation: boolean;
}

/** Relevant DSH-owned fields parsed from package.json. */
export interface DshPackageMetadata {
  name?: string;
  description?: string;
  version?: string;
  repositoryUrl?: string;
  bundlePatch?: string;
  profileBundles: string[];
  hasClientExtension: boolean;
  clientPlatform?: string;
  scripts: Record<string, string>;
  dependencies: string[];
  parseError?: string;
}

/** One Cordis configuration row or patch target. */
export interface DshCordisRow {
  file: string;
  id?: string;
  name?: string;
  operation: 'entry' | 'insert' | 'replace';
  hasConfig: boolean;
  disabled: boolean;
}

/** Parsed Cordis configuration summary. */
export interface DshCordisAnalysis {
  files: string[];
  rows: DshCordisRow[];
  parseErrors: Array<{ file: string; message: string }>;
}

/** Evidence that a directory belongs to the DSH ecosystem. */
export interface DshDetection {
  isDshPlugin: boolean;
  confidence: 'none' | 'low' | 'medium' | 'high';
  signals: string[];
  package: DshPackageMetadata;
  cordis: DshCordisAnalysis;
}

/** Install guidance shown in DSH reports. */
export type DshInstallRecommendation =
  | 'safe-to-try'
  | 'test-in-isolated-profile'
  | 'sandbox-only'
  | 'avoid-on-primary-machine'
  | 'expert-review-required';

/** Where a finding came from in the scanned repository. */
export type DshFindingSource =
  | 'runtime'
  | 'installation'
  | 'configuration'
  | 'build'
  | 'test'
  | 'example'
  | 'documentation'
  | 'data'
  | 'derived'
  | 'unknown';

/** How likely the finding is to participate in the installed runtime surface. */
export type DshRuntimeRelevance = 'direct' | 'indirect' | 'unlikely' | 'unknown';

/** Human-review ordering; this is not a claim that the plugin is malicious. */
export type DshReviewPriority = 'routine' | 'elevated' | 'high' | 'urgent';

/** A report finding with rule explanation and source evidence. */
export interface DshFinding {
  ruleId: RiskTag;
  severity: RiskLevel;
  file: string;
  line?: number;
  message: string;
  snippet?: string;
  /** Number of equivalent rule matches aggregated for this file. */
  occurrenceCount?: number;
  sourceCategory?: DshFindingSource;
  runtimeRelevance?: DshRuntimeRelevance;
  likelyGenerated?: boolean;
}

/** Stable identity for a scanned DSH plugin artifact. */
export interface DshPluginIdentity {
  name: string;
  repoUrl?: string;
  packageName?: string;
  version?: string;
  path?: string;
  artifactHash?: string;
  pluginKind: DshPluginKind;
  profileName?: string;
  bundleName?: string;
}

/** Complete installation-time report for a DSH plugin. */
export interface DshPluginScanReport {
  schemaVersion: 1;
  identity: DshPluginIdentity;
  detection: Pick<DshDetection, 'isDshPlugin' | 'confidence' | 'signals'>;
  /** Risk across the full scanned repository, including tests, docs, examples, and data. */
  riskLevel: RiskLevel;
  riskTags: RiskTag[];
  /** Additive schema-v1 field: secondary risk from direct and indirect installed-runtime evidence. */
  runtimeSurfaceRiskLevel?: RiskLevel;
  runtimeSurfaceRiskTags?: RiskTag[];
  runtimeSurfaceRecommendation?: DshInstallRecommendation;
  reviewPriority?: DshReviewPriority;
  capabilityProfile: DshCapabilityProfile;
  impactLayers: DshImpactLayer[];
  findings: DshFinding[];
  installRecommendation: DshInstallRecommendation;
  summary: string;
  harmlessMismatch: boolean;
  scannedAt: string;
  filesScanned: number;
  scanDurationMs: number;
  source: {
    input: string;
    kind: 'local' | 'github';
    resolvedPath: string;
    repositoryUrl?: string;
    revision?: string;
    lastCommitAt?: string;
  };
  project: {
    description?: string;
    repositoryUrl?: string;
    /** Informational README metadata only; never used for risk or installation recommendations. */
    hasReadmeInstallInstructions: boolean;
    manifest: {
      bundle: boolean;
      profile: boolean;
      client: boolean;
      cordisFiles: string[];
    };
  };
  diagnostics: {
    packageParseError?: string;
    cordisParseErrors: Array<{ file: string; message: string }>;
  };
}
