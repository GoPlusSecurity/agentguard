/**
 * GoPlus AgentGuard - Security guard for AI agents
 *
 * Three-module security framework:
 * - Skill Scanner: Static analysis of skill code
 * - Skill Registry: Trust level and capability management
 * - Action Scanner: Runtime action decision engine
 */

// Export types
export * from './types/index.js';

// Export modules
export { SkillScanner, type ScannerOptions } from './scanner/index.js';
export { scanDshPlugin, DSH_RULES, DSH_SCAN_RULES } from './dsh/scan.js';
export type { ScanDshPluginOptions } from './dsh/scan.js';
export { MAX_DSH_BATCH_TARGETS, parseDshBatchManifest, scanDshPlugins } from './dsh/batch.js';
export type { DshBatchResult, DshBatchScanReport, DshBatchTarget } from './dsh/batch.js';
export { DSH_INTEGRATION_PHASE, DSH_RULES_BASELINE, getDshScannerMetadata } from './dsh/metadata.js';
export { detectDshPlugin } from './dsh/detect.js';
export { parseDshPackage } from './dsh/parse-package.js';
export { parseCordisConfigs } from './dsh/parse-cordis-patch.js';
export { buildCapabilityProfile } from './dsh/capability-profile.js';
export { classifyDshPlugin, hasHarmlessCapabilityMismatch } from './dsh/classify-plugin.js';
export { classifyImpactLayers } from './dsh/classify-impact.js';
export { renderDshHtml, renderDshMarkdown } from './reports/dsh-report.js';
export { renderDshBatchMarkdown } from './reports/dsh-batch-report.js';
export type {
  DshCapabilityProfile,
  DshCordisAnalysis,
  DshDetection,
  DshFinding,
  DshFindingSource,
  DshImpactLayer,
  DshInstallRecommendation,
  DshPackageMetadata,
  DshPluginIdentity,
  DshPluginKind,
  DshPluginScanReport,
  DshReviewPriority,
  DshRuntimeRelevance,
} from './dsh/types.js';
export {
  SkillRegistry,
  RegistryStorage,
  type RegistryOptions,
  type StorageOptions,
  type LookupResult,
  type AttestResult,
} from './registry/index.js';
export {
  ActionScanner,
  GoPlusClient,
  type ActionScannerOptions,
} from './action/index.js';

// Export policy presets
export {
  DEFAULT_POLICIES,
  RESTRICTIVE_CAPABILITY,
  PERMISSIVE_CAPABILITY,
  CAPABILITY_PRESETS,
  type PolicyConfig,
} from './policy/default.js';

// Export utility functions
export {
  containsSensitiveData,
  maskSensitiveData,
  extractDomain,
  isDomainAllowed,
  SENSITIVE_PATTERNS,
} from './utils/patterns.js';

// Export adapters (multi-platform hook support)
export {
  ClaudeCodeAdapter,
  OpenClawAdapter,
  HermesAdapter,
  evaluateHook,
  registerOpenClawPlugin,
  loadConfig,
  type HookAdapter,
  type HookInput,
  type HookOutput,
  type EngineOptions,
} from './adapters/index.js';

// Export local-first runtime and Cloud connect helpers
export {
  ensureConfig,
  loadConfig as loadAgentGuardConfig,
  saveConfig as saveAgentGuardConfig,
  connectCloud,
  connectAgentJwt,
  clearAgentJwt,
  disconnectCloud,
  getAgentGuardPaths,
  type AgentGuardConfig,
} from './config.js';
export { AgentGuardCloudClient } from './cloud/client.js';
export { evaluateLocalAction } from './runtime/evaluator.js';
export {
  protectAction,
  formatProtectResult,
  exitCodeForDecision,
  type ProtectOptions,
  type ProtectResult,
} from './runtime/protect.js';
export {
  approvePendingApproval,
  cleanupExpiredApprovals,
  consumeApprovedApproval,
  listPendingApprovals,
  writePendingApproval,
  type ApprovalRecord,
} from './runtime/approvals.js';
export { redactText, redactPreview, redactReasons } from './runtime/redaction.js';
export {
  getDefaultEffectiveRuntimePolicy,
  loadCachedPolicy,
  saveCachedPolicy,
  resolveRuntimePolicy,
} from './runtime/policy.js';
export type {
  EffectiveRuntimePolicy,
  RuntimeAction,
  RuntimeDecision,
  RuntimeAuditEvent,
  RuntimeActionType,
  RuntimeAgentHost,
  CloudPolicyDecision,
} from './runtime/types.js';

// Convenience factory functions
import { SkillScanner } from './scanner/index.js';
import { SkillRegistry } from './registry/index.js';
import { ActionScanner } from './action/index.js';
import type { CapabilityModel } from './types/skill.js';

/**
 * Create a complete AgentGuard instance with all modules
 */
export function createAgentGuard(options?: {
  registryPath?: string;
  useExternalScanner?: boolean;
  /** Default capabilities used when no registry record is found for an actor */
  defaultCapabilities?: CapabilityModel;
}) {
  const registry = new SkillRegistry({
    filePath: options?.registryPath,
  });

  const scanner = new SkillScanner({
    useExternalScanner: options?.useExternalScanner ?? true,
  });

  const actionScanner = new ActionScanner({
    registry,
    defaultCapabilities: options?.defaultCapabilities,
  });

  return {
    scanner,
    registry,
    actionScanner,
  };
}

// Default export
export default createAgentGuard;
