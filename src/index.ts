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
  evaluateHook,
  registerOpenClawPlugin,
  loadConfig,
  type HookAdapter,
  type HookInput,
  type HookOutput,
  type EngineOptions,
} from './adapters/index.js';

// Convenience factory functions
import { SkillScanner } from './scanner/index.js';
import { SkillRegistry } from './registry/index.js';
import { ActionScanner } from './action/index.js';

/**
 * Create a complete AgentGuard instance with all modules
 */
export function createAgentGuard(options?: {
  registryPath?: string;
  useExternalScanner?: boolean;
}) {
  const registry = new SkillRegistry({
    filePath: options?.registryPath,
  });

  const scanner = new SkillScanner({
    useExternalScanner: options?.useExternalScanner ?? true,
  });

  const actionScanner = new ActionScanner({ registry });

  return {
    scanner,
    registry,
    actionScanner,
  };
}

// Default export
export default createAgentGuard;
