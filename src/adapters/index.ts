export type { HookAdapter, HookInput, HookOutput, EngineOptions, AgentGuardInstance } from './types.js';
export { ClaudeCodeAdapter } from './claude-code.js';
export { OpenClawAdapter } from './openclaw.js';
export { evaluateHook } from './engine.js';
export {
  registerOpenClawPlugin,
  getPluginIdFromTool,
  getPluginScanResult,
  type OpenClawPluginOptions,
} from './openclaw-plugin.js';
export {
  loadConfig,
  isSensitivePath,
  shouldDenyAtLevel,
  shouldAskAtLevel,
  writeAuditLog,
  getSkillTrustPolicy,
  isActionAllowedByCapabilities,
} from './common.js';
