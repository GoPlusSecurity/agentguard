/**
 * GoPlus AgentGuard — OpenClaw Plugin
 *
 * Registers before_tool_call, after_tool_call, and session_start hooks
 * with the OpenClaw plugin API to evaluate tool safety at runtime and
 * auto-scan installed skills on session startup.
 *
 * Features:
 * - Auto-scan all loaded plugins on registration
 * - Auto-scan skill directories (~/.openclaw/skills/, ~/.claude/skills/) on session_start
 * - Auto-register plugins to AgentGuard trust registry
 * - Build toolName → pluginId mapping for initiating skill inference
 *
 * Usage in OpenClaw plugin config:
 *   import agentguard from '@goplus/agentguard/openclaw';
 *   export default agentguard;
 *
 * Or register manually:
 *   import { registerOpenClawPlugin } from '@goplus/agentguard';
 *   registerOpenClawPlugin(api);
 */

import { readdirSync, existsSync, appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import * as path from 'node:path';
import { OpenClawAdapter } from './openclaw.js';
import { evaluateHook } from './engine.js';
import { writeAuditLog } from './common.js';
import type { AgentGuardInstance } from './types.js';
import { loadConfig as loadAgentGuardConfig } from '../config.js';
import { SkillScanner } from '../scanner/index.js';
import { SkillRegistry } from '../registry/index.js';
import { ActionScanner } from '../action/index.js';
import { DEFAULT_CAPABILITY } from '../types/skill.js';
import {
  protectAction,
  type ProtectOptions,
  type ProtectResult,
} from '../runtime/protect.js';
import type { RuntimeActionType } from '../runtime/types.js';
import type { AgentGuardConfig } from '../config.js';

// ---------------------------------------------------------------------------
// OpenClaw Types (subset we use)
// ---------------------------------------------------------------------------

/**
 * OpenClaw PluginRecord (subset)
 */
interface OpenClawPluginRecord {
  id: string;
  name: string;
  version?: string;
  source: string;
  status: 'loaded' | 'disabled' | 'error';
  enabled: boolean;
  toolNames: string[];
}

/**
 * OpenClaw PluginRegistry (subset)
 */
interface OpenClawPluginRegistry {
  plugins: OpenClawPluginRecord[];
}

/**
 * OpenClaw plugin API interface (subset we use)
 */
interface OpenClawPluginApi {
  id: string;
  name: string;
  source: string;
  registrationMode?: string;
  pluginConfig?: Record<string, unknown>;
  on(event: string, handler: (event: unknown, ctx?: unknown) => Promise<unknown>): void;
  on(event: string, options: Record<string, unknown>, handler: (event: unknown, ctx?: unknown) => Promise<unknown>): void;
}

// ---------------------------------------------------------------------------
// Auto-scan helpers (skill directories)
// ---------------------------------------------------------------------------

const OPENCLAW_SKILLS_DIR = join(homedir(), '.openclaw', 'skills');
const CLAUDE_SKILLS_DIR = join(homedir(), '.claude', 'skills');
const AGENTGUARD_DIR = process.env.OPENCLAW_STATE_DIR
  ? join(process.env.OPENCLAW_STATE_DIR, 'agentguard')
  : process.env.AGENTGUARD_HOME || join(homedir(), '.agentguard');
const AUDIT_PATH = join(AGENTGUARD_DIR, 'audit.jsonl');

function ensureAgentGuardDir(): void {
  if (!existsSync(AGENTGUARD_DIR)) {
    mkdirSync(AGENTGUARD_DIR, { recursive: true });
  }
}

function writeScanAuditLog(entry: Record<string, unknown>): void {
  try {
    ensureAgentGuardDir();
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n');
  } catch {
    // Non-critical
  }
}

/**
 * Discover skill directories (containing SKILL.md) under the given path.
 */
function discoverSkillDirs(skillsDir: string): { name: string; path: string }[] {
  if (!existsSync(skillsDir)) return [];
  const skills: { name: string; path: string }[] = [];
  try {
    const entries = readdirSync(skillsDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const skillDir = join(skillsDir, entry.name);
      if (existsSync(join(skillDir, 'SKILL.md'))) {
        skills.push({ name: entry.name, path: skillDir });
      }
    }
  } catch {
    // Can't read skills dir
  }
  return skills;
}

/**
 * Scan skill directories (~/.openclaw/skills/ and ~/.claude/skills/).
 * Scan-only mode: reports results via logger, does NOT modify the trust registry.
 * Users can register skills manually with /agentguard trust attest.
 */
async function autoScanSkillDirs(
  scanner: SkillScanner,
  _registry: SkillRegistry,
  logger: (msg: string) => void
): Promise<void> {
  const skills = [
    ...discoverSkillDirs(OPENCLAW_SKILLS_DIR),
    ...discoverSkillDirs(CLAUDE_SKILLS_DIR),
  ];

  if (skills.length === 0) return;

  let scanned = 0;

  for (const skill of skills) {
    // Skip self
    if (skill.name === 'agentguard') continue;

    try {
      const result = await scanner.quickScan(skill.path);
      scanned++;

      // Audit log — only record skill name, risk level, and tag names (no code/evidence)
      writeScanAuditLog({
        timestamp: new Date().toISOString(),
        event: 'auto_scan',
        skill_name: skill.name,
        risk_level: result.risk_level,
        risk_tags: result.risk_tags,
      });

      logger(`[AgentGuard] Skill "${skill.name}": ${result.risk_level} risk [${result.risk_tags.join(', ')}]`);
    } catch {
      // Skip skills that fail to scan
    }
  }

  if (scanned > 0) {
    logger(`[AgentGuard] Scanned ${scanned} skill dir(s). Use /agentguard trust attest to register.`);
  }
}

// ---------------------------------------------------------------------------
// Plugin registration options
// ---------------------------------------------------------------------------

/**
 * Plugin registration options
 */
export interface OpenClawPluginOptions {
  /** Protection level (strict/balanced/permissive) */
  level?: AgentGuardConfig['level'];
  /** Enable runtime policy protection via AgentGuard Cloud/cache/default policy (default: true) */
  runtimeProtection?: boolean;
  /** Runtime protection failure behavior (default: block security-sensitive actions) */
  runtimeFailureMode?: 'block' | 'fallback';
  /** Runtime policy decision mode: local-first fetches Cloud policy then evaluates locally; cloud delegates the decision to Cloud */
  decisionMode?: 'local-first' | 'cloud';
  /** Enable auto-scanning of plugins (default: false — opt-in) */
  skipAutoScan?: boolean;
  /** Custom AgentGuard instance factory */
  agentguardFactory?: () => AgentGuardInstance;
  /** Custom runtime protection function, primarily for tests */
  protectAction?: (options: ProtectOptions) => Promise<ProtectResult | null>;
  /** Custom scanner instance */
  scanner?: SkillScanner;
  /** Custom registry instance */
  registry?: SkillRegistry;
  /** Workspace paths the session is allowed to access (e.g., ['~/.openclaw/workspace/**']) */
  workspacePaths?: string[];
}

// ---------------------------------------------------------------------------
// Global State
// ---------------------------------------------------------------------------

/** Symbol to access OpenClaw's global registry */
const OPENCLAW_REGISTRY_STATE = Symbol.for('openclaw.pluginRegistryState');

/** Tool name → Plugin ID mapping */
const toolToPluginMap = new Map<string, string>();

/** Plugin ID → Scan result cache */
const pluginScanCache = new Map<string, { riskLevel: string; riskTags: string[] }>();

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/**
 * Get OpenClaw's active plugin registry via global symbol
 */
function getOpenClawRegistry(): OpenClawPluginRegistry | null {
  const globalState = globalThis as typeof globalThis & {
    [key: symbol]:
      | {
          registry?: OpenClawPluginRegistry | null;
          activeRegistry?: OpenClawPluginRegistry | null;
          channel?: { registry?: OpenClawPluginRegistry | null };
        }
      | undefined;
  };
  const state = globalState[OPENCLAW_REGISTRY_STATE];
  return state?.channel?.registry ?? state?.activeRegistry ?? state?.registry ?? null;
}

/**
 * Get plugin directory from source path
 */
function getPluginDir(source: string): string {
  // source is typically the entry file (e.g., /path/to/plugin/index.ts)
  // We want the directory
  return path.dirname(source);
}

/**
 * Scan a plugin and cache its risk level. Scan-only: does NOT modify trust registry.
 * Users can register plugins manually with /agentguard trust attest.
 */
async function scanAndRegisterPlugin(
  plugin: OpenClawPluginRecord,
  scanner: SkillScanner,
  _registry: SkillRegistry,
  logger: (msg: string) => void
): Promise<void> {
  // Skip if already scanned
  if (pluginScanCache.has(plugin.id)) {
    return;
  }

  const pluginDir = getPluginDir(plugin.source);

  try {
    // Perform scan
    const scanResult = await scanner.quickScan(pluginDir);

    // Cache result (for runtime before_tool_call checks)
    pluginScanCache.set(plugin.id, {
      riskLevel: scanResult.risk_level,
      riskTags: scanResult.risk_tags,
    });

    // Build tool → plugin mapping
    for (const toolName of plugin.toolNames) {
      toolToPluginMap.set(toolName, plugin.id);
    }

    logger(`[AgentGuard] Scanned plugin "${plugin.id}": ${scanResult.risk_level} risk [${scanResult.risk_tags.join(', ')}]`);

  } catch (err) {
    // If scan fails, cache as unknown
    pluginScanCache.set(plugin.id, {
      riskLevel: 'unknown',
      riskTags: ['SCAN_FAILED'],
    });

    // Still build tool mapping
    for (const toolName of plugin.toolNames) {
      toolToPluginMap.set(toolName, plugin.id);
    }

    logger(`[AgentGuard] Plugin "${plugin.id}" scan failed: ${String(err)}`);
  }
}

/**
 * Scan all loaded OpenClaw plugins
 */
async function scanAllPlugins(
  scanner: SkillScanner,
  registry: SkillRegistry,
  logger: (msg: string) => void,
  selfPluginId?: string
): Promise<void> {
  const openclawRegistry = getOpenClawRegistry();

  if (!openclawRegistry) {
    logger('[AgentGuard] OpenClaw registry not available, skipping plugin auto-scan');
    return;
  }

  const plugins = openclawRegistry.plugins.filter(p =>
    p.status === 'loaded' &&
    p.enabled &&
    p.id !== selfPluginId // Don't scan ourselves
  );

  logger(`[AgentGuard] Auto-scanning ${plugins.length} loaded plugins...`);

  // Scan plugins in parallel (with concurrency limit)
  const CONCURRENCY = 3;
  for (let i = 0; i < plugins.length; i += CONCURRENCY) {
    const batch = plugins.slice(i, i + CONCURRENCY);
    await Promise.all(
      batch.map(plugin => scanAndRegisterPlugin(plugin, scanner, registry, logger))
    );
  }

  logger(`[AgentGuard] Plugin auto-scan complete. ${toolToPluginMap.size} tools mapped.`);
}

/**
 * Get plugin ID from tool name
 */
export function getPluginIdFromTool(toolName: string): string | null {
  return toolToPluginMap.get(toolName) ?? null;
}

/**
 * Get scan result for a plugin
 */
export function getPluginScanResult(pluginId: string): { riskLevel: string; riskTags: string[] } | null {
  return pluginScanCache.get(pluginId) ?? null;
}

// ---------------------------------------------------------------------------
// Main Registration
// ---------------------------------------------------------------------------

/**
 * Register AgentGuard hooks with OpenClaw plugin API
 */
export function registerOpenClawPlugin(
  api: OpenClawPluginApi,
  options: OpenClawPluginOptions = {}
): void {
  if (api.registrationMode && api.registrationMode !== 'full') {
    return;
  }

  const adapter = new OpenClawAdapter();
  const runtimeConfig = loadAgentGuardConfig();
  const configuredLevel = options.level ?? readOpenClawConfigLevel(api.pluginConfig);
  const config = configuredLevel ? { ...runtimeConfig, level: configuredLevel } : runtimeConfig;
  const scanner = options.scanner ?? new SkillScanner({ useExternalScanner: false });
  const trustRegistry = options.registry ?? new SkillRegistry();
  const runProtectAction = options.protectAction ?? protectAction;
  const runtimeProtectionEnabled = options.runtimeProtection !== false;

  // Simple logger
  const logger = (msg: string) => console.log(msg);

  // Lazy-initialize agentguard instance
  let agentguard: AgentGuardInstance | null = null;

  // Build default capabilities so the core OpenClaw session can run normal
  // commands and access its workspace without a manual registry entry.
  const defaultCapabilities = {
    ...DEFAULT_CAPABILITY,
    exec: 'allow' as const,
    ...(options.workspacePaths ? { filesystem_allowlist: options.workspacePaths } : {}),
  };

  function getAgentGuard(): AgentGuardInstance {
    if (!agentguard) {
      if (options.agentguardFactory) {
        agentguard = options.agentguardFactory();
      } else {
        // Build inline — avoids require() and passes workspace defaults
        const actionScanner = new ActionScanner({
          registry: trustRegistry,
          defaultCapabilities,
        });
        agentguard = {
          registry: trustRegistry as unknown as AgentGuardInstance['registry'],
          actionScanner,
        };
      }
    }
    return agentguard!;
  }

  // Auto-scan plugins on registration (async, non-blocking, opt-in)
  if (options.skipAutoScan === false) {
    // Use setImmediate to allow plugin registration to complete first
    setImmediate(async () => {
      try {
        await scanAllPlugins(scanner, trustRegistry, logger, api.id);
      } catch (err) {
        logger(`[AgentGuard] Plugin auto-scan error: ${String(err)}`);
      }
    });
  }

  // session_start → auto-scan skill directories (only when opt-in)
  if (options.skipAutoScan === false) {
    api.on('session_start', async () => {
      try {
        await autoScanSkillDirs(scanner, trustRegistry, logger);
      } catch {
        // Non-critical — never block session startup
      }
    });
  }

  // before_tool_call → evaluate and optionally block
  api.on('before_tool_call', async (event: unknown, ctx?: unknown) => {
    try {
      // Try to infer plugin from tool name
      const toolName = readOpenClawToolName(event);
      const pluginId = toolName ? getPluginIdFromTool(toolName) : null;

      // Check if plugin is untrusted
      if (pluginId) {
        const scanResult = getPluginScanResult(pluginId);
        if (scanResult?.riskLevel === 'critical') {
          return {
            block: true,
            blockReason: `GoPlus AgentGuard: Plugin "${pluginId}" has critical security findings and is blocked. Run /agentguard trust attest to manually approve.`,
          };
        }
      }

      if (runtimeProtectionEnabled) {
        const runtimeActionType = mapOpenClawToolToRuntimeAction(toolName, event);
        try {
          const runtimeResult = await runProtectAction({
            config,
            rawInput: event,
            agentHost: 'openclaw',
            actionType: runtimeActionType,
            toolName,
            sessionId: readOpenClawSessionId(event, ctx),
            decisionMode: options.decisionMode ?? 'local-first',
            filesystemAllowlist: options.workspacePaths,
          });
          const hookDecision = runtimeResultToBeforeToolCallResult(runtimeResult);
          if (hookDecision) {
            return hookDecision;
          }
          if (isApprovedLocalRuntimeRetry(runtimeResult)) {
            return undefined;
          }
          if (isRuntimeAuthoritativeAllow(runtimeResult, runtimeActionType, event)) {
            return undefined;
          }
        } catch (err) {
          if (
            options.runtimeFailureMode !== 'fallback' &&
            isSecuritySensitiveRuntimeAction(runtimeActionType)
          ) {
            return {
              block: true,
              blockReason:
                `GoPlus AgentGuard: runtime protection failed for this OpenClaw tool call` +
                ` (${String(err)}). Blocking by default.`,
            };
          }
          logger(`[AgentGuard] Runtime protection failed; falling back to local hook policy: ${String(err)}`);
        }
      }

      const result = await evaluateHook(adapter, event, {
        config,
        agentguard: getAgentGuard(),
      });

      if (result.decision === 'deny') {
        return {
          block: true,
          blockReason: result.reason || 'Blocked by GoPlus AgentGuard',
        };
      }

      // OpenClaw has no 'ask' mode — block with explanation in strict/balanced
      if (result.decision === 'ask') {
        return {
          block: true,
          blockReason: result.reason || 'Requires confirmation (GoPlus AgentGuard)',
        };
      }

      return undefined; // allow
    } catch {
      // Fail open
      return undefined;
    }
  });

  // after_tool_call → audit log
  api.on('after_tool_call', async (event: unknown) => {
    try {
      const input = adapter.parseInput(event);
      const toolName = readOpenClawToolName(event);
      const pluginId = toolName ? getPluginIdFromTool(toolName) : null;
      if (runtimeProtectionEnabled) {
        const runtimeResult = await runProtectAction({
          config,
          rawInput: event,
          agentHost: 'openclaw',
          actionType: mapOpenClawToolToRuntimeAction(toolName, event),
          toolName,
          sessionId: readOpenClawSessionId(event, undefined),
          decisionMode: options.decisionMode ?? 'local-first',
          phase: 'post',
          filesystemAllowlist: options.workspacePaths,
        });
        if (runtimeResult) return;
      }
      writeAuditLog(input, null, pluginId);
    } catch {
      // Non-critical
    }
  });

  logger(`[AgentGuard] Registered with OpenClaw (protection level: ${config.level || 'balanced'})`);
}

export interface OpenClawPluginEntry {
  (api: OpenClawPluginApi): void;
  id: string;
  name: string;
  description: string;
  configSchema: {
    type: 'object';
    properties: Record<string, unknown>;
  };
  register(api: OpenClawPluginApi): void;
}

function mapOpenClawToolToRuntimeAction(
  toolName: string | undefined,
  event?: unknown
): RuntimeActionType {
  const normalized = (toolName || '').toLowerCase();
  if (
    normalized === 'web_search' ||
    normalized === 'websearch' ||
    normalized.includes('web_search') ||
    normalized.includes('web search') ||
    normalized.includes('search_query')
  ) {
    return 'web_search';
  }
  if (
    normalized === 'exec' ||
    normalized === 'bash' ||
    normalized === 'cmd' ||
    normalized === 'command' ||
    normalized === 'terminal' ||
    normalized === 'run' ||
    normalized.includes('exec') ||
    normalized.includes('execute') ||
    normalized.includes('shell') ||
    normalized.includes('terminal') ||
    normalized.includes('command') ||
    normalized.includes('process') ||
    normalized.includes('spawn')
  ) {
    return 'shell';
  }
  if (normalized === 'read' || normalized.includes('read') || normalized.includes('fetch_file')) {
    return 'file_read';
  }
  if (
    normalized === 'write' ||
    normalized === 'edit' ||
    normalized === 'apply_patch' ||
    normalized === 'patch' ||
    normalized === 'create' ||
    normalized === 'save' ||
    normalized === 'delete' ||
    normalized === 'remove' ||
    normalized === 'rename' ||
    normalized === 'scaffold' ||
    normalized.includes('write') ||
    normalized.includes('edit') ||
    normalized.includes('patch') ||
    normalized.includes('delete') ||
    normalized.includes('remove') ||
    normalized.includes('rename') ||
    normalized.includes('scaffold')
  ) {
    return 'file_write';
  }
  if (
    normalized.includes('web') ||
    normalized.includes('browser') ||
    normalized.includes('http') ||
    normalized.includes('fetch') ||
    normalized.includes('request')
  ) {
    return 'network';
  }

  const record = isRecord(event) ? event : undefined;
  if (typeof record?.command === 'string' || typeof record?.cmd === 'string') {
    return 'shell';
  }
  const params = readOpenClawParams(event);
  if (typeof params?.command === 'string' || typeof params?.cmd === 'string') {
    return 'shell';
  }
  if (
    typeof params?.url === 'string' ||
    typeof params?.uri === 'string'
  ) {
    return 'network';
  }
  if (typeof params?.query === 'string' || typeof params?.q === 'string') {
    return 'web_search';
  }
  if (
    typeof params?.content === 'string' ||
    typeof params?.newContent === 'string' ||
    typeof params?.patch === 'string'
  ) {
    return 'file_write';
  }
  if (
    typeof params?.path === 'string' ||
    typeof params?.file_path === 'string' ||
    typeof params?.filePath === 'string'
  ) {
    return 'file_read';
  }

  return 'other';
}

function readOpenClawToolName(event: unknown): string | undefined {
  const record = isRecord(event) ? event : undefined;
  const value = record?.toolName ?? record?.tool_name ?? record?.name ?? record?.id;
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function readOpenClawParams(event: unknown): Record<string, unknown> | undefined {
  const record = isRecord(event) ? event : undefined;
  const params = firstRecord(
    record?.params,
    record?.toolInput,
    record?.tool_input,
    record?.args,
    record?.input
  );
  return params;
}

function isSecuritySensitiveRuntimeAction(actionType: RuntimeActionType): boolean {
  return actionType !== 'other' && actionType !== 'web_search';
}

function readOpenClawSessionId(event: unknown, ctx: unknown): string | undefined {
  const eventRecord = isRecord(event) ? event : undefined;
  const ctxRecord = isRecord(ctx) ? ctx : undefined;
  const sessionId = ctxRecord?.sessionId ?? eventRecord?.sessionId;
  return typeof sessionId === 'string' && sessionId.length > 0 ? sessionId : undefined;
}

function readOpenClawConfigLevel(
  pluginConfig: Record<string, unknown> | undefined
): AgentGuardConfig['level'] | undefined {
  const level = pluginConfig?.level;
  return level === 'strict' || level === 'balanced' || level === 'permissive'
    ? level
    : undefined;
}

type OpenClawBeforeToolCallResult =
  | { block: true; blockReason: string }
  | {
      requireApproval: {
        title: string;
        description: string;
        severity?: 'info' | 'warning' | 'critical';
        timeoutMs?: number;
        timeoutBehavior?: 'allow' | 'deny';
      };
    };

function runtimeResultToBeforeToolCallResult(
  result: ProtectResult | null
): OpenClawBeforeToolCallResult | undefined {
  if (!result) return undefined;

  const decision = normalizeRuntimePolicyDecision(result.decision.decision);
  if (decision !== 'block' && decision !== 'require_approval') {
    return undefined;
  }
  if (decision === 'require_approval' && !shouldSurfaceRuntimeApproval(result)) {
    return undefined;
  }

  const reasonSummary = result.decision.reasons
    .map((reason) => reason.title)
    .filter(Boolean)
    .slice(0, 3)
    .join(', ');
  const action = decision === 'require_approval' ? 'requires approval' : 'blocked';
  const reason =
    `GoPlus AgentGuard: runtime policy ${action} this OpenClaw tool call` +
    ` (risk ${result.decision.riskScore}/100, ${result.decision.riskLevel}; policy ${result.decision.policyVersion}).` +
    (decision === 'require_approval'
      ? ' OpenClaw cannot safely resume this call after an external approval, so AgentGuard blocked it locally.'
      : '') +
    (reasonSummary ? ` Reasons: ${reasonSummary}.` : '') +
    (result.pendingApproval ? ` ${approvalInstruction(result.pendingApproval.actionId)}` : '');

  if (decision === 'require_approval') {
    return { block: true, blockReason: reason };
  }
  return {
    block: true,
    blockReason: reason,
  };
}

function shouldSurfaceRuntimeApproval(result: ProtectResult): boolean {
  return (
    result.policySource === 'cloud-decision' ||
    result.decision.riskScore > 0 ||
    result.decision.reasons.length > 0
  );
}

function isApprovedLocalRuntimeRetry(result: ProtectResult | null): boolean {
  return result?.decision.decision === 'allow' && result.event.metadata?.approvedByLocalGrant === true;
}

function isRuntimeAuthoritativeAllow(
  result: ProtectResult | null,
  actionType: RuntimeActionType,
  event: unknown
): boolean {
  if (actionType !== 'file_read' && actionType !== 'file_write') return false;
  if (!readOpenClawFilePath(event)) return false;
  if (!result) return true;
  const decision = normalizeRuntimePolicyDecision(result.decision.decision);
  return decision === 'allow' || decision === 'warn';
}

function normalizeRuntimePolicyDecision(decision: ProtectResult['decision']['decision'] | string): ProtectResult['decision']['decision'] {
  return decision === 'require_approve' ? 'require_approval' : decision as ProtectResult['decision']['decision'];
}

function approvalInstruction(actionId: string): string {
  return (
    `Approve once (only after explicit user approval): agentguard approve --action-id ${actionId} --once.` +
    ' Do not run this approval command yourself unless the user explicitly approves this exact action.'
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function firstRecord(...values: unknown[]): Record<string, unknown> | undefined {
  for (const value of values) {
    if (isRecord(value)) return value;
  }
  return undefined;
}

function readOpenClawFilePath(event: unknown): string | undefined {
  const record = isRecord(event) ? event : undefined;
  const params = readOpenClawParams(event);
  const value =
    params?.path ??
    params?.file_path ??
    params?.filePath ??
    params?.target ??
    record?.path ??
    record?.file_path ??
    record?.filePath ??
    record?.target;
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * Default export for OpenClaw plugin registration.
 *
 * OpenClaw's native plugin contract loads an entry object with register(api),
 * while older loaders may call the default export directly. Functions are
 * objects in JavaScript, so this export supports both shapes without routing
 * OpenClaw through the package root default createAgentGuard() factory.
 *
 * Usage: export default from '@goplus/agentguard/openclaw'
 */
function register(api: OpenClawPluginApi): void {
  registerOpenClawPlugin(api);
}

const openClawEntry = Object.defineProperties(register, {
  id: { enumerable: true, value: 'agentguard' },
  name: { enumerable: true, value: 'GoPlus AgentGuard' },
  description: {
    enumerable: true,
    value: 'AI agent security framework - blocks dangerous commands, prevents data leaks, and protects secrets',
  },
  configSchema: {
    enumerable: true,
    value: {
      type: 'object',
      properties: {
        level: {
          type: 'string',
          enum: ['strict', 'balanced', 'permissive'],
          default: 'balanced',
          description: 'Protection level: strict (block all risky), balanced (block dangerous, confirm risky), permissive (only block critical)',
        },
      },
    },
  },
  register: { enumerable: true, value: register },
}) as OpenClawPluginEntry;

export default openClawEntry;
