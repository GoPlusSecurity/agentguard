import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getAgentGuardPaths } from '../config.js';
import { DEFAULT_CAPABILITY } from '../types/skill.js';
import type { CapabilityModel } from '../types/skill.js';
import { domainMatchesPattern, extractDomain } from '../utils/patterns.js';
import type { EffectiveRuntimePolicy, PolicyReason, RuntimeAction } from './types.js';

/** Wildcard skill key applied to every declared-but-unmatched skill. */
const WILDCARD_SKILL = '*';

export const CAPABILITY_REASON_CODES = [
  'CAPABILITY_EXEC_DENIED',
  'CAPABILITY_NETWORK_DENIED',
  'CAPABILITY_FILE_DENIED',
] as const;

export function isCapabilityReason(code: string): boolean {
  return code.startsWith('CAPABILITY_');
}

export interface SkillScope {
  /** Effective least-privilege capabilities for the action's skill. */
  capabilities: CapabilityModel;
  /** True when the skill has an explicit manifest entry (is confined). */
  scoped: boolean;
}

/**
 * Merge a partial capability override onto the most-restrictive default so an
 * omitted field falls back to least privilege (DEFAULT_CAPABILITY).
 */
export function mergeCapabilities(override: Partial<CapabilityModel>): CapabilityModel {
  return {
    network_allowlist: override.network_allowlist ?? [...DEFAULT_CAPABILITY.network_allowlist],
    filesystem_allowlist: override.filesystem_allowlist ?? [...DEFAULT_CAPABILITY.filesystem_allowlist],
    exec: override.exec ?? DEFAULT_CAPABILITY.exec,
    secrets_allowlist: override.secrets_allowlist ?? [...DEFAULT_CAPABILITY.secrets_allowlist],
    ...(override.web3 ? { web3: override.web3 } : {}),
  };
}

/**
 * Resolve the capability scope for an action. A skill is "scoped" only when the
 * policy declares an entry for its sourceSkill (or a wildcard entry exists);
 * undeclared skills are left unconfined so existing behavior is preserved.
 */
export function resolveSkillScope(
  policy: EffectiveRuntimePolicy,
  action: RuntimeAction
): SkillScope {
  const manifest = policy.skillCapabilities;
  if (!manifest) return { capabilities: mergeCapabilities({}), scoped: false };

  const skillId = action.sourceSkill;
  const entry =
    (skillId && manifest[skillId]) ||
    manifest[WILDCARD_SKILL] ||
    undefined;

  if (!entry) return { capabilities: mergeCapabilities({}), scoped: false };
  return { capabilities: mergeCapabilities(entry), scoped: true };
}

/**
 * Produce capability-violation reasons for a confined skill. These are emitted
 * independently of the OSS threat scanner so a denial is honored even when the
 * action looks otherwise benign (the scanner's risk-score gate would auto-allow
 * it). Only exec / network / filesystem are enforced at runtime today; the
 * secrets allowlist has no runtime action mapping and is intentionally skipped.
 */
export function capabilityScopeReasons(
  capabilities: CapabilityModel,
  action: RuntimeAction
): PolicyReason[] {
  const reasons: PolicyReason[] = [];

  if (capabilities.exec === 'deny' && action.actionType === 'shell') {
    reasons.push({
      code: 'CAPABILITY_EXEC_DENIED',
      severity: 'high',
      title: 'Command execution not permitted for skill',
      description: `Skill "${action.sourceSkill}" is not granted the exec capability by its declared scope.`,
      evidence: truncate(action.input),
      remediation: 'Add `"exec": "allow"` to this skill\'s capability scope to permit command execution.',
    });
  }

  if (capabilities.network_allowlist.length > 0) {
    const denied = deniedNetworkTargets(action, capabilities.network_allowlist);
    if (denied.length > 0) {
      reasons.push({
        code: 'CAPABILITY_NETWORK_DENIED',
        severity: 'high',
        title: 'Network destination outside skill allowlist',
        description: `Skill "${action.sourceSkill}" attempted to reach a host not in its network allowlist.`,
        evidence: truncate(denied.join(', ')),
        remediation: 'Add the host to this skill\'s `network_allowlist` to permit the request.',
      });
    }
  }

  if (
    capabilities.filesystem_allowlist.length > 0 &&
    (action.actionType === 'file_read' || action.actionType === 'file_write') &&
    !filesystemAllowed(action.input, capabilities.filesystem_allowlist)
  ) {
    reasons.push({
      code: 'CAPABILITY_FILE_DENIED',
      severity: 'high',
      title: 'File path outside skill allowlist',
      description: `Skill "${action.sourceSkill}" attempted to access a path not in its filesystem allowlist.`,
      evidence: truncate(action.input),
      remediation: 'Add the path (or a `/**` prefix) to this skill\'s `filesystem_allowlist`.',
    });
  }

  return reasons;
}

/**
 * Load a local capability manifest (JSON map of skillId -> partial capability).
 * Best-effort: a missing or malformed file yields an empty manifest.
 */
export function loadSkillCapabilityManifest(
  manifestPath: string = capabilityManifestPath()
): Record<string, Partial<CapabilityModel>> {
  try {
    if (!existsSync(manifestPath)) return {};
    const parsed = JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown;
    return normalizeManifest(parsed);
  } catch {
    return {};
  }
}

export function capabilityManifestPath(): string {
  return process.env.AGENTGUARD_CAPABILITIES_PATH || join(getAgentGuardPaths().home, 'capabilities.json');
}

function normalizeManifest(value: unknown): Record<string, Partial<CapabilityModel>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, Partial<CapabilityModel>> = {};
  for (const [skillId, raw] of Object.entries(value as Record<string, unknown>)) {
    const entry = normalizeCapabilityEntry(raw);
    if (entry) out[skillId] = entry;
  }
  return out;
}

function normalizeCapabilityEntry(value: unknown): Partial<CapabilityModel> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const entry: Partial<CapabilityModel> = {};
  const network = stringArray(record.network_allowlist);
  const filesystem = stringArray(record.filesystem_allowlist);
  const secrets = stringArray(record.secrets_allowlist);
  if (network) entry.network_allowlist = network;
  if (filesystem) entry.filesystem_allowlist = filesystem;
  if (secrets) entry.secrets_allowlist = secrets;
  if (record.exec === 'allow' || record.exec === 'deny') entry.exec = record.exec;
  return entry;
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === 'string');
}

function deniedNetworkTargets(action: RuntimeAction, allowlist: string[]): string[] {
  const denied: string[] = [];
  for (const reference of networkReferences(action)) {
    const domain = referenceToDomain(reference);
    if (!domain) continue;
    if (!allowlist.some((pattern) => domainMatchesPattern(domain, pattern))) denied.push(domain);
  }
  return [...new Set(denied)];
}

function networkReferences(action: RuntimeAction): string[] {
  if (action.actionType === 'network' || action.actionType === 'browser') {
    return [action.input];
  }
  if (action.actionType === 'shell') {
    return [...action.input.matchAll(/https?:\/\/[^\s'"`<>]+/gi)].map((match) => match[0]);
  }
  return [];
}

function referenceToDomain(reference: string): string | null {
  const trimmed = reference.trim().replace(/[),.;\]]+$/g, '');
  if (!trimmed) return null;
  const urlLike = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const domain = extractDomain(urlLike);
  return domain ? domain.toLowerCase() : null;
}

/** Mirror ActionScanner.handleFileOperation allowlist matching. */
function filesystemAllowed(path: string, allowlist: string[]): boolean {
  return allowlist.some((pattern) => {
    if (pattern === '*') return true;
    if (pattern.endsWith('/**')) return path.startsWith(pattern.slice(0, -3));
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2);
      const remainder = path.slice(prefix.length);
      return path.startsWith(prefix) && !remainder.includes('/');
    }
    return path === pattern || path.startsWith(`${pattern}/`);
  });
}

function truncate(value: string, max = 200): string {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}
