import { readFileSync, appendFileSync, mkdirSync, existsSync, statSync, renameSync, unlinkSync } from 'node:fs';
import { join, resolve, normalize } from 'node:path';
import { homedir } from 'node:os';
import type { HookInput, HookOutput } from './types.js';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const AGENTGUARD_DIR = process.env.OPENCLAW_STATE_DIR
  ? join(process.env.OPENCLAW_STATE_DIR, 'agentguard')
  : process.env.AGENTGUARD_HOME || join(homedir(), '.agentguard');
const CONFIG_PATH = join(AGENTGUARD_DIR, 'config.json');
const AUDIT_PATH = join(AGENTGUARD_DIR, 'audit.jsonl');

function ensureDir(): void {
  if (!existsSync(AGENTGUARD_DIR)) {
    mkdirSync(AGENTGUARD_DIR, { recursive: true });
  }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const VALID_LEVELS = new Set(['strict', 'balanced', 'permissive']);

export function loadConfig(): { level: string } {
  try {
    const parsed = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
    const level = typeof parsed?.level === 'string' && VALID_LEVELS.has(parsed.level)
      ? parsed.level
      : 'balanced';
    return { level };
  } catch {
    return { level: 'balanced' };
  }
}

// ---------------------------------------------------------------------------
// Prototype pollution guard
// ---------------------------------------------------------------------------

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Check whether an object (or any nested descendant) contains keys
 * that could trigger prototype pollution when merged or spread.
 */
export function containsProtoKeys(obj: unknown): boolean {
  if (obj === null || typeof obj !== 'object') return false;

  if (Array.isArray(obj)) {
    return obj.some(containsProtoKeys);
  }

  for (const key of Object.getOwnPropertyNames(obj)) {
    if (DANGEROUS_KEYS.has(key)) return true;
    if (containsProtoKeys((obj as Record<string, unknown>)[key])) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Safe string extraction
// ---------------------------------------------------------------------------

/**
 * Safely extract a string from unknown data.
 */
export function getString(obj: Record<string, unknown>, key: string): string {
  const val = obj[key];
  return typeof val === 'string' ? val : '';
}

// ---------------------------------------------------------------------------
// Sensitive path detection
// ---------------------------------------------------------------------------

const SENSITIVE_PATHS = [
  // Environment / dotenv
  '.env', '.env.local', '.env.production', '.env.staging', '.env.development',
  // SSH
  '.ssh/', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa',
  // AWS
  '.aws/credentials', '.aws/config',
  // npm / package managers
  '.npmrc', '.yarnrc',
  // Network auth
  '.netrc',
  // GCP
  'credentials.json', 'serviceAccountKey.json',
  // Kubernetes
  '.kube/config',
  // GPG
  '.gnupg/',
  // Docker
  '.docker/config.json',
  // Git credentials
  '.git-credentials',
  // Wallet / crypto
  '.bitcoin/wallet.dat',
  'keystore/',
];

export function isSensitivePath(filePath: string): boolean {
  if (!filePath) return false;
  // Resolve to absolute and normalize to prevent traversal bypasses
  const normalized = resolve(normalize(filePath)).replace(/\\/g, '/');
  return SENSITIVE_PATHS.some(
    (p) => normalized.includes(`/${p}`) || normalized.endsWith(p)
  );
}

// ---------------------------------------------------------------------------
// Protection level thresholds
// ---------------------------------------------------------------------------

export function shouldDenyAtLevel(
  decision: { decision: string; risk_level?: string },
  config: { level?: string }
): boolean {
  const level = config.level || 'balanced';

  if (level === 'strict') {
    return decision.decision === 'deny' || decision.decision === 'confirm';
  }

  if (level === 'balanced') {
    return decision.decision === 'deny';
  }

  if (level === 'permissive') {
    return decision.decision === 'deny' && decision.risk_level === 'critical';
  }

  return decision.decision === 'deny';
}

export function shouldAskAtLevel(
  decision: { decision: string; risk_level?: string },
  config: { level?: string }
): boolean {
  const level = config.level || 'balanced';

  if (level === 'strict') {
    return false;
  }

  if (level === 'balanced') {
    return decision.decision === 'confirm';
  }

  if (level === 'permissive') {
    return (
      (decision.decision === 'deny' && decision.risk_level !== 'critical') ||
      (decision.decision === 'confirm' &&
        (decision.risk_level === 'high' || decision.risk_level === 'critical'))
    );
  }

  return decision.decision === 'confirm';
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

const MAX_AUDIT_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_AUDIT_FILES = 3;

function rotateAuditLogIfNeeded(): void {
  try {
    if (!existsSync(AUDIT_PATH)) return;
    const stat = statSync(AUDIT_PATH);
    if (stat.size < MAX_AUDIT_SIZE) return;

    // Rotate: .3 -> delete, .2 -> .3, .1 -> .2, current -> .1
    const oldest = `${AUDIT_PATH}.${MAX_AUDIT_FILES}`;
    if (existsSync(oldest)) {
      try { unlinkSync(oldest); } catch { /* ok */ }
    }
    for (let i = MAX_AUDIT_FILES - 1; i >= 1; i--) {
      const from = `${AUDIT_PATH}.${i}`;
      const to = `${AUDIT_PATH}.${i + 1}`;
      if (existsSync(from)) {
        try { renameSync(from, to); } catch { /* ok */ }
      }
    }
    renameSync(AUDIT_PATH, `${AUDIT_PATH}.1`);
  } catch {
    // Non-critical -- rotation failure should not block logging
  }
}

/**
 * Redact common secret patterns from a string before logging.
 */
function redactSecrets(value: string): string {
  return value
    // Bearer / Authorization tokens
    .replace(/Bearer\s+[A-Za-z0-9\-_.]+/gi, 'Bearer [REDACTED]')
    // AWS keys
    .replace(/(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, '$1[REDACTED]')
    // Generic key=value secrets
    .replace(/(api[_-]?key|api[_-]?secret|secret[_-]?key|password|token|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{8,}/gi,
      (match) => match.slice(0, match.indexOf('=') + 1 || match.indexOf(':') + 1) + '[REDACTED]')
    // Hex private keys (64 chars)
    .replace(/0x[a-fA-F0-9]{64}/g, '0x[REDACTED_KEY]')
    // SSH keys
    .replace(/-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----/g, '[REDACTED_SSH_KEY]');
}

export function writeAuditLog(
  input: HookInput,
  decision: { decision?: string; risk_level?: string; risk_tags?: string[] } | null,
  initiatingSkill?: string | null
): void {
  try {
    ensureDir();
    rotateAuditLogIfNeeded();
    const entry: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      tool_name: input.toolName,
      tool_input_summary: summarizeToolInput(input),
      decision: decision?.decision || 'allow',
      risk_level: decision?.risk_level || 'low',
      risk_tags: decision?.risk_tags || [],
    };
    if (initiatingSkill) {
      entry.initiating_skill = initiatingSkill;
    }
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n', { mode: 0o600 });
  } catch {
    // Non-critical
  }
}

function summarizeToolInput(input: HookInput): string {
  const toolInput = input.toolInput;
  if (typeof toolInput === 'object' && toolInput !== null) {
    const cmd = (toolInput as Record<string, unknown>).command;
    if (typeof cmd === 'string') return redactSecrets(cmd.slice(0, 200));
    const fp = (toolInput as Record<string, unknown>).file_path ||
      (toolInput as Record<string, unknown>).path;
    if (typeof fp === 'string') return fp.slice(0, 200);
    const url = (toolInput as Record<string, unknown>).url ||
      (toolInput as Record<string, unknown>).query;
    if (typeof url === 'string') return redactSecrets(url.slice(0, 200));
  }
  return redactSecrets(JSON.stringify(toolInput).slice(0, 200));
}

// ---------------------------------------------------------------------------
// Skill trust policy helpers
// ---------------------------------------------------------------------------

export async function getSkillTrustPolicy(
  skillId: string,
  registry: { lookup: (s: { id: string; source: string; version_ref: string; artifact_hash: string }) => Promise<{ effective_trust_level: string; effective_capabilities: Record<string, unknown>; record: unknown | null }> }
): Promise<{ trustLevel: string | null; capabilities: Record<string, unknown> | null; isKnown: boolean }> {
  if (!skillId) {
    return { trustLevel: null, capabilities: null, isKnown: false };
  }
  try {
    const result = await registry.lookup({
      id: skillId,
      source: skillId,
      version_ref: '0.0.0',
      artifact_hash: '',
    });
    return {
      trustLevel: result.effective_trust_level,
      capabilities: result.effective_capabilities,
      isKnown: result.record !== null,
    };
  } catch {
    return { trustLevel: null, capabilities: null, isKnown: false };
  }
}

export function isActionAllowedByCapabilities(
  actionType: string,
  capabilities: Record<string, unknown>
): boolean {
  if (!capabilities) return true;
  switch (actionType) {
    case 'exec_command':
      return capabilities.can_exec !== false;
    case 'network_request':
      return capabilities.can_network !== false;
    case 'write_file':
      return capabilities.can_write !== false;
    case 'read_file':
      return capabilities.can_read !== false;
    case 'web3_tx':
    case 'web3_sign':
      return capabilities.can_web3 !== false;
    default:
      // Fail-closed: unknown action types are denied by default
      return false;
  }
}
