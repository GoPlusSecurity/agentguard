import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

export type AgentGuardAgentHost = 'claude-code' | 'codex' | 'openclaw' | 'hermes' | 'qclaw';

export interface AgentGuardConfig {
  version: 1;
  level: 'strict' | 'balanced' | 'permissive';
  agentHost?: AgentGuardAgentHost;
  agentHosts?: AgentGuardAgentHost[];
  cloudUrl?: string;
  apiKey?: string;
  agentId?: string;
  agentJwt?: string;
  agentRegisterUrl?: string;
  agentRegisteredAt?: string;
  connectedAt?: string;
  threatFeedCronName?: string;
  threatFeedCronInstalledAt?: string;
  policyCachePath: string;
  auditPath: string;
  eventSpoolPath: string;
  approvalStorePath?: string;
}

export interface AgentGuardPaths {
  home: string;
  configPath: string;
  policyCachePath: string;
  auditPath: string;
  eventSpoolPath: string;
  approvalStorePath: string;
}

const DEFAULT_CLOUD_URL = 'https://agentguard.gopluslabs.io';
const API_KEY_PATTERN = /^ag_live_[A-Za-z0-9_-]{8,}$/;

export function getAgentGuardPaths(): AgentGuardPaths {
  const home = process.env.AGENTGUARD_HOME || join(homedir(), '.agentguard');
  return {
    home,
    configPath: join(home, 'config.json'),
    policyCachePath: join(home, 'policy-cache.json'),
    auditPath: join(home, 'audit.jsonl'),
    eventSpoolPath: join(home, 'events-spool.jsonl'),
    approvalStorePath: join(home, 'approvals.json'),
  };
}

export function defaultConfig(): AgentGuardConfig {
  const paths = getAgentGuardPaths();
  return {
    version: 1,
    level: 'balanced',
    cloudUrl: DEFAULT_CLOUD_URL,
    policyCachePath: paths.policyCachePath,
    auditPath: paths.auditPath,
    eventSpoolPath: paths.eventSpoolPath,
    approvalStorePath: paths.approvalStorePath,
  };
}

export function ensureAgentGuardHome(): AgentGuardPaths {
  const paths = getAgentGuardPaths();
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  chmodBestEffort(paths.home, 0o700);
  return paths;
}

export function ensureConfig(): AgentGuardConfig {
  const paths = ensureAgentGuardHome();
  if (!existsSync(paths.configPath)) {
    const config = defaultConfig();
    saveConfig(config);
    return config;
  }
  return loadConfig();
}

export function loadConfig(): AgentGuardConfig {
  const fallback = defaultConfig();
  try {
    const paths = getAgentGuardPaths();
    const parsed = JSON.parse(readFileSync(paths.configPath, 'utf8')) as Partial<AgentGuardConfig>;
    return {
      ...fallback,
      ...parsed,
      version: 1,
      level: normalizeLevel(parsed.level) ?? fallback.level,
      agentHost: normalizeAgentHost(parsed.agentHost),
      agentHosts: normalizeAgentHosts(parsed.agentHosts),
      cloudUrl: parsed.cloudUrl || fallback.cloudUrl,
      policyCachePath: parsed.policyCachePath || fallback.policyCachePath,
      auditPath: parsed.auditPath || fallback.auditPath,
      eventSpoolPath: parsed.eventSpoolPath || fallback.eventSpoolPath,
      approvalStorePath: parsed.approvalStorePath || fallback.approvalStorePath,
    };
  } catch {
    return fallback;
  }
}

export function saveConfig(config: AgentGuardConfig): void {
  const paths = ensureAgentGuardHome();
  mkdirSync(dirname(paths.configPath), { recursive: true });
  writeFileSync(paths.configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  chmodBestEffort(paths.configPath, 0o600);
}

export function connectCloud(options: { apiKey: string; cloudUrl?: string }): AgentGuardConfig {
  const current = ensureConfig();
  validateApiKey(options.apiKey);
  const next: AgentGuardConfig = {
    ...current,
    cloudUrl: normalizeCloudUrl(options.cloudUrl || current.cloudUrl || DEFAULT_CLOUD_URL),
    apiKey: options.apiKey,
    connectedAt: new Date().toISOString(),
  };
  delete next.agentId;
  delete next.agentJwt;
  delete next.agentRegisterUrl;
  delete next.agentRegisteredAt;
  saveConfig(next);
  return next;
}

export function connectAgentJwt(options: {
  agentId: string;
  agentJwt: string;
  agentRegisterUrl?: string;
  cloudUrl?: string;
}): AgentGuardConfig {
  const current = ensureConfig();
  const agentId = options.agentId.trim();
  const agentJwt = options.agentJwt.trim();
  if (!agentId) {
    throw new Error('Invalid Agent registration response: missing agentId.');
  }
  if (!agentJwt) {
    throw new Error('Invalid Agent registration response: missing jwt.');
  }
  const next: AgentGuardConfig = {
    ...current,
    cloudUrl: normalizeCloudUrl(options.cloudUrl || current.cloudUrl || DEFAULT_CLOUD_URL),
    agentId,
    agentJwt,
    agentRegisterUrl: options.agentRegisterUrl?.trim() || current.agentRegisterUrl,
    agentRegisteredAt: new Date().toISOString(),
    connectedAt: new Date().toISOString(),
  };
  delete next.apiKey;
  saveConfig(next);
  return next;
}

export function clearAgentJwt(config: AgentGuardConfig = ensureConfig()): AgentGuardConfig {
  const next: AgentGuardConfig = { ...config };
  delete next.agentId;
  delete next.agentJwt;
  delete next.agentRegisterUrl;
  delete next.agentRegisteredAt;
  saveConfig(next);
  return next;
}

export function clearAgentRegisterUrl(config: AgentGuardConfig = ensureConfig()): AgentGuardConfig {
  const next: AgentGuardConfig = { ...config };
  delete next.agentRegisterUrl;
  saveConfig(next);
  return next;
}

export function disconnectCloud(): AgentGuardConfig {
  const current = ensureConfig();
  const next: AgentGuardConfig = { ...current };
  delete next.apiKey;
  delete next.agentId;
  delete next.agentJwt;
  delete next.agentRegisterUrl;
  delete next.agentRegisteredAt;
  delete next.connectedAt;
  delete next.threatFeedCronName;
  delete next.threatFeedCronInstalledAt;
  rmSync(current.eventSpoolPath, { force: true });
  rmSync(current.policyCachePath, { force: true });
  saveConfig(next);
  return next;
}

export function maskApiKey(apiKey?: string): string {
  if (!apiKey) return 'not configured';
  if (apiKey.length <= 12) return `${apiKey.slice(0, 4)}…`;
  return `${apiKey.slice(0, 8)}…${apiKey.slice(-4)}`;
}

export function validateApiKey(apiKey: string): void {
  if (!API_KEY_PATTERN.test(apiKey)) {
    throw new Error('Invalid AgentGuard API key format. Expected an ag_live_ key.');
  }
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

export function normalizeCloudUrl(value: string): string {
  const normalized = value.replace(/\/+$/, '');
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error('Invalid Cloud URL.');
  }
  const isLoopback = LOOPBACK_HOSTS.has(parsed.hostname);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback)) {
    throw new Error(
      'Invalid Cloud URL. AgentGuard Cloud URLs must use https:// (http:// allowed only for loopback hosts).'
    );
  }
  return normalized;
}

function normalizeLevel(value: unknown): AgentGuardConfig['level'] | null {
  return value === 'strict' || value === 'balanced' || value === 'permissive'
    ? value
    : null;
}

function normalizeAgentHost(value: unknown): AgentGuardAgentHost | undefined {
  return value === 'claude-code' || value === 'codex' || value === 'openclaw' || value === 'hermes' || value === 'qclaw'
    ? value
    : undefined;
}

function normalizeAgentHosts(value: unknown): AgentGuardAgentHost[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const seen = new Set<AgentGuardAgentHost>();
  for (const item of value) {
    const host = normalizeAgentHost(item);
    if (host) seen.add(host);
  }
  return seen.size > 0 ? [...seen] : undefined;
}

function chmodBestEffort(path: string, mode: number): void {
  try {
    chmodSync(path, mode);
  } catch {
    // Best-effort hardening for platforms/filesystems that support chmod.
  }
}
