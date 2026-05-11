import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

export interface AgentGuardConfig {
  version: 1;
  level: 'strict' | 'balanced' | 'permissive';
  cloudUrl?: string;
  apiKey?: string;
  connectedAt?: string;
  policyCachePath: string;
  auditPath: string;
  eventSpoolPath: string;
}

export interface AgentGuardPaths {
  home: string;
  configPath: string;
  policyCachePath: string;
  auditPath: string;
  eventSpoolPath: string;
}

const DEFAULT_CLOUD_URL = 'https://agentguard.gopluslabs.io';

export function getAgentGuardPaths(): AgentGuardPaths {
  const home = process.env.AGENTGUARD_HOME || join(homedir(), '.agentguard');
  return {
    home,
    configPath: join(home, 'config.json'),
    policyCachePath: join(home, 'policy-cache.json'),
    auditPath: join(home, 'audit.jsonl'),
    eventSpoolPath: join(home, 'events-spool.jsonl'),
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
  };
}

export function ensureAgentGuardHome(): AgentGuardPaths {
  const paths = getAgentGuardPaths();
  mkdirSync(paths.home, { recursive: true });
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
      cloudUrl: parsed.cloudUrl || fallback.cloudUrl,
      policyCachePath: parsed.policyCachePath || fallback.policyCachePath,
      auditPath: parsed.auditPath || fallback.auditPath,
      eventSpoolPath: parsed.eventSpoolPath || fallback.eventSpoolPath,
    };
  } catch {
    return fallback;
  }
}

export function saveConfig(config: AgentGuardConfig): void {
  const paths = ensureAgentGuardHome();
  mkdirSync(dirname(paths.configPath), { recursive: true });
  writeFileSync(paths.configPath, `${JSON.stringify(config, null, 2)}\n`);
}

export function connectCloud(options: { apiKey: string; cloudUrl?: string }): AgentGuardConfig {
  const current = ensureConfig();
  const next: AgentGuardConfig = {
    ...current,
    cloudUrl: normalizeCloudUrl(options.cloudUrl || current.cloudUrl || DEFAULT_CLOUD_URL),
    apiKey: options.apiKey,
    connectedAt: new Date().toISOString(),
  };
  saveConfig(next);
  return next;
}

export function maskApiKey(apiKey?: string): string {
  if (!apiKey) return 'not configured';
  if (apiKey.length <= 12) return `${apiKey.slice(0, 4)}…`;
  return `${apiKey.slice(0, 8)}…${apiKey.slice(-4)}`;
}

function normalizeCloudUrl(value: string): string {
  return value.replace(/\/+$/, '');
}

function normalizeLevel(value: unknown): AgentGuardConfig['level'] | null {
  return value === 'strict' || value === 'balanced' || value === 'permissive'
    ? value
    : null;
}
