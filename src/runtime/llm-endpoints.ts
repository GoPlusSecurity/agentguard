import { isIP } from 'node:net';
import type { LlmEndpointTier } from './types.js';

const T0_HOSTS = new Set(['localhost', 'ollama', 'lmstudio', 'host.docker.internal']);
const T1_HOSTS = [
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.mistral.ai',
  'api.cohere.com',
  'api.groq.com',
  'api.x.ai',
];
const T2_HOSTS = [
  'openrouter.ai',
  'openai.azure.com',
  'services.ai.azure.com',
  'bedrock-runtime.amazonaws.com',
  'aiplatform.googleapis.com',
];
const SHORTENER_HOSTS = [
  'bit.ly',
  't.co',
  'tinyurl.com',
  'is.gd',
  'cutt.ly',
  'shorturl.at',
];
const HIGH_RISK_TLDS = ['zip', 'mov', 'top', 'click', 'link', 'gq', 'tk', 'work'];

export interface NormalizedLlmEndpoint {
  url: string;
  scheme: string;
  hostname: string;
  port?: number;
  path: string;
  hadUserinfo: boolean;
}

export interface LlmEndpointClassification extends NormalizedLlmEndpoint {
  tier: LlmEndpointTier;
  reason:
    | 'local'
    | 'official_provider'
    | 'auditable_cloud'
    | 'configured_trusted'
    | 'unknown'
    | 'blocked_domain'
    | 'ip_literal'
    | 'shortener'
    | 'high_risk_tld'
    | 'invalid_url';
  redirected: boolean;
}

export interface LlmEndpointClassificationOptions {
  trustedEndpoints?: string[];
  blockedDomains?: string[];
  redirectTarget?: string;
}

export function normalizeLlmEndpoint(input: string): NormalizedLlmEndpoint {
  const raw = input.trim();
  if (!raw) throw new TypeError('LLM endpoint URL is empty');
  const parsed = new URL(hasScheme(raw) ? raw : `https://${raw}`);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new TypeError('LLM endpoint must use http or https');
  }

  const hadUserinfo = Boolean(parsed.username || parsed.password);
  parsed.username = '';
  parsed.password = '';
  const rawHostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  const hostname = stripIpv6Brackets(rawHostname);
  parsed.hostname = isIP(hostname) === 6 ? `[${hostname}]` : hostname;

  return {
    url: parsed.toString(),
    scheme: parsed.protocol.slice(0, -1),
    hostname,
    port: parsed.port ? Number(parsed.port) : undefined,
    path: `${parsed.pathname}${parsed.search}`,
    hadUserinfo,
  };
}

export function classifyLlmEndpoint(
  input: string,
  options: LlmEndpointClassificationOptions = {},
): LlmEndpointClassification {
  const selected = options.redirectTarget || input;
  let endpoint: NormalizedLlmEndpoint;
  try {
    endpoint = normalizeLlmEndpoint(selected);
  } catch {
    return {
      url: '',
      scheme: '',
      hostname: '',
      path: '',
      hadUserinfo: false,
      tier: 'T4',
      reason: 'invalid_url',
      redirected: Boolean(options.redirectTarget),
    };
  }

  const result = (tier: LlmEndpointTier, reason: LlmEndpointClassification['reason']): LlmEndpointClassification => ({
    ...endpoint,
    tier,
    reason,
    redirected: Boolean(options.redirectTarget),
  });

  if (isLocalEndpoint(endpoint)) return result('T0', 'local');
  if (matchesAnyDomain(endpoint.hostname, options.blockedDomains ?? [])) return result('T4', 'blocked_domain');
  if (isIP(endpoint.hostname)) return result('T4', 'ip_literal');
  if (matchesAnyDomain(endpoint.hostname, SHORTENER_HOSTS)) return result('T4', 'shortener');
  if (HIGH_RISK_TLDS.includes(lastLabel(endpoint.hostname))) return result('T4', 'high_risk_tld');
  if (isConfiguredTrusted(endpoint, options.trustedEndpoints ?? [])) return result('T2', 'configured_trusted');

  const standardHttpsPort = endpoint.scheme === 'https' && endpoint.port === undefined;
  if (standardHttpsPort && matchesAnyDomain(endpoint.hostname, T1_HOSTS)) return result('T1', 'official_provider');
  if (standardHttpsPort && isAuditableCloudHost(endpoint.hostname)) return result('T2', 'auditable_cloud');
  return result('T3', 'unknown');
}

function isLocalEndpoint(endpoint: NormalizedLlmEndpoint): boolean {
  const host = endpoint.hostname;
  if (T0_HOSTS.has(host) || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1' || host.startsWith('::ffff:127.')) return true;
  if (isIP(host) === 4) {
    const first = Number(host.split('.')[0]);
    return first === 127;
  }
  return false;
}

function isAuditableCloudHost(hostname: string): boolean {
  if (matchesAnyDomain(hostname, ['openrouter.ai'])) return true;
  if (/(?:^|\.)openai\.azure\.com$/.test(hostname)) return true;
  if (/(?:^|\.)services\.ai\.azure\.com$/.test(hostname)) return true;
  if (/^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/.test(hostname)) return true;
  if (/^[a-z0-9-]+-aiplatform\.googleapis\.com$/.test(hostname)) return true;
  return matchesAnyDomain(hostname, T2_HOSTS);
}

function isConfiguredTrusted(endpoint: NormalizedLlmEndpoint, configured: string[]): boolean {
  for (const item of configured) {
    try {
      const trusted = normalizeLlmEndpoint(item);
      if (trusted.hostname !== endpoint.hostname) continue;
      if (trusted.port !== undefined && trusted.port !== endpoint.port) continue;
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

function matchesAnyDomain(hostname: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    const candidate = endpointPatternHostname(pattern);
    return Boolean(candidate) && (hostname === candidate || hostname.endsWith(`.${candidate}`));
  });
}

function endpointPatternHostname(pattern: string): string {
  const trimmed = pattern.trim().toLowerCase().replace(/^\*\./, '');
  if (!trimmed) return '';
  try {
    return normalizeLlmEndpoint(trimmed).hostname;
  } catch {
    return trimmed.split('/')[0].replace(/\.$/, '');
  }
}

function hasScheme(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
}

function stripIpv6Brackets(value: string): string {
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}

function lastLabel(hostname: string): string {
  return hostname.split('.').at(-1) ?? '';
}
