import type { NetworkRequestData, ActionEvidence } from '../../types/action.js';
import { extractDomain, isDomainAllowed } from '../../utils/patterns.js';
import { detectSecretLeak, containsCriticalSecrets } from './secret-leak.js';

/**
 * Network request analysis result
 */
export interface NetworkAnalysisResult {
  /** Risk level */
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  /** Risk tags */
  risk_tags: string[];
  /** Evidence */
  evidence: ActionEvidence[];
  /** Should block */
  should_block: boolean;
  /** Block reason */
  block_reason?: string;
}

type NetworkRiskLevel = NetworkAnalysisResult['risk_level'];
type NetworkMethod = NetworkRequestData['method'];

/**
 * Known webhook/exfiltration domains
 */
const WEBHOOK_DOMAINS = [
  'discord.com',
  'discordapp.com',
  'api.telegram.org',
  'hooks.slack.com',
  'webhook.site',
  'requestbin.com',
  'pipedream.com',
  'ngrok.io',
  'ngrok-free.app',
  'beeceptor.com',
  'mockbin.org',
  'workers.dev',
  'vercel.app',
  'netlify.app',
  'deno.dev',
  'burpcollaborator.net',
  'interact.sh',
  'oast.pro',
];

/**
 * Known malicious TLDs (high risk)
 */
const HIGH_RISK_TLDS = [
  '.xyz',
  '.top',
  '.tk',
  '.ml',
  '.ga',
  '.cf',
  '.gq',
  '.work',
  '.click',
  '.link',
];

/**
 * Analyze a network request for security risks
 */
export function analyzeNetworkRequest(
  request: NetworkRequestData,
  allowlist: string[] = []
): NetworkAnalysisResult {
  const riskTags: string[] = [];
  const evidence: ActionEvidence[] = [];
  let riskLevel: NetworkRiskLevel = 'low';
  let shouldBlock = false;
  let blockReason: string | undefined;
  const method = normalizeMethod(request.method);
  const readOnlyMethod = isReadOnlyMethod(method);
  const mutatingMethod = method === 'POST' || method === 'PUT' || method === 'PATCH';

  // Extract domain
  const domain = extractDomain(request.url);

  if (!domain) {
    return {
      risk_level: 'high',
      risk_tags: ['INVALID_URL'],
      evidence: [
        {
          type: 'invalid_url',
          field: 'url',
          match: request.url,
          description: 'Could not parse URL',
        },
      ],
      should_block: true,
      block_reason: 'Invalid URL',
    };
  }

  // Check if domain is in allowlist
  const isAllowed = isDomainAllowed(domain, allowlist);

  // Check for webhook domains
  const isWebhook = WEBHOOK_DOMAINS.some(
    (d) => domain === d || domain.endsWith('.' + d)
  );

  if (isWebhook) {
    riskTags.push('WEBHOOK_EXFIL');
    evidence.push({
      type: 'webhook_domain',
      field: 'url',
      match: domain,
      description: `Webhook/exfiltration domain detected: ${domain}`,
    });
    riskLevel = 'high';

    if (!isAllowed) {
      shouldBlock = true;
      blockReason = 'Webhook domain not in allowlist';
    }
  }

  // Check for high-risk TLDs
  const hasHighRiskTLD = HIGH_RISK_TLDS.some((tld) => domain.endsWith(tld));

  if (hasHighRiskTLD && !isAllowed) {
    riskTags.push('HIGH_RISK_TLD');
    evidence.push({
      type: 'high_risk_tld',
      field: 'url',
      match: domain,
      description: `High-risk TLD detected`,
    });
    if (riskLevel === 'low') riskLevel = 'medium';
  }

  // Check for untrusted domain
  if (!isAllowed && !isWebhook && !readOnlyMethod) {
    riskTags.push('UNTRUSTED_DOMAIN');
    evidence.push({
      type: 'untrusted_domain',
      field: 'url',
      match: domain,
      description: `Domain not in allowlist`,
    });
    if (riskLevel === 'low') riskLevel = 'medium';
  }

  // Check request body for sensitive data
  if (request.body_preview) {
    // Check for critical secrets (private keys, mnemonics)
    if (containsCriticalSecrets(request.body_preview)) {
      riskTags.push('CRITICAL_SECRET_EXFIL');
      evidence.push({
        type: 'critical_secret',
        field: 'body',
        description: 'Request body contains private key or mnemonic',
      });
      riskLevel = 'critical';
      shouldBlock = true;
      blockReason = 'Attempt to exfiltrate private key or mnemonic';
    } else {
      // Check for other sensitive data
      const secretLeak = detectSecretLeak(request.body_preview);

      if (secretLeak.found) {
        riskTags.push('POTENTIAL_SECRET_EXFIL');
        evidence.push(...secretLeak.evidence);

        if (secretLeak.risk_level === 'critical') {
          riskLevel = 'critical';
          shouldBlock = true;
          blockReason = `Attempt to exfiltrate: ${secretLeak.secret_types.join(', ')}`;
        } else if (secretLeak.risk_level === 'high') {
          riskLevel = 'high';
        }
      }
    }
  }

  if (method === 'DELETE') {
    riskTags.push('DESTRUCTIVE_HTTP_METHOD');
    evidence.push({
      type: 'destructive_http_method',
      field: 'method',
      match: method,
      description: 'DELETE requests can remove remote resources',
    });
    riskLevel = maxRisk(riskLevel, 'high');
  }

  if (mutatingMethod && !isAllowed && !riskTags.includes('CRITICAL_SECRET_EXFIL')) {
    riskTags.push('MUTATING_UNTRUSTED_REQUEST');
    evidence.push({
      type: 'mutating_untrusted_request',
      field: 'method',
      match: method,
      description: `${method} request to a non-allowlisted domain`,
    });
    riskLevel = maxRisk(riskLevel, 'medium');
  }

  return {
    risk_level: riskLevel,
    risk_tags: riskTags,
    evidence,
    should_block: shouldBlock,
    block_reason: blockReason,
  };
}

function normalizeMethod(method: string | undefined): NetworkMethod {
  const normalized = method?.toUpperCase();
  switch (normalized) {
    case 'GET':
    case 'HEAD':
    case 'OPTIONS':
    case 'POST':
    case 'PUT':
    case 'DELETE':
    case 'PATCH':
      return normalized;
    default:
      return 'GET';
  }
}

function isReadOnlyMethod(method: NetworkMethod): boolean {
  return method === 'GET' || method === 'HEAD' || method === 'OPTIONS';
}

const RISK_ORDER: Record<NetworkRiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function maxRisk(current: NetworkRiskLevel, next: NetworkRiskLevel): NetworkRiskLevel {
  return RISK_ORDER[next] > RISK_ORDER[current] ? next : current;
}
