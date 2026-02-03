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
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  let shouldBlock = false;
  let blockReason: string | undefined;

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
  if (!isAllowed && !isWebhook) {
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

  // POST/PUT to untrusted domain is higher risk
  if (
    (request.method === 'POST' || request.method === 'PUT') &&
    !isAllowed &&
    riskLevel === 'medium'
  ) {
    riskLevel = 'high';
  }

  return {
    risk_level: riskLevel,
    risk_tags: riskTags,
    evidence,
    should_block: shouldBlock,
    block_reason: blockReason,
  };
}
