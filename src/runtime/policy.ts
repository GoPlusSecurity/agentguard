import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { CloudPolicyDecision, EffectiveRuntimePolicy, PiiCategory } from './types.js';

const PRIVACY_CATEGORIES: PiiCategory[] = [
  'national_id',
  'bank_account',
  'biometric',
  'minor_data',
  'health_record',
  'location_trace',
  'contact_dump',
  'phone_number',
  'email_address',
  'hardcoded_dataset',
];

export function getDefaultEffectiveRuntimePolicy(): EffectiveRuntimePolicy {
  return {
    policyVersion: 'runtime-local-v0.1',
    mode: 'balanced',
    decisions: {
      destructiveCommand: 'block',
      remoteCodeExecution: 'require_approval',
      dataExfiltration: 'block',
      secretAccess: 'require_approval',
      deployAction: 'require_approval',
    },
    protectedPaths: [
      '~/.ssh/**',
      '~/.aws/**',
      '~/.config/**/credentials*',
      '**/.env*',
      '**/*private-key*',
      '**/*seed*',
    ],
    blockedCommandPatterns: [
      'rm -rf /',
      'base64 -d | bash',
      'git push --force',
    ],
    allowedCommandPatterns: [],
    approvalActionTypes: ['file_read', 'file_write', 'mcp_tool', 'skill_install', 'deploy'],
    network: {
      defaultOutbound: 'warn',
      blockedDomains: [
        'discord.com/api/webhooks',
        'hooks.slack.com/services',
        'api.telegram.org/bot',
      ],
      approvalDomains: [],
      behaviorAnomaly: 'require_approval',
      untrustedLlmEndpoint: 'require_approval',
      trustedLlmEndpoints: [],
    },
    privacy: {
      piiEgressTrusted: 'warn',
      piiEgressUntrusted: 'require_approval',
      enabledCategories: [...PRIVACY_CATEGORIES],
      bulkEgressBytes: 1024 * 1024,
      bulkAttachmentBytes: 5 * 1024 * 1024,
      bulkFilePathCount: 20,
    },
    updatedAt: new Date(0).toISOString(),
  };
}

export function loadCachedPolicy(cachePath: string): EffectiveRuntimePolicy | null {
  try {
    if (!existsSync(cachePath)) return null;
    return normalizeEffectiveRuntimePolicy(JSON.parse(readFileSync(cachePath, 'utf8')));
  } catch {
    return null;
  }
}

export function saveCachedPolicy(cachePath: string, policy: EffectiveRuntimePolicy): void {
  mkdirSync(dirname(cachePath), { recursive: true });
  writeFileSync(cachePath, `${JSON.stringify(policy, null, 2)}\n`);
}

export async function resolveRuntimePolicy(options: {
  cachePath: string;
  fetchPolicy?: () => Promise<EffectiveRuntimePolicy | null>;
}): Promise<{ policy: EffectiveRuntimePolicy; source: 'cloud' | 'cache' | 'default' }> {
  if (options.fetchPolicy) {
    try {
      const cloudPolicy = await options.fetchPolicy();
      if (cloudPolicy) {
        const normalizedPolicy = normalizeEffectiveRuntimePolicy(cloudPolicy);
        saveCachedPolicy(options.cachePath, normalizedPolicy);
        return { policy: normalizedPolicy, source: 'cloud' };
      }
    } catch {
      // Fall through to cache/default.
    }
  }

  const cached = loadCachedPolicy(options.cachePath);
  if (cached) return { policy: cached, source: 'cache' };
  return { policy: getDefaultEffectiveRuntimePolicy(), source: 'default' };
}

export function normalizeEffectiveRuntimePolicy(value: unknown): EffectiveRuntimePolicy {
  const defaults = getDefaultEffectiveRuntimePolicy();
  if (!isRecord(value)) return defaults;

  const decisions = isRecord(value.decisions) ? value.decisions : {};
  const network = isRecord(value.network) ? value.network : {};
  const privacy = isRecord(value.privacy) ? value.privacy : {};

  return {
    policyVersion: stringValue(value.policyVersion) ?? defaults.policyVersion,
    mode: value.mode === 'observe' || value.mode === 'balanced' || value.mode === 'strict'
      ? value.mode
      : defaults.mode,
    decisions: {
      destructiveCommand: decisionValue(decisions.destructiveCommand) ?? defaults.decisions.destructiveCommand,
      remoteCodeExecution: decisionValue(decisions.remoteCodeExecution) ?? defaults.decisions.remoteCodeExecution,
      dataExfiltration: decisionValue(decisions.dataExfiltration) ?? defaults.decisions.dataExfiltration,
      secretAccess: decisionValue(decisions.secretAccess) ?? defaults.decisions.secretAccess,
      deployAction: decisionValue(decisions.deployAction) ?? defaults.decisions.deployAction,
    },
    protectedPaths: stringArray(value.protectedPaths) ?? defaults.protectedPaths,
    filesystemAllowlist: stringArray(value.filesystemAllowlist),
    blockedCommandPatterns: stringArray(value.blockedCommandPatterns) ?? defaults.blockedCommandPatterns,
    allowedCommandPatterns: stringArray(value.allowedCommandPatterns) ?? defaults.allowedCommandPatterns,
    approvalActionTypes: runtimeActionTypeArray(value.approvalActionTypes) ?? defaults.approvalActionTypes,
    network: {
      defaultOutbound: decisionValue(network.defaultOutbound) ?? defaults.network.defaultOutbound,
      blockedDomains: stringArray(network.blockedDomains) ?? defaults.network.blockedDomains,
      approvalDomains: stringArray(network.approvalDomains) ?? defaults.network.approvalDomains,
      behaviorAnomaly: decisionValue(network.behaviorAnomaly) ?? defaults.network.behaviorAnomaly,
      responseAnomaly: decisionValue(network.responseAnomaly),
      untrustedLlmEndpoint: decisionValue(network.untrustedLlmEndpoint) ?? defaults.network.untrustedLlmEndpoint,
      trustedLlmEndpoints: stringArray(network.trustedLlmEndpoints) ?? defaults.network.trustedLlmEndpoints,
    },
    privacy: {
      piiEgressTrusted: decisionValue(privacy.piiEgressTrusted) ?? defaults.privacy.piiEgressTrusted,
      piiEgressUntrusted: decisionValue(privacy.piiEgressUntrusted) ?? defaults.privacy.piiEgressUntrusted,
      enabledCategories: piiCategoryArray(privacy.enabledCategories) ?? defaults.privacy.enabledCategories,
      bulkEgressBytes: nonNegativeInteger(privacy.bulkEgressBytes) ?? defaults.privacy.bulkEgressBytes,
      bulkAttachmentBytes: nonNegativeInteger(privacy.bulkAttachmentBytes) ?? defaults.privacy.bulkAttachmentBytes,
      bulkFilePathCount: nonNegativeInteger(privacy.bulkFilePathCount) ?? defaults.privacy.bulkFilePathCount,
    },
    updatedAt: stringValue(value.updatedAt) ?? defaults.updatedAt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function stringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return undefined;
  return [...value];
}

function decisionValue(value: unknown): CloudPolicyDecision | undefined {
  return value === 'allow' || value === 'warn' || value === 'require_approval' || value === 'block'
    ? value
    : undefined;
}

function nonNegativeInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function piiCategoryArray(value: unknown): PiiCategory[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const categories = value.filter((item): item is PiiCategory =>
    typeof item === 'string' && PRIVACY_CATEGORIES.includes(item as PiiCategory)
  );
  return categories.length === value.length ? categories : undefined;
}

function runtimeActionTypeArray(value: unknown): EffectiveRuntimePolicy['approvalActionTypes'] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) return undefined;
  return value as EffectiveRuntimePolicy['approvalActionTypes'];
}
