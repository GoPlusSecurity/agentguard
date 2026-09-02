import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { CapabilityModel } from '../types/skill.js';
import { loadSkillCapabilityManifest } from './capabilities.js';
import type { EffectiveRuntimePolicy } from './types.js';

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
    },
    updatedAt: new Date(0).toISOString(),
  };
}

export function loadCachedPolicy(cachePath: string): EffectiveRuntimePolicy | null {
  try {
    if (!existsSync(cachePath)) return null;
    return JSON.parse(readFileSync(cachePath, 'utf8')) as EffectiveRuntimePolicy;
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
        saveCachedPolicy(options.cachePath, cloudPolicy);
        return { policy: withLocalCapabilityManifest(cloudPolicy), source: 'cloud' };
      }
    } catch {
      // Fall through to cache/default.
    }
  }

  const cached = loadCachedPolicy(options.cachePath);
  if (cached) return { policy: withLocalCapabilityManifest(cached), source: 'cache' };
  return { policy: withLocalCapabilityManifest(getDefaultEffectiveRuntimePolicy()), source: 'default' };
}

/**
 * Overlay the local capability manifest (`capabilities.json`) onto the resolved
 * policy. Local entries take precedence over any cloud-supplied scope so an
 * operator can confine a skill without a cloud round-trip. Returns the policy
 * unchanged when no local manifest entries exist.
 */
function withLocalCapabilityManifest(policy: EffectiveRuntimePolicy): EffectiveRuntimePolicy {
  const local = loadSkillCapabilityManifest();
  if (Object.keys(local).length === 0) return policy;
  const merged: Record<string, Partial<CapabilityModel>> = {
    ...(policy.skillCapabilities || {}),
    ...local,
  };
  return { ...policy, skillCapabilities: merged };
}
