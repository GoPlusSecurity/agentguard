import type { SkillIdentity, CapabilityModel } from './skill.js';

/**
 * Trust levels for skills
 */
export type TrustLevel = 'untrusted' | 'restricted' | 'trusted';

/**
 * Record status
 */
export type RecordStatus = 'active' | 'revoked';

/**
 * Review information
 */
export interface ReviewInfo {
  /** Who reviewed this skill */
  reviewed_by: string;
  /** When the review happened */
  reviewed_at: string;
  /** References to evidence (e.g., scan IDs) */
  evidence_refs: string[];
  /** Review notes */
  notes: string;
}

/**
 * Trust record in the registry
 */
export interface TrustRecord {
  /** Unique key: source@version#hash */
  record_key: string;
  /** Skill identity */
  skill: SkillIdentity;
  /** Trust level */
  trust_level: TrustLevel;
  /** Capability snapshot */
  capabilities: CapabilityModel;
  /** Expiration time (ISO 8601) */
  expires_at?: string;
  /** Review information */
  review: ReviewInfo;
  /** Record status */
  status: RecordStatus;
  /** Created timestamp */
  created_at: string;
  /** Updated timestamp */
  updated_at: string;
}

/**
 * Request to attest (add/update) a trust record
 */
export interface AttestRequest {
  /** Skill identity */
  skill: SkillIdentity;
  /** Trust level to assign */
  trust_level: TrustLevel;
  /** Capabilities to grant */
  capabilities: CapabilityModel;
  /** Optional expiration */
  expires_at?: string;
  /** Review information */
  review: Omit<ReviewInfo, 'reviewed_at'>;
}

/**
 * Match criteria for revocation
 */
export interface RevokeMatch {
  /** Source pattern (exact or wildcard) */
  source?: string;
  /** Version pattern */
  version_ref?: string;
  /** Specific record key */
  record_key?: string;
}

/**
 * Filters for listing records
 */
export interface ListFilters {
  /** Filter by trust level */
  trust_level?: TrustLevel;
  /** Filter by status */
  status?: RecordStatus;
  /** Filter by source pattern */
  source_pattern?: string;
  /** Include expired records */
  include_expired?: boolean;
}

/**
 * Registry storage format
 */
export interface RegistryData {
  /** Schema version */
  version: number;
  /** Last updated timestamp */
  updated_at: string;
  /** Trust records */
  records: TrustRecord[];
}

/**
 * Check if a record is expired
 */
export function isRecordExpired(record: TrustRecord): boolean {
  if (!record.expires_at) return false;
  return new Date(record.expires_at) < new Date();
}

/**
 * Check if skill matches a record (considering hash)
 */
export function skillMatchesRecord(skill: SkillIdentity, record: TrustRecord): boolean {
  return (
    skill.source === record.skill.source &&
    skill.version_ref === record.skill.version_ref &&
    skill.artifact_hash === record.skill.artifact_hash
  );
}
