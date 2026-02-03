import type {
  TrustRecord,
  TrustLevel,
  AttestRequest,
  RevokeMatch,
  ListFilters,
} from '../types/registry.js';
import type { SkillIdentity, CapabilityModel } from '../types/skill.js';
import { generateRecordKey, DEFAULT_CAPABILITY } from '../types/skill.js';
import { isRecordExpired, skillMatchesRecord } from '../types/registry.js';
import { RegistryStorage, type StorageOptions } from './storage.js';
import {
  createTrustRecord,
  needsReevaluation,
  isCapabilityEscalation,
  isTrustUpgrade,
} from './trust.js';

/**
 * Registry options
 */
export interface RegistryOptions extends StorageOptions {
  /** Auto-downgrade on hash/version change */
  autoDowngrade?: boolean;
  /** Require confirmation for trust upgrades */
  requireConfirmForUpgrade?: boolean;
}

/**
 * Lookup result
 */
export interface LookupResult {
  /** Found record (if any) */
  record: TrustRecord | null;
  /** Effective trust level (considering expiry, hash changes) */
  effective_trust_level: TrustLevel;
  /** Effective capabilities */
  effective_capabilities: CapabilityModel;
  /** Reason if trust was modified */
  modification_reason?: string;
}

/**
 * Attest result
 */
export interface AttestResult {
  /** Success */
  success: boolean;
  /** Record key */
  record_key: string;
  /** Requires confirmation */
  requires_confirmation: boolean;
  /** Confirmation reasons */
  confirmation_reasons?: string[];
  /** Created or updated */
  action: 'created' | 'updated';
}

/**
 * Skill Registry - Module B
 * Manages trusted/restricted/untrusted skill records
 */
export class SkillRegistry {
  private storage: RegistryStorage;
  private options: RegistryOptions;

  constructor(options: RegistryOptions = {}) {
    this.options = {
      autoDowngrade: true,
      requireConfirmForUpgrade: true,
      ...options,
    };
    this.storage = new RegistryStorage(options);
  }

  /**
   * Look up a skill's trust record
   */
  async lookup(skill: SkillIdentity): Promise<LookupResult> {
    const recordKey = generateRecordKey(skill);

    // Try exact match first
    let record = await this.storage.findByKey(recordKey);

    // If not found, check for records with same source but different hash/version
    if (!record) {
      const sourceRecords = await this.storage.findBySource(skill.source);

      // Find best matching record
      for (const r of sourceRecords) {
        if (r.skill.version_ref === skill.version_ref) {
          record = r;
          break;
        }
      }

      // If still not found, use any record from same source
      if (!record && sourceRecords.length > 0) {
        record = sourceRecords[0];
      }
    }

    // No record found - return untrusted
    if (!record) {
      return {
        record: null,
        effective_trust_level: 'untrusted',
        effective_capabilities: DEFAULT_CAPABILITY,
      };
    }

    // Check if record matches exactly
    const exactMatch = skillMatchesRecord(skill, record);

    // Check expiry
    if (isRecordExpired(record)) {
      return {
        record,
        effective_trust_level: 'untrusted',
        effective_capabilities: DEFAULT_CAPABILITY,
        modification_reason: 'record_expired',
      };
    }

    // Check for hash/version changes
    if (!exactMatch && this.options.autoDowngrade) {
      const evaluation = needsReevaluation(record, skill);

      if (evaluation.needsReevaluation) {
        return {
          record,
          effective_trust_level: 'untrusted',
          effective_capabilities: DEFAULT_CAPABILITY,
          modification_reason: evaluation.reason,
        };
      }
    }

    // Check if revoked
    if (record.status === 'revoked') {
      return {
        record,
        effective_trust_level: 'untrusted',
        effective_capabilities: DEFAULT_CAPABILITY,
        modification_reason: 'record_revoked',
      };
    }

    // Return the record's trust level and capabilities
    return {
      record,
      effective_trust_level: record.trust_level,
      effective_capabilities: record.capabilities,
    };
  }

  /**
   * Attest (add/update) a trust record
   */
  async attest(request: AttestRequest): Promise<AttestResult> {
    const { skill, trust_level, capabilities, expires_at, review } = request;
    const recordKey = generateRecordKey(skill);

    // Check for existing record
    const existingRecord = await this.storage.findByKey(recordKey);

    let requiresConfirmation = false;
    const confirmationReasons: string[] = [];

    if (existingRecord) {
      // Check for trust upgrade
      if (
        this.options.requireConfirmForUpgrade &&
        isTrustUpgrade(existingRecord.trust_level, trust_level)
      ) {
        requiresConfirmation = true;
        confirmationReasons.push(
          `Trust upgrade: ${existingRecord.trust_level} -> ${trust_level}`
        );
      }

      // Check for capability escalation
      const escalation = isCapabilityEscalation(
        existingRecord.capabilities,
        capabilities
      );

      if (escalation.isEscalation && this.options.requireConfirmForUpgrade) {
        requiresConfirmation = true;
        confirmationReasons.push(...escalation.escalations);
      }
    }

    // Create new record
    const newRecord = createTrustRecord(
      skill,
      trust_level,
      capabilities,
      {
        reviewed_by: review.reviewed_by,
        evidence_refs: review.evidence_refs,
        notes: review.notes,
      },
      expires_at
    );

    // If confirmation is required, return without saving
    if (requiresConfirmation) {
      return {
        success: false,
        record_key: recordKey,
        requires_confirmation: true,
        confirmation_reasons: confirmationReasons,
        action: existingRecord ? 'updated' : 'created',
      };
    }

    // Save the record
    await this.storage.upsert(newRecord);

    return {
      success: true,
      record_key: recordKey,
      requires_confirmation: false,
      action: existingRecord ? 'updated' : 'created',
    };
  }

  /**
   * Force attest (skip confirmation)
   */
  async forceAttest(request: AttestRequest): Promise<AttestResult> {
    const { skill, trust_level, capabilities, expires_at, review } = request;
    const recordKey = generateRecordKey(skill);

    const existingRecord = await this.storage.findByKey(recordKey);

    const newRecord = createTrustRecord(
      skill,
      trust_level,
      capabilities,
      {
        reviewed_by: review.reviewed_by,
        evidence_refs: review.evidence_refs,
        notes: review.notes,
      },
      expires_at
    );

    await this.storage.upsert(newRecord);

    return {
      success: true,
      record_key: recordKey,
      requires_confirmation: false,
      action: existingRecord ? 'updated' : 'created',
    };
  }

  /**
   * Revoke trust records
   */
  async revoke(match: RevokeMatch, reason: string): Promise<number> {
    let revokedCount = 0;
    const records = await this.storage.getRecords();

    for (const record of records) {
      let shouldRevoke = false;

      // Match by record_key
      if (match.record_key && record.record_key === match.record_key) {
        shouldRevoke = true;
      }

      // Match by source
      if (match.source) {
        if (match.source.includes('*')) {
          // Wildcard match
          const pattern = new RegExp(
            `^${match.source.replace(/\*/g, '.*')}$`
          );
          if (pattern.test(record.skill.source)) {
            shouldRevoke = true;
          }
        } else if (record.skill.source === match.source) {
          shouldRevoke = true;
        }
      }

      // Match by version
      if (match.version_ref && record.skill.version_ref === match.version_ref) {
        // Only revoke if source also matches (or not specified)
        if (!match.source || shouldRevoke) {
          shouldRevoke = true;
        }
      }

      if (shouldRevoke && record.status !== 'revoked') {
        record.status = 'revoked';
        record.updated_at = new Date().toISOString();
        record.review.notes += `\n[REVOKED] ${reason}`;

        await this.storage.upsert(record);
        revokedCount++;
      }
    }

    return revokedCount;
  }

  /**
   * List trust records
   */
  async list(filters?: ListFilters): Promise<TrustRecord[]> {
    let records = await this.storage.getRecords();

    if (filters) {
      // Filter by trust level
      if (filters.trust_level) {
        records = records.filter((r) => r.trust_level === filters.trust_level);
      }

      // Filter by status
      if (filters.status) {
        records = records.filter((r) => r.status === filters.status);
      }

      // Filter by source pattern
      if (filters.source_pattern) {
        const pattern = new RegExp(
          filters.source_pattern.replace(/\*/g, '.*'),
          'i'
        );
        records = records.filter((r) => pattern.test(r.skill.source));
      }

      // Filter expired
      if (!filters.include_expired) {
        records = records.filter((r) => !isRecordExpired(r));
      }
    }

    return records;
  }

  /**
   * Get a single record by key
   */
  async get(recordKey: string): Promise<TrustRecord | null> {
    return this.storage.findByKey(recordKey);
  }

  /**
   * Delete a record (hard delete)
   */
  async delete(recordKey: string): Promise<boolean> {
    return this.storage.remove(recordKey);
  }

  /**
   * Export registry
   */
  async export(): Promise<string> {
    return this.storage.export();
  }

  /**
   * Import registry
   */
  async import(jsonData: string, merge: boolean = false): Promise<void> {
    return this.storage.import(jsonData, merge);
  }

  /**
   * Clear all records
   */
  async clear(): Promise<void> {
    return this.storage.clear();
  }
}

// Export singleton instance
export const registry = new SkillRegistry();

// Re-export types
export * from './storage.js';
export * from './trust.js';
