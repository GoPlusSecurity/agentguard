import * as fs from 'fs/promises';
import * as path from 'path';
import { homedir } from 'os';
import type { RegistryData, TrustRecord } from '../types/registry.js';

/**
 * Default registry data
 */
const DEFAULT_REGISTRY: RegistryData = {
  version: 1,
  updated_at: new Date().toISOString(),
  records: [],
};

/**
 * Storage options
 */
export interface StorageOptions {
  /** Path to registry file */
  filePath?: string;
}

/**
 * JSON-based storage for registry.
 *
 * Concurrency-safe for parallel multi-agent environments:
 *  - Load coalescing: concurrent load() calls share a single file read.
 *  - Write serialization: concurrent mutations queue behind the current
 *    write to prevent interleaved save() calls from losing data.
 *  - Record-key index: O(1) lookups by record_key instead of linear scan.
 */
export class RegistryStorage {
  private filePath: string;
  private data: RegistryData | null = null;

  /** Promise for the in-flight load — concurrent callers share this */
  private loadPromise: Promise<RegistryData> | null = null;

  /** Chain for serializing mutations (upsert / remove / save) */
  private writeChain: Promise<void> = Promise.resolve();

  /** Fast lookup index: record_key → array index */
  private keyIndex: Map<string, number> | null = null;

  constructor(options: StorageOptions = {}) {
    this.filePath =
      options.filePath ||
      (process.env.OPENCLAW_STATE_DIR
        ? path.join(process.env.OPENCLAW_STATE_DIR, 'agentguard', 'registry.json')
        : process.env.AGENTGUARD_HOME
          ? path.join(process.env.AGENTGUARD_HOME, 'registry.json')
          : path.join(homedir(), '.agentguard', 'registry.json'));
  }

  /**
   * Ensure data directory exists
   */
  private async ensureDirectory(): Promise<void> {
    const dir = path.dirname(this.filePath);
    await fs.mkdir(dir, { recursive: true });
  }

  /**
   * Rebuild the record_key → index mapping.
   */
  private rebuildIndex(): void {
    this.keyIndex = new Map();
    if (!this.data) return;
    for (let i = 0; i < this.data.records.length; i++) {
      this.keyIndex.set(this.data.records[i].record_key, i);
    }
  }

  /**
   * Load registry data from file.
   *
   * Concurrent callers share a single in-flight read to avoid redundant I/O.
   */
  async load(): Promise<RegistryData> {
    if (this.data) {
      return this.data;
    }

    // Coalesce concurrent loads
    if (this.loadPromise) {
      return this.loadPromise;
    }

    this.loadPromise = this.loadFromDisk();

    try {
      return await this.loadPromise;
    } finally {
      this.loadPromise = null;
    }
  }

  private async loadFromDisk(): Promise<RegistryData> {
    try {
      const content = await fs.readFile(this.filePath, 'utf-8');
      this.data = JSON.parse(content) as RegistryData;

      // Validate version
      if (this.data.version !== 1) {
        console.warn(`Unknown registry version: ${this.data.version}`);
      }

      this.rebuildIndex();
      return this.data;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        // File doesn't exist, create default
        this.data = { ...DEFAULT_REGISTRY, records: [] };
        this.rebuildIndex();
        await this.save();
        return this.data;
      }
      throw err;
    }
  }

  /**
   * Save registry data to file.
   *
   * Serialized: concurrent writes queue behind the current in-flight save.
   */
  async save(): Promise<void> {
    if (!this.data) {
      throw new Error('No data to save');
    }

    // Serialize writes to prevent interleaving
    const doSave = async (): Promise<void> => {
      if (!this.data) return;

      await this.ensureDirectory();

      this.data.updated_at = new Date().toISOString();

      await fs.writeFile(
        this.filePath,
        JSON.stringify(this.data, null, 2),
        { encoding: 'utf-8', mode: 0o600 }
      );
    };

    // Chain behind any pending write
    this.writeChain = this.writeChain.then(doSave, doSave);
    return this.writeChain;
  }

  /**
   * Get all records
   */
  async getRecords(): Promise<TrustRecord[]> {
    const data = await this.load();
    return data.records;
  }

  /**
   * Find record by key (O(1) via index)
   */
  async findByKey(recordKey: string): Promise<TrustRecord | null> {
    const data = await this.load();
    if (this.keyIndex) {
      const idx = this.keyIndex.get(recordKey);
      return idx !== undefined ? data.records[idx] : null;
    }
    return data.records.find((r) => r.record_key === recordKey) || null;
  }

  /**
   * Find records by source
   */
  async findBySource(source: string): Promise<TrustRecord[]> {
    const data = await this.load();
    return data.records.filter((r) => r.skill.source === source);
  }

  /**
   * Add or update a record
   */
  async upsert(record: TrustRecord): Promise<void> {
    const data = await this.load();

    if (this.keyIndex) {
      const existingIdx = this.keyIndex.get(record.record_key);
      if (existingIdx !== undefined) {
        data.records[existingIdx] = record;
      } else {
        const newIdx = data.records.length;
        data.records.push(record);
        this.keyIndex.set(record.record_key, newIdx);
      }
    } else {
      const existingIndex = data.records.findIndex(
        (r) => r.record_key === record.record_key
      );
      if (existingIndex >= 0) {
        data.records[existingIndex] = record;
      } else {
        data.records.push(record);
      }
    }

    await this.save();
  }

  /**
   * Remove a record by key
   */
  async remove(recordKey: string): Promise<boolean> {
    const data = await this.load();

    const initialLength = data.records.length;
    data.records = data.records.filter((r) => r.record_key !== recordKey);

    if (data.records.length < initialLength) {
      // Rebuild index since indices shifted
      this.rebuildIndex();
      await this.save();
      return true;
    }

    return false;
  }

  /**
   * Update record status
   */
  async updateStatus(
    recordKey: string,
    status: 'active' | 'revoked'
  ): Promise<boolean> {
    const record = await this.findByKey(recordKey);

    if (!record) {
      return false;
    }

    record.status = status;
    record.updated_at = new Date().toISOString();

    await this.upsert(record);
    return true;
  }

  /**
   * Export registry to JSON string
   */
  async export(): Promise<string> {
    const data = await this.load();
    return JSON.stringify(data, null, 2);
  }

  /**
   * Import registry from JSON string
   */
  async import(jsonData: string, merge: boolean = false): Promise<void> {
    const importData = JSON.parse(jsonData) as RegistryData;

    if (merge) {
      const data = await this.load();

      // Merge records, preferring imported records for conflicts
      const recordMap = new Map<string, TrustRecord>();

      for (const record of data.records) {
        recordMap.set(record.record_key, record);
      }

      for (const record of importData.records) {
        recordMap.set(record.record_key, record);
      }

      data.records = Array.from(recordMap.values());
      this.rebuildIndex();
      await this.save();
    } else {
      this.data = importData;
      this.rebuildIndex();
      await this.save();
    }
  }

  /**
   * Clear all records
   */
  async clear(): Promise<void> {
    this.data = { ...DEFAULT_REGISTRY, records: [] };
    this.rebuildIndex();
    await this.save();
  }

  /**
   * Get registry file path
   */
  getFilePath(): string {
    return this.filePath;
  }
}
