import * as fs from 'fs/promises';
import * as path from 'path';
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
 * JSON-based storage for registry
 */
export class RegistryStorage {
  private filePath: string;
  private data: RegistryData | null = null;

  constructor(options: StorageOptions = {}) {
    this.filePath =
      options.filePath ||
      path.join(process.cwd(), 'data', 'registry.json');
  }

  /**
   * Ensure data directory exists
   */
  private async ensureDirectory(): Promise<void> {
    const dir = path.dirname(this.filePath);
    await fs.mkdir(dir, { recursive: true });
  }

  /**
   * Load registry data from file
   */
  async load(): Promise<RegistryData> {
    if (this.data) {
      return this.data;
    }

    try {
      const content = await fs.readFile(this.filePath, 'utf-8');
      this.data = JSON.parse(content) as RegistryData;

      // Validate version
      if (this.data.version !== 1) {
        console.warn(`Unknown registry version: ${this.data.version}`);
      }

      return this.data;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        // File doesn't exist, create default
        this.data = { ...DEFAULT_REGISTRY };
        await this.save();
        return this.data;
      }
      throw err;
    }
  }

  /**
   * Save registry data to file
   */
  async save(): Promise<void> {
    if (!this.data) {
      throw new Error('No data to save');
    }

    await this.ensureDirectory();

    this.data.updated_at = new Date().toISOString();

    await fs.writeFile(
      this.filePath,
      JSON.stringify(this.data, null, 2),
      'utf-8'
    );
  }

  /**
   * Get all records
   */
  async getRecords(): Promise<TrustRecord[]> {
    const data = await this.load();
    return data.records;
  }

  /**
   * Find record by key
   */
  async findByKey(recordKey: string): Promise<TrustRecord | null> {
    const data = await this.load();
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

    const existingIndex = data.records.findIndex(
      (r) => r.record_key === record.record_key
    );

    if (existingIndex >= 0) {
      data.records[existingIndex] = record;
    } else {
      data.records.push(record);
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
      await this.save();
    } else {
      this.data = importData;
      await this.save();
    }
  }

  /**
   * Clear all records
   */
  async clear(): Promise<void> {
    this.data = { ...DEFAULT_REGISTRY };
    await this.save();
  }

  /**
   * Get registry file path
   */
  getFilePath(): string {
    return this.filePath;
  }
}
