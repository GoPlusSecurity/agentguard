import { spawn } from 'child_process';
import * as crypto from 'crypto';
import type {
  ScanPayload,
  ScanResult,
  ScanEvidence,
  RiskLevel,
  RiskTag,
  ScanRule,
} from '../types/scanner.js';
import type { SkillIdentity } from '../types/skill.js';
import { walkDirectory, isDirectory, pathExists } from './file-walker.js';
import { ALL_RULES, getRulesForExtension } from './rules/index.js';

/**
 * Scanner options
 */
export interface ScannerOptions {
  /** Use cisco-ai-defense/skill-scanner if available */
  useExternalScanner?: boolean;
  /** Enable deep analysis */
  deep?: boolean;
  /** Custom rules to add */
  additionalRules?: ScanRule[];
}

/**
 * Skill Scanner - Module A
 * Scans skill code for security risks
 */
export class SkillScanner {
  private options: ScannerOptions;
  private externalScannerAvailable: boolean | null = null;

  constructor(options: ScannerOptions = {}) {
    this.options = {
      useExternalScanner: true,
      deep: false,
      ...options,
    };
  }

  /**
   * Check if cisco-ai-defense/skill-scanner is installed
   */
  private async checkExternalScanner(): Promise<boolean> {
    if (this.externalScannerAvailable !== null) {
      return this.externalScannerAvailable;
    }

    return new Promise((resolve) => {
      const proc = spawn('skill-scanner', ['--version'], {
        shell: true,
        stdio: 'pipe',
      });

      proc.on('error', () => {
        this.externalScannerAvailable = false;
        resolve(false);
      });

      proc.on('close', (code) => {
        this.externalScannerAvailable = code === 0;
        resolve(code === 0);
      });
    });
  }

  /**
   * Run external skill-scanner CLI
   */
  private async runExternalScanner(dirPath: string): Promise<ScanResult | null> {
    return new Promise((resolve) => {
      const args = ['scan', dirPath, '--format', 'json'];

      if (this.options.deep) {
        args.push('--use-behavioral');
      }

      const proc = spawn('skill-scanner', args, {
        shell: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr?.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('error', () => {
        resolve(null);
      });

      proc.on('close', (code) => {
        if (code !== 0 && code !== 1) {
          // code 1 means findings detected
          console.warn('External scanner failed:', stderr);
          resolve(null);
          return;
        }

        try {
          const result = this.parseExternalResult(stdout);
          resolve(result);
        } catch (err) {
          console.warn('Failed to parse external scanner result:', err);
          resolve(null);
        }
      });
    });
  }

  /**
   * Parse external skill-scanner JSON output
   */
  private parseExternalResult(jsonOutput: string): ScanResult {
    // Try to extract JSON from output (may contain non-JSON text)
    const jsonMatch = jsonOutput.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      throw new Error('No JSON found in output');
    }

    const data = JSON.parse(jsonMatch[0]);

    // Map external findings to our format
    const evidence: ScanEvidence[] = [];
    const riskTags: Set<RiskTag> = new Set();

    if (data.findings && Array.isArray(data.findings)) {
      for (const finding of data.findings) {
        // Map finding type to our risk tags
        const tag = this.mapExternalFindingToTag(finding.type || finding.category);
        if (tag) {
          riskTags.add(tag);
          evidence.push({
            tag,
            file: finding.file || finding.location?.file || 'unknown',
            line: finding.line || finding.location?.line || 0,
            match: finding.match || finding.description || '',
            context: finding.context,
          });
        }
      }
    }

    // Determine risk level
    const riskLevel = this.calculateRiskLevel(Array.from(riskTags));

    return {
      risk_level: riskLevel,
      risk_tags: Array.from(riskTags),
      evidence,
      summary: data.summary || `Found ${evidence.length} security findings`,
      metadata: {
        files_scanned: data.files_scanned || 0,
        scan_duration_ms: data.duration_ms || 0,
        scan_time: new Date().toISOString(),
      },
    };
  }

  /**
   * Map external finding type to our risk tags
   */
  private mapExternalFindingToTag(externalType: string): RiskTag | null {
    const mapping: Record<string, RiskTag> = {
      'command-injection': 'SHELL_EXEC',
      'code-execution': 'SHELL_EXEC',
      'remote-code-loading': 'REMOTE_LOADER',
      'dynamic-import': 'REMOTE_LOADER',
      'env-access': 'READ_ENV_SECRETS',
      'secret-access': 'READ_ENV_SECRETS',
      'ssh-key-access': 'READ_SSH_KEYS',
      'credential-access': 'READ_KEYCHAIN',
      'data-exfiltration': 'NET_EXFIL_UNRESTRICTED',
      'webhook-exfil': 'WEBHOOK_EXFIL',
      'obfuscation': 'OBFUSCATION',
      'prompt-injection': 'PROMPT_INJECTION',
      'private-key': 'PRIVATE_KEY_PATTERN',
      'mnemonic': 'MNEMONIC_PATTERN',
    };

    return mapping[externalType?.toLowerCase()] || null;
  }

  /**
   * Extract fenced code blocks from Markdown content.
   * Returns the code block contents joined, preserving line positions for reporting.
   */
  private extractMarkdownCodeBlocks(content: string): string {
    const lines = content.split('\n');
    const result: string[] = [];
    let inBlock = false;

    for (const line of lines) {
      if (/^```/.test(line)) {
        inBlock = !inBlock;
        result.push(''); // keep line count aligned
      } else if (inBlock) {
        result.push(line);
      } else {
        result.push(''); // outside code block: blank line to preserve numbering
      }
    }
    return result.join('\n');
  }

  /**
   * Extract and decode base64 strings from content.
   * Returns decoded strings for re-scanning.
   */
  private extractAndDecodeBase64(content: string): string[] {
    const decoded: string[] = [];
    // Match base64 strings (min 20 chars, typical encoding length)
    const b64Regex = /(?:['"`]|base64[,\s]+)([A-Za-z0-9+/]{20,}={0,2})(?:['"`]|\s|$)/g;
    let m: RegExpExecArray | null;
    while ((m = b64Regex.exec(content)) !== null) {
      try {
        const text = Buffer.from(m[1], 'base64').toString('utf-8');
        // Only keep if the decoded result looks like text (not binary)
        if (/^[\x20-\x7e\t\r\n]+$/.test(text) && text.length > 5) {
          decoded.push(text);
        }
      } catch {
        // invalid base64 — skip
      }
    }
    return decoded;
  }

  /**
   * Scan content against rules and collect evidence
   */
  private scanContent(
    content: string,
    rules: ScanRule[],
    filePath: string,
    riskTags: Set<RiskTag>,
    evidence: ScanEvidence[],
    context?: string,
  ): void {
    for (const rule of rules) {
      for (const pattern of rule.patterns) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const match = line.match(pattern);
          if (match) {
            if (rule.validator && !rule.validator(content, match)) {
              continue;
            }
            riskTags.add(rule.id);
            const ev: ScanEvidence = {
              tag: rule.id,
              file: filePath,
              line: i + 1,
              match: match[0].slice(0, 100),
            };
            if (context) {
              ev.context = context;
            }
            evidence.push(ev);
          }
        }
      }
    }
  }

  /**
   * Run built-in scanner
   */
  private async runBuiltinScanner(dirPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const files = await walkDirectory(dirPath);
    const evidence: ScanEvidence[] = [];
    const riskTags: Set<RiskTag> = new Set();

    for (const file of files) {
      const rules = getRulesForExtension(file.extension);

      // For Markdown files: only scan inside fenced code blocks
      const contentToScan = file.extension === '.md'
        ? this.extractMarkdownCodeBlocks(file.content)
        : file.content;

      this.scanContent(contentToScan, rules, file.relativePath, riskTags, evidence);

      // Base64 decode pass: extract encoded payloads and re-scan
      const decodedPayloads = this.extractAndDecodeBase64(file.content);
      if (decodedPayloads.length > 0) {
        const allRules = [...ALL_RULES, ...(this.options.additionalRules || [])];
        for (const decoded of decodedPayloads) {
          this.scanContent(decoded, allRules, file.relativePath, riskTags, evidence, 'decoded_from:base64');
        }
      }
    }

    const riskLevel = this.calculateRiskLevel(Array.from(riskTags));

    return {
      risk_level: riskLevel,
      risk_tags: Array.from(riskTags),
      evidence,
      summary: this.generateSummary(riskTags, evidence),
      metadata: {
        files_scanned: files.length,
        scan_duration_ms: Date.now() - startTime,
        scan_time: new Date().toISOString(),
      },
    };
  }

  /**
   * Calculate risk level from tags
   */
  private calculateRiskLevel(tags: RiskTag[]): RiskLevel {
    const allRules = [...ALL_RULES, ...(this.options.additionalRules || [])];

    for (const tag of tags) {
      const rule = allRules.find((r) => r.id === tag);
      if (rule?.severity === 'critical') return 'critical';
    }

    for (const tag of tags) {
      const rule = allRules.find((r) => r.id === tag);
      if (rule?.severity === 'high') return 'high';
    }

    for (const tag of tags) {
      const rule = allRules.find((r) => r.id === tag);
      if (rule?.severity === 'medium') return 'medium';
    }

    return 'low';
  }

  /**
   * Generate human-readable summary
   */
  private generateSummary(tags: Set<RiskTag>, evidence: ScanEvidence[]): string {
    if (tags.size === 0) {
      return 'No security issues detected';
    }

    const parts: string[] = [];

    if (tags.has('SHELL_EXEC') || tags.has('REMOTE_LOADER')) {
      parts.push('code execution capabilities');
    }
    if (tags.has('PRIVATE_KEY_PATTERN') || tags.has('MNEMONIC_PATTERN')) {
      parts.push('hardcoded secrets');
    }
    if (tags.has('PROMPT_INJECTION')) {
      parts.push('prompt injection attempts');
    }
    if (tags.has('WALLET_DRAINING') || tags.has('UNLIMITED_APPROVAL')) {
      parts.push('dangerous Web3 patterns');
    }
    if (tags.has('WEBHOOK_EXFIL') || tags.has('NET_EXFIL_UNRESTRICTED')) {
      parts.push('data exfiltration risks');
    }

    return `Found ${evidence.length} findings: ${parts.join(', ') || 'various security concerns'}`;
  }

  /**
   * Calculate artifact hash for a directory
   */
  async calculateArtifactHash(dirPath: string): Promise<string> {
    const files = await walkDirectory(dirPath);
    const hash = crypto.createHash('sha256');

    // Sort files for consistent hashing
    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));

    for (const file of files) {
      hash.update(file.relativePath);
      hash.update(file.content);
    }

    return `sha256:${hash.digest('hex')}`;
  }

  /**
   * Main scan method
   */
  async scan(payload: ScanPayload): Promise<ScanResult> {
    const { skill, payload: scanPayload, options } = payload;

    // Validate payload
    if (scanPayload.type !== 'dir') {
      // For now, only support directory scanning
      // TODO: Support zip and repo_url
      throw new Error(`Unsupported payload type: ${scanPayload.type}. Only 'dir' is supported.`);
    }

    const dirPath = scanPayload.ref.replace('file://', '');

    // Check if directory exists
    if (!(await pathExists(dirPath))) {
      throw new Error(`Directory not found: ${dirPath}`);
    }

    if (!(await isDirectory(dirPath))) {
      throw new Error(`Path is not a directory: ${dirPath}`);
    }

    // Try external scanner first if enabled
    if (this.options.useExternalScanner) {
      const externalAvailable = await this.checkExternalScanner();

      if (externalAvailable) {
        const externalResult = await this.runExternalScanner(dirPath);
        if (externalResult) {
          return externalResult;
        }
      }
    }

    // Fall back to built-in scanner
    return this.runBuiltinScanner(dirPath);
  }

  /**
   * Quick scan - scan and return basic info
   */
  async quickScan(dirPath: string): Promise<{
    risk_level: RiskLevel;
    risk_tags: RiskTag[];
    summary: string;
  }> {
    const hash = await this.calculateArtifactHash(dirPath);
    const skill: SkillIdentity = {
      id: 'unknown',
      source: dirPath,
      version_ref: 'unknown',
      artifact_hash: hash,
    };

    const result = await this.scan({
      skill,
      payload: { type: 'dir', ref: dirPath },
    });

    return {
      risk_level: result.risk_level,
      risk_tags: result.risk_tags,
      summary: result.summary,
    };
  }
}

// Export singleton instance
export const scanner = new SkillScanner();
