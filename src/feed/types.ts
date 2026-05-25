/**
 * Threat-feed advisory types.
 *
 * AgentGuard Cloud publishes `Advisory` objects describing newly discovered
 * supply-chain threats (malicious skills, rugged MCP servers, prompt-injection
 * patterns in popular plugins). Subscribing local guards pull the feed,
 * run a targeted self-check, and report back which local artifacts matched.
 *
 * Schema intentionally mirrors the OSV.dev advisory shape (signed JSON over
 * HTTPS, `affected[]` array of identifier matchers) so the feed can later be
 * federated with OSV and OSS Insight.
 */

/** Supply-chain ecosystem an advisory targets. */
export type AdvisoryEcosystem =
  | 'skill'
  | 'plugin'
  | 'mcp_server'
  | 'supply_chain'
  | 'url'
  | 'prompt_injection';

export type AdvisorySeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * One matcher used by Cloud-published advisories and local OSS guard
 * self-checks. A local artifact matches the advisory if ANY matcher matches.
 * A matcher matches if ALL of its populated fields match the same local
 * artifact (so name + version narrows the hit).
 */
export interface AdvisoryAffected {
  /**
   * Glob-ish name pattern matched against the skill's `name` field or the
   * containing directory name. Supports `*` as a single-segment wildcard.
   * Example: `slack-webhook-*`.
   */
  namePattern?: string;
  /**
   * Specific SHA-256 hash (hex, lowercase) of the artifact's content
   * (a directory hash for skill dirs, file hash for single-file artifacts).
   * Exact match.
   */
  sha256?: string;
  /**
   * Optional semver range used for plugin/package matching.
   */
  versionRange?: string;
  /**
   * Optional regex applied to the textual body of `SKILL.md` (or the file
   * contents for non-skill artifacts). Use this when the threat manifests as
   * a code/text pattern rather than a known hash.
   */
  bodyRegex?: string;
  /** Optional URL glob/regex-style pattern for URL-focused advisories. */
  urlPattern?: string;
  /** Optional exact domain match for URL/domain-focused advisories. */
  domainExact?: string;
}

export interface Advisory {
  /** Stable identifier, e.g. `AGS-2026-0042`. */
  id: string;
  ecosystem: AdvisoryEcosystem;
  severity: AdvisorySeverity;
  /** Short headline. <= 120 chars. */
  summary: string;
  /** Long-form markdown body. May include remediation steps. */
  detailsMd: string;
  /** Matchers — local artifact matches the advisory if ANY entry matches. */
  affected: AdvisoryAffected[];
  /** ISO-8601 timestamp when published. */
  publishedAt: string;
  /** Optional withdrawal timestamp — if set, the advisory was retracted. */
  withdrawnAt?: string | null;
  /**
   * Optional HMAC-SHA256 hex signature of the canonical JSON payload, signed
   * with the cloud's per-publisher key. Subscribers can verify integrity if
   * they have the verifier key. Empty when the cloud doesn't sign yet.
   */
  signature?: string;
  /** External references — Snyk, NVD, GHSA, blog posts. */
  references?: string[];
  selfCheck?: {
    inspectPaths?: string[];
    matchers: AdvisoryAffected[];
    remediationAction?: 'quarantine' | 'uninstall' | 'block_url' | 'revoke_token' | 'notify_only';
    remediationMd?: string;
  };
}

/** One local feed-subscription pull record. Newest records are stored first. */
export interface FeedStateEntry {
  /** ISO-8601 timestamp for when this subscribe run pulled the feed. */
  pulledAt: string;
  /** Stable IDs of advisories newly processed in this pull. */
  newSeenIds: string[];
  /** Advisory IDs whose self-check found local matches in this pull. */
  foundIds: string[];
}

/**
 * Local feed-subscription state. Persisted between `subscribe` runs so the
 * client doesn't re-process advisories it has already seen.
 */
export type FeedState = FeedStateEntry[];

/**
 * Result of running a single advisory's checks against the local environment.
 */
export interface SelfCheckResult {
  advisoryId: string;
  /** Always populated, even when empty (means "we checked, nothing matched"). */
  matchedArtifacts: SelfCheckMatch[];
  /** Wall-clock duration in milliseconds. */
  elapsedMs: number;
  /** Errors per-matcher that prevented a definitive answer. Non-fatal. */
  warnings: string[];
}

export interface SelfCheckMatch {
  /** Local path to the matched artifact (skill dir / file). Redaction is the
   *  caller's responsibility before reporting upstream. */
  path: string;
  /** Which matcher hit. Useful for explaining "why" to the user. */
  matchedBy: 'namePattern' | 'sha256' | 'versionRange' | 'bodyRegex' | 'urlPattern' | 'domainExact';
  /** When matched by hash, this is the local hash that equalled the advisory's. */
  hash?: string;
}
