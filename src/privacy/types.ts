import type { CoverageLevel, PiiCategory } from '../runtime/types.js';

/**
 * How precisely a privacy finding is located in the source text.
 *
 * - `value`    exact character span; supports character-level masking
 * - `chunk`    sentence/segment only; semantic PII has no meaningful span
 * - `document` presence only; cannot mask without destroying the document
 * - `none`     nothing located
 */
export type PiiLocalization = 'value' | 'chunk' | 'document' | 'none';

/** A loosely extracted span that MAY be personal data. Precision is not assumed. */
export interface PiiCandidate {
  id: string;
  /** Extractor that produced the span, e.g. `digits11`, `national_id`, `address`. */
  kind: string;
  /** Likely category, refined by adjudication. */
  category: PiiCategory;
  value: string;
  start: number;
  end: number;
  /** Index of the chunk the span falls in, for evidence and masking. */
  chunkIndex: number;
  /** Surrounding sentence; adjudication needs it to judge intent. */
  context: string;
}

/** A sentence-sized segment, used for PII that has no extractable span. */
export interface PiiChunk {
  index: number;
  text: string;
  start: number;
  end: number;
}

export interface AdjudicationRequest {
  candidates: PiiCandidate[];
  chunks: PiiChunk[];
  /** Context every judgment must consult, sent once. */
  sharedContext?: string;
}

export interface AdjudicationVerdict {
  id: string;
  /** Thresholded decision. */
  isPii: boolean;
  /** Raw probability, retained so thresholds can change without re-inference. */
  probability: number;
}

export interface AdjudicationUsage {
  inputTokens: number;
  outputTokens: number;
  requests: number;
}

export interface AdjudicationResult {
  candidateVerdicts: AdjudicationVerdict[];
  chunkVerdicts: AdjudicationVerdict[];
  /**
   * How much of the request the provider actually judged. Never `full` when
   * any batch failed: a privacy check that silently skipped input must not
   * report clean coverage.
   */
  coverage: CoverageLevel;
  provider: string;
  model?: string;
  usage?: AdjudicationUsage;
  /** Non-fatal provider errors, already redacted. */
  errors?: string[];
}

/**
 * Which tracks are sent for judgment.
 *
 * - `candidates` spans only; correct for source code, which has no prose
 * - `filtered`   spans plus sentences that pass the local soft-signal net
 * - `full`       spans plus every sentence; complete, and ~36x the tokens
 *
 * Chosen by the calling surface rather than the user: `scan` over a repository
 * and `checkup` over chat logs want different tracks, and the user already made
 * the one decision that matters when they enabled enhancement at all.
 */
export type PrivacyScope = 'candidates' | 'filtered' | 'full';

/**
 * Token ceiling shared across every adjudication in one command invocation.
 *
 * Without a shared budget, a per-call limit multiplies by the file count: a
 * directory scan would send unbounded data. Exhaustion degrades coverage rather
 * than throwing, so a partial analysis is reported as partial.
 */
export class TokenBudget {
  private spent = 0;
  constructor(readonly limit: number) {}
  get remaining(): number {
    return Math.max(0, this.limit - this.spent);
  }
  get exhausted(): boolean {
    return this.spent >= this.limit;
  }
  /** Reserve `amount`; false when the budget cannot cover it. */
  tryConsume(amount: number): boolean {
    if (this.spent + amount > this.limit) return false;
    this.spent += amount;
    return true;
  }

  /**
   * Correct a reservation against the provider's reported usage.
   *
   * Reservations are made from a character-based estimate, which can undercount.
   * Without reconciliation those errors accumulate and the ceiling drifts above
   * what was configured, so the actual figure replaces the estimate — even when
   * that pushes the budget over, which then stops subsequent requests.
   */
  reconcile(estimated: number, actual: number): void {
    this.spent += Math.max(0, actual - estimated);
  }
}

export interface AdjudicateOptions {
  /** Probability at or above which a verdict counts as PII. */
  threshold: number;
  /** Per-request input-token ceiling used to split batches. */
  tokenBudget: number;
  /** Hard cap on provider requests for one adjudication. */
  maxRequests: number;
  /** Ceiling shared across the whole invocation; omitted means unbounded. */
  budget?: TokenBudget;
  signal?: AbortSignal;
}

/**
 * Semantic adjudication layer. Deliberately provider-agnostic: the contract is
 * "given spans and chunks, say which are real personal data", which any judge
 * can satisfy. Jev is the first implementation, not the interface.
 */
export interface PrivacyAdjudicator {
  readonly name: string;
  /** False when unconfigured; callers must degrade instead of failing. */
  readonly available: boolean;
  adjudicate(request: AdjudicationRequest, options: AdjudicateOptions): Promise<AdjudicationResult>;
}

export const DEFAULT_ADJUDICATE_OPTIONS: AdjudicateOptions = {
  threshold: 0.5,
  tokenBudget: 50_000,
  maxRequests: 20,
};
