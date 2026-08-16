import { closeSync, existsSync, fstatSync, openSync, readSync } from 'node:fs';
import type {
  CloudPolicyDecision,
  RuntimeActionType,
  RuntimeAuditEvent,
  RuntimeRiskLevel,
} from '../runtime/types.js';

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;
const MAX_READ_BYTES = 1024 * 1024;

export interface DshRuntimeSummaryOptions {
  limit?: number;
  sessionId?: string;
}

export interface DshRuntimeReasonCount {
  code: string;
  count: number;
}

export interface DshRuntimeSummary {
  total: number;
  inspected: number;
  malformedLines: number;
  truncated: boolean;
  sessionId?: string;
  decisions: Partial<Record<CloudPolicyDecision, number>>;
  actionTypes: Partial<Record<RuntimeActionType, number>>;
  riskLevels: Partial<Record<RuntimeRiskLevel, number>>;
  phases: Partial<Record<'pre' | 'post' | 'unknown', number>>;
  topReasons: DshRuntimeReasonCount[];
  nestedCalls: number;
  latestActionId?: string;
  latestPolicyVersion?: string;
}

/**
 * Read a bounded tail of the local audit log and aggregate DSH observation events.
 * Raw inputs and reason evidence are intentionally never returned to the caller.
 */
export function summarizeDshRuntimeAudit(
  auditPath: string,
  options: DshRuntimeSummaryOptions = {}
): DshRuntimeSummary {
  const limit = normalizeLimit(options.limit);
  const sessionId = normalizeSessionId(options.sessionId);
  const tail = readBoundedTail(auditPath);
  const parsed: RuntimeAuditEvent[] = [];
  let malformedLines = 0;

  for (const line of tail.lines) {
    try {
      const event = JSON.parse(line) as RuntimeAuditEvent;
      if (event.agentHost !== 'dsh') continue;
      if (event.metadata?.runtimeMode !== 'observe') continue;
      if (sessionId && event.sessionId !== sessionId) continue;
      parsed.push(event);
    } catch {
      malformedLines++;
    }
  }

  const events = parsed.slice(-limit);
  const decisions: DshRuntimeSummary['decisions'] = {};
  const actionTypes: DshRuntimeSummary['actionTypes'] = {};
  const riskLevels: DshRuntimeSummary['riskLevels'] = {};
  const phases: DshRuntimeSummary['phases'] = {};
  const reasons = new Map<string, number>();
  let nestedCalls = 0;

  for (const event of events) {
    increment(decisions, event.decision);
    increment(actionTypes, event.actionType);
    increment(riskLevels, event.riskLevel);
    const phase = event.metadata?.runtimePhase === 'pre' || event.metadata?.runtimePhase === 'post'
      ? event.metadata.runtimePhase
      : 'unknown';
    increment(phases, phase);
    if (event.metadata?.nested === true) nestedCalls++;
    for (const reason of event.reasons ?? []) {
      if (typeof reason.code === 'string' && reason.code) {
        reasons.set(reason.code, (reasons.get(reason.code) ?? 0) + 1);
      }
    }
  }

  const latest = events.at(-1);
  return {
    total: events.length,
    inspected: parsed.length,
    malformedLines,
    truncated: tail.truncated || parsed.length > limit,
    ...(sessionId ? { sessionId } : {}),
    decisions,
    actionTypes,
    riskLevels,
    phases,
    topReasons: [...reasons.entries()]
      .sort(([leftCode, leftCount], [rightCode, rightCount]) => rightCount - leftCount || leftCode.localeCompare(rightCode))
      .slice(0, 10)
      .map(([code, count]) => ({ code, count })),
    nestedCalls,
    ...(latest?.actionId ? { latestActionId: latest.actionId } : {}),
    ...(latest?.policyVersion ? { latestPolicyVersion: latest.policyVersion } : {}),
  };
}

function readBoundedTail(path: string): { lines: string[]; truncated: boolean } {
  if (!existsSync(path)) return { lines: [], truncated: false };
  const fd = openSync(path, 'r');
  try {
    const size = fstatSync(fd).size;
    const length = Math.min(size, MAX_READ_BYTES);
    const start = size - length;
    const buffer = Buffer.alloc(length);
    readSync(fd, buffer, 0, length, start);
    const text = buffer.toString('utf8');
    const lines = text.split('\n');
    if (start > 0) lines.shift();
    return {
      lines: lines.map(line => line.trim()).filter(Boolean),
      truncated: start > 0,
    };
  } finally {
    closeSync(fd);
  }
}

function normalizeLimit(value: number | undefined): number {
  if (value === undefined) return DEFAULT_LIMIT;
  if (!Number.isInteger(value) || value < 1 || value > MAX_LIMIT) {
    throw new Error(`limit must be an integer between 1 and ${MAX_LIMIT}`);
  }
  return value;
}

function normalizeSessionId(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (!normalized) throw new Error('sessionId must be a non-empty string');
  if (normalized.length > 160) throw new Error('sessionId must be at most 160 characters');
  return normalized;
}

function increment<T extends string>(target: Partial<Record<T, number>>, key: T): void {
  target[key] = (target[key] ?? 0) + 1;
}
