import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RuntimeAuditEvent } from './types.js';
import { redactLlmMetadata, redactMetadata, redactPreview, redactReasons } from './redaction.js';

export function buildAuditEvent(event: RuntimeAuditEvent): RuntimeAuditEvent {
  return {
    actionId: redactPreview(event.actionId, 160),
    sessionId: redactPreview(event.sessionId, 160),
    agentHost: event.agentHost,
    actionType: event.actionType,
    toolName: redactPreview(event.toolName, 160),
    input: isLlmTrafficEvent(event) ? '[LOCAL_ONLY_LLM_CONTENT]' : redactPreview(event.input),
    decision: event.decision,
    policyDecision: event.policyDecision,
    riskScore: clampRiskScore(event.riskScore),
    riskLevel: event.riskLevel,
    reasons: redactReasons(event.reasons),
    policyVersion: redactPreview(event.policyVersion, 160),
    cwd: event.cwd ? redactPreview(event.cwd, 500) : event.cwd,
    sourceSkill: event.sourceSkill ? redactPreview(event.sourceSkill, 240) : event.sourceSkill,
    lifecycleStage: event.lifecycleStage,
    canBlockCurrentAction: event.canBlockCurrentAction,
    coverageLevel: event.coverageLevel,
    enforcementStatus: event.enforcementStatus,
    missingFacts: event.missingFacts ? [...event.missingFacts] : undefined,
    llm: event.llm ? redactLlmMetadata(event.llm) : undefined,
    metadata: {
      ...redactMetadata(event.metadata),
      evaluation: redactPreview(event.metadata?.evaluation || 'local-oss', 120),
    },
  };
}

function isLlmTrafficEvent(event: RuntimeAuditEvent): boolean {
  return event.actionType === 'llm_request' || event.actionType === 'llm_response';
}

export function writeAuditLog(auditPath: string, event: RuntimeAuditEvent): void {
  ensurePrivateDir(dirname(auditPath));
  appendFileSync(auditPath, `${JSON.stringify(buildAuditEvent(event))}\n`, { mode: 0o600 });
  chmodBestEffort(auditPath, 0o600);
}

export function spoolEvent(spoolPath: string, event: RuntimeAuditEvent): void {
  ensurePrivateDir(dirname(spoolPath));
  appendFileSync(spoolPath, `${JSON.stringify(buildAuditEvent(event))}\n`, { mode: 0o600 });
  chmodBestEffort(spoolPath, 0o600);
}

export function readSpooledEvents(spoolPath: string): RuntimeAuditEvent[] {
  if (!existsSync(spoolPath)) return [];
  return readFileSync(spoolPath, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as RuntimeAuditEvent);
}

export async function flushEventSpool(
  spoolPath: string,
  sendBatch: (events: RuntimeAuditEvent[]) => Promise<void>,
  batchSize = 100
): Promise<{ flushed: number; remaining: number }> {
  const events = readSpooledEvents(spoolPath);
  if (events.length === 0) return { flushed: 0, remaining: 0 };

  let flushed = 0;
  const remaining: RuntimeAuditEvent[] = [];
  for (let index = 0; index < events.length; index += batchSize) {
    const batch = events.slice(index, index + batchSize);
    try {
      await sendBatch(batch);
      flushed += batch.length;
    } catch {
      remaining.push(...batch, ...events.slice(index + batch.length));
      break;
    }
  }

  if (remaining.length === 0) {
    rmSync(spoolPath, { force: true });
  } else {
    writeFileSync(spoolPath, `${remaining.map((event) => JSON.stringify(buildAuditEvent(event))).join('\n')}\n`, { mode: 0o600 });
    chmodBestEffort(spoolPath, 0o600);
  }

  return { flushed, remaining: remaining.length };
}

function clampRiskScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function ensurePrivateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodBestEffort(path, 0o700);
}

function chmodBestEffort(path: string, mode: number): void {
  try {
    chmodSync(path, mode);
  } catch {
    // Best-effort hardening for platforms/filesystems that support chmod.
  }
}
