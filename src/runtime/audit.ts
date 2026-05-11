import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RuntimeAuditEvent } from './types.js';
import { redactPreview, redactReasons } from './redaction.js';

export function buildAuditEvent(event: RuntimeAuditEvent): RuntimeAuditEvent {
  return {
    ...event,
    input: redactPreview(event.input),
    reasons: redactReasons(event.reasons),
    metadata: {
      ...(event.metadata || {}),
      evaluation: event.metadata?.evaluation || 'local-oss',
    },
  };
}

export function writeAuditLog(auditPath: string, event: RuntimeAuditEvent): void {
  mkdirSync(dirname(auditPath), { recursive: true });
  appendFileSync(auditPath, `${JSON.stringify(buildAuditEvent(event))}\n`);
}

export function spoolEvent(spoolPath: string, event: RuntimeAuditEvent): void {
  mkdirSync(dirname(spoolPath), { recursive: true });
  appendFileSync(spoolPath, `${JSON.stringify(buildAuditEvent(event))}\n`);
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
    writeFileSync(spoolPath, `${remaining.map((event) => JSON.stringify(event)).join('\n')}\n`);
  }

  return { flushed, remaining: remaining.length };
}
