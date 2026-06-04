import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { RuntimeAction, RuntimeDecision } from './types.js';
import { redactPreview, redactReasons } from './redaction.js';

export const DEFAULT_PENDING_APPROVAL_TTL_MS = 5 * 60 * 1000;
const LAST_APPROVAL_WINDOW_MS = 2 * 60 * 1000;
const LOCK_STALE_MS = 30 * 1000;
const LOCK_TIMEOUT_MS = 5 * 1000;

export type ApprovalRecordStatus = 'pending' | 'approved';

export interface ApprovalRecord {
  actionId: string;
  status: ApprovalRecordStatus;
  once: boolean;
  actionFingerprint: string;
  sessionId: string;
  agentHost: RuntimeAction['agentHost'];
  actionType: RuntimeAction['actionType'];
  toolName: string;
  inputPreview: string;
  cwd?: string;
  reasonTitles: string[];
  riskScore: number;
  riskLevel: RuntimeDecision['riskLevel'];
  policyVersion: string;
  createdAt: string;
  expiresAt: string;
  approvedAt?: string;
}

export interface ApprovalStore {
  version: 1;
  records: ApprovalRecord[];
}

export function actionFingerprint(action: RuntimeAction): string {
  const canonical = JSON.stringify({
    sessionId: fingerprintSessionId(action),
    agentHost: action.agentHost,
    actionType: action.actionType,
    toolName: action.toolName,
    input: normalizeActionInput(action.input),
    cwd: action.cwd || '',
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function fingerprintSessionId(action: RuntimeAction): string {
  if (action.agentHost === 'openclaw' && action.sessionId.startsWith('sess_local_')) {
    return '';
  }
  return action.sessionId;
}

export function writePendingApproval(
  storePath: string,
  action: RuntimeAction,
  decision: RuntimeDecision,
  now = new Date()
): ApprovalRecord {
  const store = readApprovalStore(storePath, now);
  const fingerprint = actionFingerprint(action);
  const existing = store.records.find((record) =>
    record.status === 'pending' &&
    record.actionFingerprint === fingerprint
  );
  if (existing) return existing;

  const expiresAt = new Date(now.getTime() + DEFAULT_PENDING_APPROVAL_TTL_MS).toISOString();
  const record: ApprovalRecord = {
    actionId: decision.actionId,
    status: 'pending',
    once: true,
    actionFingerprint: fingerprint,
    sessionId: redactPreview(action.sessionId, 160),
    agentHost: action.agentHost,
    actionType: action.actionType,
    toolName: redactPreview(action.toolName, 160),
    inputPreview: redactPreview(action.input),
    cwd: action.cwd ? redactPreview(action.cwd, 500) : undefined,
    reasonTitles: redactReasons(decision.reasons).map((reason) => reason.title).filter(Boolean).slice(0, 5),
    riskScore: decision.riskScore,
    riskLevel: decision.riskLevel,
    policyVersion: redactPreview(decision.policyVersion, 160),
    createdAt: now.toISOString(),
    expiresAt,
  };

  const records = store.records.filter((item) => item.actionId !== record.actionId);
  records.push(record);
  writeApprovalStore(storePath, { version: 1, records }, now);
  return record;
}

export function listPendingApprovals(storePath: string, now = new Date()): ApprovalRecord[] {
  return readApprovalStore(storePath, now).records
    .filter((record) => record.status === 'pending')
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
}

export function approvePendingApproval(
  storePath: string,
  options: { actionId?: string; last?: boolean; sessionId?: string; once?: boolean },
  now = new Date()
): ApprovalRecord {
  const store = readApprovalStore(storePath, now);
  const pending = store.records.filter((record) => record.status === 'pending');
  const selected = selectPendingApproval(pending, options, now);
  const approved: ApprovalRecord = {
    ...selected,
    status: 'approved',
    once: options.once !== false,
    approvedAt: now.toISOString(),
  };
  writeApprovalStore(storePath, {
    version: 1,
    records: store.records.map((record) => record.actionId === selected.actionId ? approved : record),
  }, now);
  return approved;
}

export function consumeApprovedApproval(
  storePath: string,
  action: RuntimeAction,
  now = new Date()
): ApprovalRecord | null {
  return withApprovalStoreLock(storePath, () => {
    const store = readApprovalStore(storePath, now);
    const fingerprint = actionFingerprint(action);
    const approved = store.records.find((record) =>
      record.status === 'approved' &&
      record.actionFingerprint === fingerprint &&
      Date.parse(record.expiresAt) > now.getTime()
    );
    if (!approved) return null;

    const records = approved.once
      ? store.records.filter((record) => record.actionId !== approved.actionId)
      : store.records;
    writeApprovalStore(storePath, { version: 1, records }, now);
    return approved;
  });
}

export function cleanupExpiredApprovals(storePath: string, now = new Date()): number {
  if (!existsSync(storePath)) return 0;
  const raw = readStoreFile(storePath);
  const records = raw.records.filter((record) => Date.parse(record.expiresAt) > now.getTime());
  const removed = raw.records.length - records.length;
  if (removed > 0) writeApprovalStore(storePath, { version: 1, records }, now);
  return removed;
}

function selectPendingApproval(
  records: ApprovalRecord[],
  options: { actionId?: string; last?: boolean; sessionId?: string },
  now: Date
): ApprovalRecord {
  if (options.actionId) {
    const found = records.find((record) => record.actionId === options.actionId);
    if (!found) throw new Error(`No pending approval found for action ${options.actionId}.`);
    return found;
  }

  if (!options.last) {
    throw new Error('Specify --action-id <id> or --last.');
  }

  const sessionMatches = options.sessionId
    ? records.filter((record) => record.sessionId === options.sessionId)
    : [];
  if (sessionMatches.length === 1) return sessionMatches[0];
  if (sessionMatches.length > 1) {
    throw new Error('Multiple pending approvals match this session. Run `agentguard approvals list` and approve a specific action id.');
  }

  const recent = records.filter((record) => now.getTime() - Date.parse(record.createdAt) <= LAST_APPROVAL_WINDOW_MS);
  if (recent.length === 1) return recent[0];
  if (recent.length > 1) {
    throw new Error('Multiple recent pending approvals exist. Run `agentguard approvals list` and approve a specific action id.');
  }
  throw new Error('No pending approval is available to approve.');
}

function readApprovalStore(storePath: string, now: Date): ApprovalStore {
  if (!existsSync(storePath)) return { version: 1, records: [] };
  const raw = readStoreFile(storePath);
  const records = raw.records.filter((record) => Date.parse(record.expiresAt) > now.getTime());
  if (records.length !== raw.records.length) {
    writeApprovalStore(storePath, { version: 1, records }, now);
  }
  return { version: 1, records };
}

function readStoreFile(storePath: string): ApprovalStore {
  try {
    const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as Partial<ApprovalStore>;
    return {
      version: 1,
      records: Array.isArray(parsed.records) ? parsed.records.filter(isApprovalRecord) : [],
    };
  } catch {
    return { version: 1, records: [] };
  }
}

function writeApprovalStore(storePath: string, store: ApprovalStore, now: Date): void {
  const records = store.records.filter((record) => Date.parse(record.expiresAt) > now.getTime());
  if (records.length === 0) {
    rmSync(storePath, { force: true });
    return;
  }
  mkdirSync(dirname(storePath), { recursive: true, mode: 0o700 });
  writeFileSync(storePath, `${JSON.stringify({ version: 1, records }, null, 2)}\n`, { mode: 0o600 });
  chmodBestEffort(storePath, 0o600);
}

function isApprovalRecord(value: unknown): value is ApprovalRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Partial<ApprovalRecord>;
  return (
    typeof record.actionId === 'string' &&
    (record.status === 'pending' || record.status === 'approved') &&
    typeof record.actionFingerprint === 'string' &&
    typeof record.sessionId === 'string' &&
    typeof record.expiresAt === 'string'
  );
}

function normalizeActionInput(input: string): string {
  return input.trim();
}

function withApprovalStoreLock<T>(storePath: string, fn: () => T): T {
  const lockPath = `${storePath}.lock`;
  acquireApprovalStoreLock(lockPath);
  try {
    return fn();
  } finally {
    rmSync(lockPath, { recursive: true, force: true });
  }
}

function acquireApprovalStoreLock(lockPath: string): void {
  const startedAt = Date.now();
  mkdirSync(dirname(lockPath), { recursive: true, mode: 0o700 });
  while (true) {
    try {
      mkdirSync(lockPath, { mode: 0o700 });
      return;
    } catch (err) {
      if (!isAlreadyExistsError(err)) throw err;
      removeStaleLock(lockPath);
      if (Date.now() - startedAt > LOCK_TIMEOUT_MS) {
        throw new Error('Timed out waiting for AgentGuard approval store lock.');
      }
      sleepSync(25);
    }
  }
}

function removeStaleLock(lockPath: string): void {
  try {
    const ageMs = Date.now() - statSync(lockPath).mtimeMs;
    if (ageMs > LOCK_STALE_MS) {
      rmSync(lockPath, { recursive: true, force: true });
    }
  } catch {
    // Another process may have released the lock between mkdir attempts.
  }
}

function isAlreadyExistsError(err: unknown): boolean {
  return Boolean(err && typeof err === 'object' && (err as { code?: string }).code === 'EEXIST');
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function chmodBestEffort(path: string, mode: number): void {
  try {
    chmodSync(path, mode);
  } catch {
    // Best-effort hardening for platforms/filesystems that support chmod.
  }
}
