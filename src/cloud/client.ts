import { normalizeCloudUrl } from '../config.js';
import type { AgentGuardConfig } from '../config.js';
import type {
  EffectiveRuntimePolicy,
  RuntimeAction,
  RuntimeAuditEvent,
  RuntimeDecision,
} from '../runtime/types.js';
import { redactMetadata, redactPreview } from '../runtime/redaction.js';
import { buildAuditEvent } from '../runtime/audit.js';
import type { Advisory, SelfCheckMatch } from '../feed/types.js';

interface ApiSuccess<T> {
  success: true;
  data: T;
  meta?: ApiMeta;
}

interface ApiErrorEnvelope {
  success: false;
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
  meta?: ApiMeta;
}

interface ApiMeta {
  requestId?: string;
}

export class AgentGuardCloudClient {
  private readonly cloudUrl: string;
  private readonly apiKey?: string;
  private readonly agentJwt?: string;

  constructor(config: Pick<AgentGuardConfig, 'cloudUrl' | 'apiKey' | 'agentJwt'>) {
    this.cloudUrl = normalizeCloudUrl(config.cloudUrl || 'https://agentguard.gopluslabs.io');
    this.apiKey = config.apiKey;
    this.agentJwt = config.agentJwt;
  }

  get connected(): boolean {
    return Boolean(this.agentJwt || this.apiKey);
  }

  async status(): Promise<{ ok?: boolean; service?: string; status?: string; version?: string; detectors?: number }> {
    return this.requestData('/api/v1/status', { allowBareSuccess: true });
  }

  async fetchEffectivePolicy(): Promise<EffectiveRuntimePolicy> {
    this.requireCredential();
    const body = await this.request<EffectiveRuntimePolicy>('/api/v1/policies/effective');
    return body.data;
  }

  async evaluateAction(action: RuntimeAction): Promise<RuntimeDecision> {
    this.requireCredential();
    const body = await this.request<RuntimeDecision>('/api/v1/actions/evaluate', {
      method: 'POST',
      body: JSON.stringify(sanitizeActionRequest(action)),
    });
    return body.data;
  }

  async ingestEvents(events: RuntimeAuditEvent[]): Promise<void> {
    this.requireCredential();
    await this.request('/api/v1/events/ingest', {
      method: 'POST',
      body: JSON.stringify({
        events: events.map((event) => buildAuditEvent(event)),
      }),
    });
  }

  /**
   * Pull threat-feed advisories newer than `since`. Returns null when the
   * cloud doesn't expose the endpoint yet (404) — callers should treat null
   * as "no new advisories" rather than an error, so the subscribe command
   * works against older AgentGuard Cloud versions too.
   */
  async pullAdvisories(since?: string): Promise<Advisory[] | null> {
    const params = new URLSearchParams();
    if (since) params.set('since', since);
    const qs = params.toString();
    const path = `/api/v1/feed/advisories${qs ? `?${qs}` : ''}`;
    try {
      const body = await this.request<{ advisories: Advisory[] }>(path);
      return body.data.advisories ?? [];
    } catch (err) {
      if (err instanceof CloudRequestError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  async getAdvisory(id: string): Promise<Advisory | null> {
    try {
      return await this.requestData<Advisory>(`/api/v1/feed/advisories/${encodeURIComponent(id)}`);
    } catch (err) {
      if (err instanceof CloudRequestError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  /**
   * Report the outcome of a single advisory self-check. Matches paths are
   * redacted by the caller before they get here. Tolerates 404 so subscribe
   * still completes locally even if the report sink is absent server-side.
   */
  async reportSelfCheck(
    advisoryId: string,
    matches: SelfCheckMatch[],
    options: { elapsedMs?: number; warnings?: string[] } = {}
  ): Promise<void> {
    this.requireCredential();
    try {
      await this.request('/api/v1/feed/self-check-report', {
        method: 'POST',
        body: JSON.stringify({
          advisoryId,
          matches,
          elapsedMs: options.elapsedMs,
          warnings: options.warnings,
        }),
      });
    } catch (err) {
      if (err instanceof CloudRequestError && err.status === 404) {
        return;
      }
      throw err;
    }
  }

  async registerAgent(options: {
    email?: string;
    metadata?: Record<string, unknown>;
  } = {}): Promise<{ agentId: string; jwt: string; registerUrl: string }> {
    const body = await this.request<{
      agentId: string;
      jwt: string;
      registerUrl: string;
    }>('/api/agent/register', {
      method: 'POST',
      body: JSON.stringify({
        ...(options.email ? { email: options.email } : {}),
        ...(options.metadata ? { metadata: options.metadata } : {}),
      }),
    });
    return body.data;
  }

  async subscribeFeed(options: {
    ecosystems?: string[];
    webhookUrl?: string | null;
  } = {}): Promise<unknown | null> {
    this.requireCredential();
    try {
      const body = await this.request('/api/v1/feed/subscribe', {
        method: 'POST',
        body: JSON.stringify({
          ecosystems: options.ecosystems ?? [
            'skill',
            'plugin',
            'mcp_server',
            'supply_chain',
            'url',
            'prompt_injection',
          ],
          webhookUrl: options.webhookUrl ?? null,
        }),
      });
      return body.data;
    } catch (err) {
      if (err instanceof CloudRequestError && err.status === 404) {
        return null;
      }
      throw err;
    }
  }

  private async request<T = unknown>(path: string, init: RequestInit = {}): Promise<ApiSuccess<T>> {
    const body = await this.requestJson<T>(path, init);
    if (isApiSuccess<T>(body)) return body;
    throw buildCloudRequestError(200, path, body);
  }

  private async requestData<T = unknown>(
    path: string,
    init: RequestInit & { allowBareSuccess?: boolean } = {}
  ): Promise<T> {
    const { allowBareSuccess, ...requestInit } = init;
    const body = await this.requestJson<T>(path, requestInit);
    if (isApiSuccess<T>(body)) return body.data;
    if (allowBareSuccess && !hasApiSuccessField(body)) return body as T;
    throw buildCloudRequestError(200, path, body);
  }

  private async requestJson<T = unknown>(path: string, init: RequestInit = {}): Promise<ApiSuccess<T> | ApiErrorEnvelope | T | null> {
    const response = await fetch(`${this.cloudUrl}${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        ...this.authHeaders(),
        ...(init.headers || {}),
      },
      signal: AbortSignal.timeout(5000),
    });
    const body = (await response.json().catch(() => null)) as ApiSuccess<T> | ApiErrorEnvelope | T | null;
    if (!response.ok) {
      throw buildCloudRequestError(response.status, path, body);
    }
    return body;
  }

  private authHeaders(): Record<string, string> {
    if (this.agentJwt) {
      return { Authorization: `Bearer ${this.agentJwt}` };
    }
    if (this.apiKey) {
      return { 'x-api-key': this.apiKey };
    }
    return {};
  }

  private requireCredential(): void {
    if (!this.agentJwt && !this.apiKey) {
      throw new Error('AgentGuard Cloud credential is not configured.');
    }
  }
}

export class CloudRequestError extends Error {
  constructor(
    public readonly status: number,
    public readonly path: string,
    public readonly code?: string,
    message?: string,
    public readonly requestId?: string,
    public readonly details?: unknown
  ) {
    super(message ? `AgentGuard Cloud request failed: ${status} (${path}): ${message}` : `AgentGuard Cloud request failed: ${status} (${path})`);
    this.name = 'CloudRequestError';
  }
}

function isApiSuccess<T>(body: unknown): body is ApiSuccess<T> {
  return Boolean(body) && typeof body === 'object' && (body as { success?: unknown }).success === true;
}

function isApiErrorEnvelope(body: unknown): body is ApiErrorEnvelope {
  return Boolean(body) && typeof body === 'object' && (body as { success?: unknown }).success === false;
}

function hasApiSuccessField(body: unknown): boolean {
  return body !== null && typeof body === 'object' && 'success' in body;
}

function buildCloudRequestError(status: number, path: string, body: unknown): CloudRequestError {
  if (isApiErrorEnvelope(body)) {
    return new CloudRequestError(
      status,
      path,
      body.error?.code,
      body.error?.message,
      body.meta?.requestId,
      body.error?.details
    );
  }
  return new CloudRequestError(status, path);
}

function sanitizeActionRequest(action: RuntimeAction): RuntimeAction {
  return {
    sessionId: redactPreview(action.sessionId, 160),
    agentHost: action.agentHost,
    actionType: action.actionType,
    toolName: redactPreview(action.toolName, 160),
    input: redactPreview(action.input, 64_000),
    cwd: action.cwd ? redactPreview(action.cwd, 500) : undefined,
    sourceSkill: action.sourceSkill ? redactPreview(action.sourceSkill, 240) : undefined,
    metadata: redactMetadata(action.metadata),
  };
}
