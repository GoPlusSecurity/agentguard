import type { AgentGuardConfig } from '../config.js';
import type {
  EffectiveRuntimePolicy,
  RuntimeAction,
  RuntimeAuditEvent,
  RuntimeDecision,
} from '../runtime/types.js';
import { redactPreview, redactReasons } from '../runtime/redaction.js';

interface ApiSuccess<T> {
  success: true;
  data: T;
}

export class AgentGuardCloudClient {
  private readonly cloudUrl: string;
  private readonly apiKey?: string;

  constructor(config: Pick<AgentGuardConfig, 'cloudUrl' | 'apiKey'>) {
    this.cloudUrl = (config.cloudUrl || 'https://agentguard.gopluslabs.io').replace(/\/+$/, '');
    this.apiKey = config.apiKey;
  }

  get connected(): boolean {
    return Boolean(this.apiKey);
  }

  async status(): Promise<{ status: string; version?: string }> {
    const body = await this.request<{ status: string; version?: string }>('/api/v1/status');
    return body.data;
  }

  async fetchEffectivePolicy(): Promise<EffectiveRuntimePolicy> {
    this.requireApiKey();
    const body = await this.request<EffectiveRuntimePolicy>('/api/v1/policies/effective');
    return body.data;
  }

  async evaluateAction(action: RuntimeAction): Promise<RuntimeDecision> {
    this.requireApiKey();
    const body = await this.request<RuntimeDecision>('/api/v1/actions/evaluate', {
      method: 'POST',
      body: JSON.stringify({
        ...action,
        input: redactPreview(action.input, 64_000),
      }),
    });
    return body.data;
  }

  async ingestEvents(events: RuntimeAuditEvent[]): Promise<void> {
    this.requireApiKey();
    await this.request('/api/v1/events/ingest', {
      method: 'POST',
      body: JSON.stringify({
        events: events.map((event) => ({
          ...event,
          input: redactPreview(event.input),
          reasons: redactReasons(event.reasons),
        })),
      }),
    });
  }

  async createApproval(event: RuntimeAuditEvent): Promise<string | null> {
    this.requireApiKey();
    const body = await this.request<{ approvalId: string }>('/api/v1/approvals', {
      method: 'POST',
      body: JSON.stringify({
        ...event,
        input: redactPreview(event.input),
        reasons: redactReasons(event.reasons),
      }),
    });
    return body.data.approvalId || null;
  }

  private async request<T = unknown>(path: string, init: RequestInit = {}): Promise<ApiSuccess<T>> {
    const response = await fetch(`${this.cloudUrl}${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        ...(this.apiKey ? { 'x-api-key': this.apiKey } : {}),
        ...(init.headers || {}),
      },
      signal: AbortSignal.timeout(5000),
    });
    const body = (await response.json().catch(() => null)) as ApiSuccess<T> | null;
    if (!response.ok || !body?.success) {
      throw new Error(`AgentGuard Cloud request failed: ${response.status}`);
    }
    return body;
  }

  private requireApiKey(): void {
    if (!this.apiKey) {
      throw new Error('AgentGuard Cloud API key is not configured.');
    }
  }
}
