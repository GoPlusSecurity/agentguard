import type { ActionEnvelope } from '../types/action.js';
import type { HookAdapter, HookInput } from './types.js';
import type {
  AgentLifecycleCapabilities,
  MissingLlmFact,
  RuntimeActionType,
  RuntimeLifecycleStage,
} from '../runtime/types.js';

/**
 * Tool name → action type mapping for OpenClaw
 */
const TOOL_ACTION_MAP: Record<string, string> = {
  exec: 'exec_command',
  write: 'write_file',
  read: 'read_file',
  web_search: 'web_search',
  web_fetch: 'network_request',
  browser: 'network_request',
};

export type OpenClawLifecycleHook =
  | 'before_agent_run'
  | 'llm_input'
  | 'llm_output'
  | 'model_call_started'
  | 'model_call_ended'
  | 'before_tool_call'
  | 'after_tool_call';

export interface OpenClawRuntimeHookInput {
  rawInput: Record<string, unknown>;
  actionType: RuntimeActionType;
  toolName: string;
  sessionId?: string;
  phase?: 'pre' | 'post';
}

const REQUEST_MISSING_FACTS: MissingLlmFact[] = [
  'complete_payload',
  'final_destination',
  'credential_kind',
  'credential_presence',
  'exact_payload_bytes',
  'attachment_bytes',
  'file_path_count',
  'retry_and_fallback',
  'auxiliary_model_calls',
];

const RESPONSE_MISSING_FACTS: MissingLlmFact[] = [
  'complete_response',
  'final_destination',
  'credential_kind',
  'credential_presence',
  'retry_and_fallback',
  'auxiliary_model_calls',
  'response_source',
];

/**
 * OpenClaw hook adapter
 *
 * Bridges OpenClaw's before_tool_call / after_tool_call plugin hooks
 * to the common AgentGuard decision engine.
 *
 * OpenClaw plugin hooks receive an event object:
 *   { toolName: string, params: Record<string, any>, toolCallId?: string }
 *
 * Blocking is done by returning { block: true, blockReason: "..." }
 * from the before_tool_call handler.
 */
export class OpenClawAdapter implements HookAdapter {
  readonly name = 'openclaw';
  readonly capabilities: AgentLifecycleCapabilities = {
    userPrompt: 'blocking',
    promptExpansion: 'blocking',
    modelRequest: 'observe_only',
    modelResponse: 'observe_only',
    preTool: 'blocking',
    postTool: 'observe_only',
    toolOutputRewrite: false,
    postToolBatch: 'none',
    configChange: 'none',
    modelSwitch: 'none',
    assistantDisplay: 'none',
    finalDestination: false,
    credentialFacts: false,
    exactPayloadBytes: false,
    retryAndFallback: false,
    auxiliaryModelCalls: false,
  };

  parseInput(raw: unknown): HookInput {
    const event = raw as Record<string, unknown>;
    const toolInput =
      (event.params as Record<string, unknown>) ||
      (event.toolInput as Record<string, unknown>) ||
      (event.tool_input as Record<string, unknown>) ||
      (event.args as Record<string, unknown>) ||
      {};
    return {
      toolName: (event.toolName as string) || (event.tool_name as string) || '',
      toolInput,
      eventType: 'pre', // before_tool_call = pre
      raw: event,
    };
  }

  mapToolToActionType(toolName: string): string | null {
    // Direct match
    if (TOOL_ACTION_MAP[toolName]) {
      return TOOL_ACTION_MAP[toolName];
    }
    // Prefix match for tool families (e.g. "exec_python" → "exec_command")
    for (const [prefix, actionType] of Object.entries(TOOL_ACTION_MAP)) {
      if (toolName.startsWith(prefix)) {
        return actionType;
      }
    }
    return null;
  }

  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null {
    const actionType = this.mapToolToActionType(input.toolName);
    if (!actionType) return null;

    const actor = {
      skill: {
        id: initiatingSkill || 'openclaw-session',
        source: initiatingSkill || 'openclaw',
        version_ref: '0.0.0',
        artifact_hash: '',
      },
    };

    const context = {
      session_id: `openclaw-${Date.now()}`,
      user_present: true,
      env: 'prod' as const,
      time: new Date().toISOString(),
      initiating_skill: initiatingSkill || undefined,
    };

    let actionData: Record<string, unknown>;

    switch (actionType) {
      case 'exec_command':
        actionData = {
          command: (input.toolInput.command as string) || '',
          args: [],
        };
        break;

      case 'write_file':
        actionData = {
          path: (input.toolInput.path as string) ||
                (input.toolInput.file_path as string) || '',
        };
        break;

      case 'read_file':
        actionData = {
          path: (input.toolInput.path as string) ||
                (input.toolInput.file_path as string) || '',
        };
        break;

      case 'network_request':
        actionData = {
          method: (input.toolInput.method as string) || 'GET',
          url: (input.toolInput.url as string) || '',
          body_preview: input.toolInput.body as string | undefined,
        };
        break;

      case 'web_search':
        actionData = {
          query: (input.toolInput.query as string) || '',
        };
        break;

      default:
        return null;
    }

    return {
      actor,
      action: { type: actionType, data: actionData },
      context,
    } as unknown as ActionEnvelope;
  }

  async inferInitiatingSkill(input: HookInput): Promise<string | null> {
    // Try to get plugin ID from tool → plugin mapping
    try {
      const { getPluginIdFromTool } = await import('./openclaw-plugin.js');
      return getPluginIdFromTool(input.toolName);
    } catch {
      // Mapping not available (plugin not loaded)
      return null;
    }
  }

  /**
   * Normalize each public OpenClaw lifecycle event into the existing runtime
   * protection input contract. Model observers never gain blocking authority,
   * and transport facts absent from the hook stay absent.
   */
  normalizeLifecycleEvent(
    hook: OpenClawLifecycleHook,
    raw: unknown,
    rawContext?: unknown,
  ): OpenClawRuntimeHookInput[] {
    const event = record(raw);
    const context = record(rawContext);
    if (hook === 'before_tool_call' || hook === 'after_tool_call') {
      const toolName = this.readToolName(event);
      return [{
        rawInput: event,
        actionType: this.mapToolToRuntimeAction(toolName, event),
        toolName,
        sessionId: this.readSessionId(event, context),
        phase: hook === 'after_tool_call' ? 'post' : 'pre',
      }];
    }

    if (hook === 'before_agent_run') {
      const runId = firstString(context.runId, event.runId);
      const sessionId = this.readSessionId(event, context) || scopedSessionId(runId);
      return [this.lifecycleObservation({
        hook,
        actionType: 'llm_request',
        lifecycleStage: 'run_start',
        requestId: runId ? `openclaw:${runId}:run` : `openclaw:${sessionId}:run`,
        sessionId,
        canBlockCurrentAction: true,
        coverageLevel: 'partial',
        missingFacts: REQUEST_MISSING_FACTS,
        provider: stringOrUndefined(context.modelProviderId),
        model: stringOrUndefined(context.modelId),
        input: {
          prompt: stringOrUndefined(event.prompt),
          messages: arrayOrEmpty(event.messages),
          systemPrompt: stringOrUndefined(event.systemPrompt),
        },
        messageCount: arrayLength(event.messages),
      })];
    }

    const runId = firstString(event.runId, context.runId);
    const callId = firstString(event.callId);
    const sessionId = this.readSessionId(event, context) || scopedSessionId(runId || callId);
    const requestId = callId ? `openclaw:${callId}` : runId ? `openclaw:${runId}` : `openclaw:${sessionId}`;
    const provider = stringOrUndefined(event.provider);
    const model = stringOrUndefined(event.model);

    if (hook === 'llm_input') {
      return [this.lifecycleObservation({
        hook,
        actionType: 'llm_request',
        lifecycleStage: 'model_request',
        requestId,
        sessionId,
        canBlockCurrentAction: false,
        coverageLevel: 'observe_only',
        missingFacts: REQUEST_MISSING_FACTS,
        provider,
        model,
        input: {
          systemPrompt: stringOrUndefined(event.systemPrompt),
          prompt: stringOrUndefined(event.prompt),
          historyMessages: arrayOrEmpty(event.historyMessages),
          imagesCount: nonNegativeInteger(event.imagesCount),
          tools: arrayOrUndefined(event.tools),
        },
        messageCount: arrayLength(event.historyMessages),
      })];
    }

    if (hook === 'llm_output') {
      return [this.lifecycleObservation({
        hook,
        actionType: 'llm_response',
        lifecycleStage: 'model_response',
        requestId,
        sessionId,
        canBlockCurrentAction: false,
        coverageLevel: 'observe_only',
        missingFacts: RESPONSE_MISSING_FACTS,
        provider,
        model,
        input: {
          assistantTexts: arrayOrEmpty(event.assistantTexts),
          lastAssistant: event.lastAssistant,
        },
      })];
    }

    if (hook === 'model_call_started') {
      return [this.lifecycleObservation({
        hook,
        actionType: 'llm_request',
        lifecycleStage: 'model_request',
        requestId,
        parentRequestId: runId ? `openclaw:${runId}` : undefined,
        sessionId,
        canBlockCurrentAction: false,
        coverageLevel: 'observe_only',
        missingFacts: REQUEST_MISSING_FACTS,
        provider,
        model,
        apiMode: firstString(event.api, event.transport) || undefined,
        input: diagnosticInput(event),
      })];
    }

    const common = {
      requestId,
      parentRequestId: runId ? `openclaw:${runId}` : undefined,
      sessionId,
      canBlockCurrentAction: false,
      coverageLevel: 'observe_only' as const,
      provider,
      model,
      apiMode: firstString(event.api, event.transport) || undefined,
      input: diagnosticInput(event),
    };
    const observations: OpenClawRuntimeHookInput[] = [];
    const requestPayloadBytes = nonNegativeInteger(event.requestPayloadBytes);
    if (requestPayloadBytes !== undefined) {
      observations.push(this.lifecycleObservation({
        ...common,
        hook: 'model_call_ended',
        actionType: 'llm_request',
        lifecycleStage: 'model_request',
        missingFacts: REQUEST_MISSING_FACTS.filter(fact => fact !== 'exact_payload_bytes'),
        payloadBytes: requestPayloadBytes,
        suffix: 'request',
      }));
    }
    observations.push(this.lifecycleObservation({
      ...common,
      hook: 'model_call_ended',
      actionType: 'llm_response',
      lifecycleStage: 'model_response',
      missingFacts: RESPONSE_MISSING_FACTS,
      payloadBytes: nonNegativeInteger(event.responseStreamBytes),
      suffix: 'response',
    }));
    return observations;
  }

  readToolName(raw: unknown): string {
    const event = record(raw);
    return firstString(event.toolName, event.tool_name, event.name, event.id);
  }

  readFilePath(raw: unknown): string | undefined {
    const event = record(raw);
    const params = readParams(event);
    return firstString(
      params?.path,
      params?.file_path,
      params?.filePath,
      params?.target,
      event.path,
      event.file_path,
      event.filePath,
      event.target,
    ) || undefined;
  }

  mapToolToRuntimeAction(toolName: string, raw?: unknown): RuntimeActionType {
    const normalized = toolName.toLowerCase();
    if (
      normalized === 'web_search' || normalized === 'websearch' ||
      normalized.includes('web_search') || normalized.includes('web search') ||
      normalized.includes('search_query')
    ) return 'web_search';
    if (
      normalized === 'exec' || normalized === 'bash' || normalized === 'cmd' ||
      normalized === 'command' || normalized === 'terminal' || normalized === 'run' ||
      normalized.includes('exec') || normalized.includes('execute') ||
      normalized.includes('shell') || normalized.includes('terminal') ||
      normalized.includes('command') || normalized.includes('process') ||
      normalized.includes('spawn')
    ) return 'shell';
    if (normalized === 'read' || normalized.includes('read') || normalized.includes('fetch_file')) {
      return 'file_read';
    }
    if (
      normalized === 'write' || normalized === 'edit' || normalized === 'apply_patch' ||
      normalized === 'patch' || normalized === 'create' || normalized === 'save' ||
      normalized === 'delete' || normalized === 'remove' || normalized === 'rename' ||
      normalized === 'scaffold' || normalized.includes('write') ||
      normalized.includes('edit') || normalized.includes('patch') ||
      normalized.includes('delete') || normalized.includes('remove') ||
      normalized.includes('rename') || normalized.includes('scaffold')
    ) return 'file_write';
    if (
      normalized.includes('web') || normalized.includes('browser') ||
      normalized.includes('http') || normalized.includes('fetch') || normalized.includes('request')
    ) return 'network';

    const event = record(raw);
    const params = readParams(event);
    if (typeof event.command === 'string' || typeof event.cmd === 'string' ||
        typeof params?.command === 'string' || typeof params?.cmd === 'string') return 'shell';
    if (typeof params?.url === 'string' || typeof params?.uri === 'string') return 'network';
    if (typeof params?.query === 'string' || typeof params?.q === 'string') return 'web_search';
    if (typeof params?.content === 'string' || typeof params?.newContent === 'string' ||
        typeof params?.patch === 'string') return 'file_write';
    if (this.readFilePath(event)) return 'file_read';
    return 'other';
  }

  private readSessionId(event: Record<string, unknown>, context: Record<string, unknown>): string | undefined {
    return firstString(context.sessionId, context.sessionKey, event.sessionId, event.session_id) || undefined;
  }

  private lifecycleObservation(options: {
    hook: OpenClawLifecycleHook;
    actionType: 'llm_request' | 'llm_response';
    lifecycleStage: RuntimeLifecycleStage;
    requestId: string;
    parentRequestId?: string;
    sessionId: string;
    canBlockCurrentAction: boolean;
    coverageLevel: 'partial' | 'observe_only';
    missingFacts: MissingLlmFact[];
    input: unknown;
    provider?: string;
    model?: string;
    apiMode?: string;
    payloadBytes?: number;
    messageCount?: number;
    suffix?: string;
  }): OpenClawRuntimeHookInput {
    const llm: Record<string, unknown> = {
      schemaVersion: 1,
      requestId: options.requestId,
      ...(options.parentRequestId ? { parentRequestId: options.parentRequestId } : {}),
      sessionId: options.sessionId,
      purpose: 'unknown',
      lifecycleStage: options.lifecycleStage,
      canBlockCurrentAction: options.canBlockCurrentAction,
      ...(options.provider ? { provider: options.provider } : {}),
      ...(options.model ? { model: options.model } : {}),
      ...(options.apiMode ? { apiMode: options.apiMode } : {}),
      credentialKind: 'unknown',
      credentialPresent: 'unknown',
      ...(options.payloadBytes !== undefined ? { payloadBytes: options.payloadBytes } : {}),
      ...(options.messageCount !== undefined ? { messageCount: options.messageCount } : {}),
    };
    return {
      rawInput: {
        input: safeStringify(options.input),
        lifecycleStage: options.lifecycleStage,
        canBlockCurrentAction: options.canBlockCurrentAction,
        coverageLevel: options.coverageLevel,
        missingFacts: [...options.missingFacts],
        llm,
        metadata: {
          openClawHook: options.hook,
          perModelRequestGate: 'unsupported',
          retryAndFallback: 'unsupported',
          compaction: 'unsupported',
          auxiliaryModelCalls: 'unsupported',
        },
      },
      actionType: options.actionType,
      toolName: `openclaw.${options.hook}${options.suffix ? `.${options.suffix}` : ''}`,
      sessionId: options.sessionId,
      phase: options.actionType === 'llm_response' ? 'post' : 'pre',
    };
  }
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function readParams(event: Record<string, unknown>): Record<string, unknown> | undefined {
  for (const value of [event.params, event.toolInput, event.tool_input, event.args, event.input]) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  }
  return undefined;
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function arrayOrEmpty(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function arrayOrUndefined(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function arrayLength(value: unknown): number | undefined {
  return Array.isArray(value) ? value.length : undefined;
}

function nonNegativeInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function scopedSessionId(scope: string): string {
  return scope ? `openclaw:${scope}` : `openclaw:unscoped:${Date.now()}`;
}

function diagnosticInput(event: Record<string, unknown>): Record<string, unknown> {
  return {
    runId: stringOrUndefined(event.runId),
    callId: stringOrUndefined(event.callId),
    provider: stringOrUndefined(event.provider),
    model: stringOrUndefined(event.model),
    api: stringOrUndefined(event.api),
    transport: stringOrUndefined(event.transport),
    durationMs: nonNegativeInteger(event.durationMs),
    outcome: stringOrUndefined(event.outcome),
    errorCategory: stringOrUndefined(event.errorCategory),
    failureKind: stringOrUndefined(event.failureKind),
    requestPayloadBytes: nonNegativeInteger(event.requestPayloadBytes),
    responseStreamBytes: nonNegativeInteger(event.responseStreamBytes),
    timeToFirstByteMs: nonNegativeInteger(event.timeToFirstByteMs),
  };
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, (_key, item) => typeof item === 'bigint' ? item.toString() : item);
  } catch {
    return '[unserializable OpenClaw hook payload]';
  }
}
