import type {
  AgentLifecycleCapabilities,
  CoverageLevel,
  LlmEndpointTier,
  LlmRequestPurpose,
  MissingLlmFact,
  RuntimeAction,
  RuntimeAgentHost,
  RuntimeLifecycleStage,
} from '../../runtime/types.js';
import { DSH_LLM_CAPABILITIES } from '../../dsh/llm-privacy.js';

export type ConformanceHost = Extract<RuntimeAgentHost, 'dsh' | 'hermes' | 'openclaw' | 'codex' | 'claude-code'>;

export interface ConformanceActionFixture {
  name: string;
  input: string;
  destination?: { host: string; tier: LlmEndpointTier };
  credentialKind?: 'api_key' | 'oauth' | 'ambient' | 'none' | 'unknown';
  credentialPresent?: boolean | 'unknown';
  missingFacts?: MissingLlmFact[];
  payloadBytes?: number;
  attachmentBytes?: number;
  filePathCount?: number;
  purpose?: LlmRequestPurpose;
}

export const CONFORMANCE_ACTION_FIXTURES: readonly ConformanceActionFixture[] = [
  {
    name: 'local-model',
    input: 'Summarize this repository.',
    destination: { host: 'localhost', tier: 'T0' },
    credentialKind: 'none',
    credentialPresent: false,
    payloadBytes: 128,
    attachmentBytes: 0,
    filePathCount: 0,
  },
  {
    name: 'official-provider',
    input: 'Summarize this repository.',
    destination: { host: 'api.openai.com', tier: 'T1' },
    credentialKind: 'api_key',
    credentialPresent: true,
    payloadBytes: 128,
    attachmentBytes: 0,
    filePathCount: 0,
  },
  {
    name: 'known-aggregator',
    input: 'Summarize this repository.',
    destination: { host: 'openrouter.ai', tier: 'T2' },
    credentialKind: 'api_key',
    credentialPresent: true,
    payloadBytes: 128,
    attachmentBytes: 0,
    filePathCount: 0,
  },
  {
    name: 'unknown-relay-with-key',
    input: 'Summarize this repository.',
    destination: { host: 'relay.example.net', tier: 'T3' },
    credentialKind: 'api_key',
    credentialPresent: true,
    payloadBytes: 128,
    attachmentBytes: 0,
    filePathCount: 0,
  },
  {
    name: 'high-risk-endpoint',
    input: 'Summarize this repository.',
    destination: { host: 'model.evil.zip', tier: 'T4' },
    credentialKind: 'api_key',
    credentialPresent: true,
    payloadBytes: 128,
    attachmentBytes: 0,
    filePathCount: 0,
  },
  {
    name: 'unknown-relay-missing-transport-facts',
    input: 'Summarize this repository.',
    credentialKind: 'unknown',
    credentialPresent: 'unknown',
    missingFacts: ['final_destination', 'credential_kind', 'credential_presence'],
    purpose: 'conversation',
  },
];

export function buildConformanceAction(fixture: ConformanceActionFixture, agentHost: ConformanceHost): RuntimeAction {
  const requestId = `conformance:${fixture.name}`;
  return {
    sessionId: `conformance:${agentHost}`,
    agentHost,
    actionType: 'llm_request',
    toolName: 'model_request',
    input: fixture.input,
    lifecycleStage: 'model_request',
    canBlockCurrentAction: true,
    coverageLevel: fixture.missingFacts?.length ? 'unsupported' : 'full',
    missingFacts: fixture.missingFacts ?? [],
    llm: {
      schemaVersion: 1,
      requestId,
      sessionId: `conformance:${agentHost}`,
      purpose: fixture.purpose ?? 'conversation',
      lifecycleStage: 'model_request',
      canBlockCurrentAction: true,
      provider: 'fixture-provider',
      model: 'fixture-model',
      credentialKind: fixture.credentialKind ?? 'unknown',
      credentialPresent: fixture.credentialPresent ?? 'unknown',
      ...(fixture.destination ? {
        destination: {
          scheme: 'https',
          host: fixture.destination.host,
          path: '/v1/chat/completions',
          tier: fixture.destination.tier,
        },
      } : {}),
      ...(fixture.payloadBytes === undefined ? {} : { payloadBytes: fixture.payloadBytes }),
      ...(fixture.attachmentBytes === undefined ? {} : { attachmentBytes: fixture.attachmentBytes }),
      ...(fixture.filePathCount === undefined ? {} : { filePathCount: fixture.filePathCount }),
    },
  };
}

export interface LifecycleConformanceEvent {
  scenario: 'ordinary' | 'tool_loop_second' | 'retry' | 'fallback' | 'auxiliary' | 'streaming' | 'embedding' | 'file_upload' | 'post_tool_batch' | 'config_change' | 'model_switch';
  lifecycleStage: RuntimeLifecycleStage;
  coverageLevel: CoverageLevel;
  canBlockCurrentAction: boolean;
  missingFacts: MissingLlmFact[];
  purpose: LlmRequestPurpose;
}

export interface LifecycleConformanceFixture {
  adapter: ConformanceHost;
  capabilities: AgentLifecycleCapabilities;
  events: readonly LifecycleConformanceEvent[];
}

const OBSERVER_REQUEST_GAPS: MissingLlmFact[] = [
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

const CODEX_CAPABILITIES: AgentLifecycleCapabilities = {
  userPrompt: 'blocking',
  promptExpansion: 'none',
  modelRequest: 'none',
  modelResponse: 'none',
  preTool: 'blocking',
  postTool: 'observe_only',
  toolOutputRewrite: true,
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

const CLAUDE_CAPABILITIES: AgentLifecycleCapabilities = {
  userPrompt: 'blocking',
  promptExpansion: 'blocking',
  modelRequest: 'none',
  modelResponse: 'none',
  preTool: 'blocking',
  postTool: 'blocking',
  toolOutputRewrite: true,
  postToolBatch: 'blocking',
  configChange: 'blocking',
  modelSwitch: 'blocking',
  assistantDisplay: 'rewrite_display_only',
  finalDestination: false,
  credentialFacts: false,
  exactPayloadBytes: false,
  retryAndFallback: false,
  auxiliaryModelCalls: false,
};

const DSH_EVENTS: LifecycleConformanceEvent[] = [
  event('ordinary', 'model_request', 'partial', true, OBSERVER_REQUEST_GAPS),
  event('streaming', 'model_response', 'partial', true, ['complete_response', 'response_source', 'final_destination']),
  event('tool_loop_second', 'pre_tool', 'partial', true, ['final_destination', 'credential_kind', 'credential_presence']),
  event('retry', 'model_request', 'unsupported', false, ['retry_and_fallback']),
  event('fallback', 'model_request', 'unsupported', false, ['retry_and_fallback']),
  event('auxiliary', 'model_request', 'unsupported', false, ['auxiliary_model_calls']),
  event('embedding', 'model_request', 'unsupported', false, ['retry_and_fallback'], 'embedding'),
  event('file_upload', 'model_request', 'unsupported', false, ['retry_and_fallback'], 'file_upload'),
];

export const LIFECYCLE_CONFORMANCE_FIXTURES: readonly LifecycleConformanceFixture[] = [
  {
    adapter: 'dsh',
    capabilities: DSH_LLM_CAPABILITIES,
    events: DSH_EVENTS,
  },
  {
    adapter: 'hermes',
    capabilities: {
      userPrompt: 'none', promptExpansion: 'none', modelRequest: 'observe_only', modelResponse: 'observe_only',
      preTool: 'blocking', postTool: 'observe_only', toolOutputRewrite: false, postToolBatch: 'none',
      configChange: 'none', modelSwitch: 'none', assistantDisplay: 'none', finalDestination: false,
      credentialFacts: false, exactPayloadBytes: false, retryAndFallback: false, auxiliaryModelCalls: false,
    },
    events: [
      event('ordinary', 'model_request', 'observe_only', false, OBSERVER_REQUEST_GAPS),
      event('streaming', 'model_response', 'observe_only', false, ['complete_response', 'response_source', 'retry_and_fallback']),
      event('tool_loop_second', 'pre_tool', 'partial', true, ['final_destination', 'credential_kind', 'credential_presence']),
      event('retry', 'model_request', 'observe_only', false, ['retry_and_fallback']),
      event('fallback', 'model_response', 'observe_only', false, ['retry_and_fallback']),
      event('auxiliary', 'model_request', 'unsupported', false, ['auxiliary_model_calls']),
      event('embedding', 'model_request', 'unsupported', false, ['auxiliary_model_calls'], 'embedding'),
      event('file_upload', 'model_request', 'unsupported', false, ['auxiliary_model_calls'], 'file_upload'),
    ],
  },
  {
    adapter: 'openclaw',
    capabilities: {
      userPrompt: 'blocking', promptExpansion: 'blocking', modelRequest: 'observe_only', modelResponse: 'observe_only',
      preTool: 'blocking', postTool: 'observe_only', toolOutputRewrite: false, postToolBatch: 'none',
      configChange: 'none', modelSwitch: 'none', assistantDisplay: 'none', finalDestination: false,
      credentialFacts: false, exactPayloadBytes: false, retryAndFallback: false, auxiliaryModelCalls: false,
    },
    events: [
      event('ordinary', 'run_start', 'partial', true, ['final_destination', 'credential_kind', 'credential_presence']),
      event('streaming', 'model_response', 'observe_only', false, ['complete_response', 'response_source', 'retry_and_fallback']),
      event('tool_loop_second', 'pre_tool', 'partial', true, ['final_destination']),
      event('retry', 'model_request', 'observe_only', false, ['retry_and_fallback']),
      event('fallback', 'model_response', 'observe_only', false, ['retry_and_fallback']),
      event('auxiliary', 'model_request', 'unsupported', false, ['auxiliary_model_calls']),
      event('embedding', 'model_request', 'unsupported', false, ['auxiliary_model_calls'], 'embedding'),
      event('file_upload', 'model_request', 'unsupported', false, ['auxiliary_model_calls'], 'file_upload'),
    ],
  },
  {
    adapter: 'codex',
    capabilities: CODEX_CAPABILITIES,
    events: [
      event('ordinary', 'user_prompt', 'partial', true, ['complete_payload']),
      event('tool_loop_second', 'pre_tool', 'partial', true, ['final_destination', 'credential_kind', 'credential_presence']),
      event('streaming', 'post_tool', 'partial', false, ['complete_response', 'response_source']),
      event('retry', 'model_request', 'unsupported', false, ['final_destination', 'retry_and_fallback']),
      event('fallback', 'model_request', 'unsupported', false, ['final_destination', 'retry_and_fallback']),
      event('auxiliary', 'model_request', 'unsupported', false, ['final_destination', 'auxiliary_model_calls']),
      event('embedding', 'model_request', 'unsupported', false, ['final_destination', 'credential_kind'], 'embedding'),
      event('file_upload', 'model_request', 'unsupported', false, ['final_destination', 'credential_kind'], 'file_upload'),
    ],
  },
  {
    adapter: 'claude-code',
    capabilities: CLAUDE_CAPABILITIES,
    events: [
      event('ordinary', 'user_prompt', 'partial', true, ['complete_payload']),
      event('tool_loop_second', 'pre_tool', 'partial', true, ['final_destination', 'credential_kind', 'credential_presence']),
      event('streaming', 'assistant_display', 'observe_only', false, ['complete_response']),
      event('retry', 'model_switch', 'partial', true, ['final_destination', 'retry_and_fallback']),
      event('fallback', 'model_switch', 'partial', true, ['final_destination', 'retry_and_fallback']),
      event('auxiliary', 'model_request', 'unsupported', false, ['final_destination', 'auxiliary_model_calls']),
      event('embedding', 'model_request', 'unsupported', false, ['final_destination', 'credential_kind'], 'embedding'),
      event('file_upload', 'model_request', 'unsupported', false, ['final_destination', 'credential_kind'], 'file_upload'),
      event('post_tool_batch', 'post_tool_batch', 'partial', true, ['complete_payload', 'exact_payload_bytes']),
      event('config_change', 'config_change', 'partial', true, ['final_destination']),
      event('model_switch', 'model_switch', 'partial', true, ['final_destination', 'retry_and_fallback']),
    ],
  },
];

function event(
  scenario: LifecycleConformanceEvent['scenario'],
  lifecycleStage: RuntimeLifecycleStage,
  coverageLevel: CoverageLevel,
  canBlockCurrentAction: boolean,
  missingFacts: MissingLlmFact[],
  purpose: LlmRequestPurpose = 'conversation',
): LifecycleConformanceEvent {
  return { scenario, lifecycleStage, coverageLevel, canBlockCurrentAction, missingFacts, purpose };
}
