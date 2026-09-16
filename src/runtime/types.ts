export type CloudPolicyDecision = 'allow' | 'warn' | 'require_approval' | 'block';
export type RuntimeRiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type RuntimeSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type CoverageLevel = 'full' | 'partial' | 'observe_only' | 'unsupported';
export type EnforcementStatus = 'enforced' | 'would_block' | 'observed' | 'unsupported';

export type AgentLifecycleAccess = 'blocking' | 'observe_only' | 'none';
export type AssistantDisplayAccess = 'rewrite_display_only' | 'observe_only' | 'none';

export interface AgentLifecycleCapabilities {
  userPrompt: AgentLifecycleAccess;
  promptExpansion: AgentLifecycleAccess;
  modelRequest: AgentLifecycleAccess;
  modelResponse: AgentLifecycleAccess;
  preTool: AgentLifecycleAccess;
  postTool: AgentLifecycleAccess;
  toolOutputRewrite: boolean;
  postToolBatch: AgentLifecycleAccess;
  configChange: AgentLifecycleAccess;
  modelSwitch: AgentLifecycleAccess;
  assistantDisplay: AssistantDisplayAccess;
  finalDestination: boolean;
  credentialFacts: boolean;
  exactPayloadBytes: boolean;
  retryAndFallback: boolean;
  auxiliaryModelCalls: boolean;
}

export type RuntimeLifecycleStage =
  | 'user_prompt'
  | 'prompt_expansion'
  | 'run_start'
  | 'model_request'
  | 'model_response'
  | 'pre_tool'
  | 'post_tool'
  | 'post_tool_batch'
  | 'config_change'
  | 'model_switch'
  | 'assistant_display'
  | 'stop';

export type LlmRequestPurpose =
  | 'unknown'
  | 'conversation'
  | 'compaction'
  | 'title'
  | 'vision'
  | 'embedding'
  | 'file_upload'
  | 'plugin'
  | 'other';

export type CredentialKind = 'api_key' | 'oauth' | 'aws' | 'ambient' | 'none' | 'unknown';
export type LlmEndpointTier = 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'unknown';

export type MissingLlmFact =
  | 'complete_payload'
  | 'complete_response'
  | 'final_destination'
  | 'credential_kind'
  | 'credential_presence'
  | 'exact_payload_bytes'
  | 'attachment_bytes'
  | 'file_path_count'
  | 'retry_and_fallback'
  | 'auxiliary_model_calls'
  | 'response_source';

export type RuntimePrivacyRuleId =
  | 'UNTRUSTED_LLM_ENDPOINT'
  | 'PII_EGRESS'
  | 'LLM_ENDPOINT_HIJACK'
  | 'RELAY_RESPONSE_TAMPERING'
  | 'LLM_KEY_TO_UNKNOWN_HOST'
  | 'WORKSPACE_BULK_EGRESS';

export interface RuntimePrivacyRuleEvaluation {
  ruleId: RuntimePrivacyRuleId;
  coverageLevel: CoverageLevel;
  missingFacts: MissingLlmFact[];
  detected: boolean;
  decision?: CloudPolicyDecision;
}

/**
 * Facts visible at a host lifecycle boundary. Secret values and reversible
 * credential digests are intentionally not representable by this contract.
 * `payloadBytes`, when present, is the UTF-8 byte size of the serialized body.
 */
export interface LlmEgressRequestMetadata {
  schemaVersion: 1;
  requestId: string;
  parentRequestId?: string;
  sessionId: string;
  purpose: LlmRequestPurpose;
  lifecycleStage: RuntimeLifecycleStage;
  canBlockCurrentAction: boolean;
  provider?: string;
  model?: string;
  apiMode?: string;
  attempt?: number;
  isRetry?: boolean;
  isFallback?: boolean;
  destination?: {
    scheme?: string;
    host?: string;
    port?: number;
    path?: string;
    service?: string;
    region?: string;
    tier?: LlmEndpointTier;
  };
  credentialKind: CredentialKind;
  credentialPresent: boolean | 'unknown';
  payloadBytes?: number;
  attachmentBytes?: number;
  messageCount?: number;
  filePathCount?: number;
}

export type PiiCategory =
  | 'national_id'
  | 'bank_account'
  | 'biometric'
  | 'minor_data'
  | 'health_record'
  | 'location_trace'
  | 'contact_dump'
  | 'phone_number'
  | 'email_address'
  | 'hardcoded_dataset';

export type RuntimeActionType =
  | 'shell'
  | 'file_read'
  | 'file_write'
  | 'network'
  | 'web_search'
  | 'mcp_tool'
  | 'browser'
  | 'skill_install'
  | 'deploy'
  | 'llm_request'
  | 'llm_response'
  | 'other';

export type RuntimeAgentHost =
  | 'claude-code'
  | 'codex'
  | 'openclaw'
  | 'hermes'
  | 'dsh'
  | 'qclaw'
  | 'cursor'
  | 'gemini'
  | 'copilot'
  | 'other';

export interface PolicyReason {
  code: string;
  severity: RuntimeSeverity;
  title: string;
  description: string;
  evidence?: string;
  remediation?: string;
}

export interface EffectiveRuntimePolicy {
  policyVersion: string;
  mode: 'observe' | 'balanced' | 'strict';
  decisions: {
    destructiveCommand: CloudPolicyDecision;
    remoteCodeExecution: CloudPolicyDecision;
    dataExfiltration: CloudPolicyDecision;
    secretAccess: CloudPolicyDecision;
    deployAction: CloudPolicyDecision;
  };
  protectedPaths: string[];
  filesystemAllowlist?: string[];
  blockedCommandPatterns: string[];
  allowedCommandPatterns: string[];
  approvalActionTypes: RuntimeActionType[];
  network: {
    defaultOutbound: CloudPolicyDecision;
    blockedDomains: string[];
    approvalDomains: string[];
    behaviorAnomaly?: CloudPolicyDecision;
    responseAnomaly?: CloudPolicyDecision;
    untrustedLlmEndpoint: CloudPolicyDecision;
    trustedLlmEndpoints: string[];
  };
  privacy: {
    piiEgressTrusted: CloudPolicyDecision;
    piiEgressUntrusted: CloudPolicyDecision;
    enabledCategories: PiiCategory[];
    bulkEgressBytes: number;
    bulkAttachmentBytes: number;
    bulkFilePathCount: number;
  };
  updatedAt: string;
}

export interface RuntimeAction {
  sessionId: string;
  agentHost: RuntimeAgentHost;
  actionType: RuntimeActionType;
  toolName: string;
  input: string;
  cwd?: string;
  sourceSkill?: string;
  lifecycleStage?: RuntimeLifecycleStage;
  canBlockCurrentAction?: boolean;
  coverageLevel?: CoverageLevel;
  enforcementStatus?: EnforcementStatus;
  missingFacts?: MissingLlmFact[];
  llm?: LlmEgressRequestMetadata;
  metadata?: Record<string, unknown>;
}

export interface RuntimeDecision {
  actionId: string;
  decision: CloudPolicyDecision;
  policyDecision?: CloudPolicyDecision;
  riskScore: number;
  riskLevel: RuntimeRiskLevel;
  reasons: PolicyReason[];
  policyVersion: string;
  expiresAt?: string;
  coverageLevel?: CoverageLevel;
  missingFacts?: MissingLlmFact[];
  ruleEvaluations?: RuntimePrivacyRuleEvaluation[];
}

export interface RuntimeAuditEvent extends RuntimeAction {
  actionId: string;
  decision: CloudPolicyDecision;
  policyDecision?: CloudPolicyDecision;
  riskScore: number;
  riskLevel: RuntimeRiskLevel;
  reasons: PolicyReason[];
  policyVersion: string;
}
