export type CloudPolicyDecision = 'allow' | 'warn' | 'require_approval' | 'block';
export type RuntimeRiskLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type RuntimeSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

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
  | 'other';

export type RuntimeAgentHost =
  | 'claude-code'
  | 'codex'
  | 'openclaw'
  | 'hermes'
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
  metadata?: Record<string, unknown>;
}

export interface RuntimeDecision {
  actionId: string;
  decision: CloudPolicyDecision;
  riskScore: number;
  riskLevel: RuntimeRiskLevel;
  reasons: PolicyReason[];
  policyVersion: string;
  expiresAt?: string;
}

export interface RuntimeAuditEvent extends RuntimeAction {
  actionId: string;
  decision: CloudPolicyDecision;
  riskScore: number;
  riskLevel: RuntimeRiskLevel;
  reasons: PolicyReason[];
  policyVersion: string;
}
