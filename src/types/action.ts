import type { SkillIdentity, CapabilityModel } from './skill.js';
import type { RiskLevel } from './scanner.js';

/**
 * Action types that can be scanned
 */
export type ActionType =
  | 'network_request'
  | 'exec_command'
  | 'read_file'
  | 'write_file'
  | 'secret_access'
  | 'web3_tx'
  | 'web3_sign';

/**
 * Policy decision
 */
export type Decision = 'allow' | 'deny' | 'confirm';

/**
 * Evidence for action decisions
 */
export interface ActionEvidence {
  /** Evidence type */
  type: string;
  /** Field that triggered */
  field?: string;
  /** Matched pattern */
  match?: string;
  /** Description */
  description: string;
}

/**
 * Policy decision result
 */
export interface PolicyDecision {
  /** Decision: allow, deny, or confirm */
  decision: Decision;
  /** Risk level */
  risk_level: RiskLevel;
  /** Risk tags that contributed to decision */
  risk_tags: string[];
  /** Evidence supporting the decision */
  evidence: ActionEvidence[];
  /** Effective capabilities (if modified) */
  effective_capabilities?: Partial<CapabilityModel>;
  /** Human-readable explanation */
  explanation?: string;
}

/**
 * Network request action data
 */
export interface NetworkRequestData {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers?: Record<string, string>;
  body_preview?: string;
}

/**
 * Command execution action data
 */
export interface ExecCommandData {
  command: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
}

/**
 * File operation action data
 */
export interface FileOperationData {
  path: string;
  content_preview?: string;
}

/**
 * Secret access action data
 */
export interface SecretAccessData {
  secret_name: string;
  access_type: 'read' | 'write';
}

/**
 * Web3 transaction action data
 */
export interface Web3TxData {
  chain_id: number;
  from: string;
  to: string;
  value: string;
  data?: string;
  gas_limit?: string;
  origin?: string;
}

/**
 * Web3 signature action data
 */
export interface Web3SignData {
  chain_id: number;
  signer: string;
  message?: string;
  typed_data?: unknown;
  origin?: string;
}

/**
 * Union type for all action data
 */
export type ActionData =
  | NetworkRequestData
  | ExecCommandData
  | FileOperationData
  | SecretAccessData
  | Web3TxData
  | Web3SignData;

/**
 * Action context
 */
export interface ActionContext {
  /** Session identifier */
  session_id: string;
  /** Whether user is present/active */
  user_present: boolean;
  /** Environment */
  env: 'prod' | 'dev' | 'test';
  /** Action timestamp */
  time: string;
  /** Skill that initiated this action (inferred from transcript) */
  initiating_skill?: string;
}

/**
 * Action envelope - the complete action request
 */
export interface ActionEnvelope {
  /** Actor information */
  actor: {
    skill: SkillIdentity;
    record_key?: string;
  };
  /** Action details */
  action: {
    type: ActionType;
    data: ActionData;
  };
  /** Action context */
  context: ActionContext;
}

/**
 * Web3 intent for simulation
 */
export interface Web3Intent {
  chain_id: number;
  from: string;
  to: string;
  value: string;
  data?: string;
  origin?: string;
  kind: 'tx' | 'sign';
}

/**
 * Asset change from simulation
 */
export interface AssetChange {
  asset_type: 'native' | 'erc20' | 'erc721' | 'erc1155';
  token_address?: string;
  token_id?: string;
  amount: string;
  direction: 'in' | 'out';
}

/**
 * Approval change from simulation
 */
export interface ApprovalChange {
  token_address: string;
  spender: string;
  amount: string;
  is_unlimited: boolean;
}

/**
 * Web3 simulation result
 */
export interface Web3SimulationResult {
  /** Decision */
  decision: Decision;
  /** Risk level */
  risk_level: RiskLevel;
  /** Risk tags */
  risk_tags: string[];
  /** Human-readable explanation */
  explanation: string;
  /** GoPlus raw response */
  goplus?: {
    simulation?: {
      success: boolean;
      balance_changes: AssetChange[];
      approval_changes: ApprovalChange[];
    };
    address_risk?: {
      is_malicious: boolean;
      is_phishing: boolean;
      risk_type?: string[];
    };
    token_risk?: {
      is_honeypot: boolean;
      has_hidden_tax: boolean;
      buy_tax?: string;
      sell_tax?: string;
    };
  };
  /** Guardrail recommendations */
  guardrail?: {
    require_user_confirmation: boolean;
    suggested_change?: string;
    capabilities_patch?: Partial<CapabilityModel>;
  };
}
