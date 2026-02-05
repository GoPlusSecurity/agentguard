import type { ActionEnvelope, PolicyDecision } from '../types/action.js';

/**
 * Standardized hook input — platform-agnostic representation
 */
export interface HookInput {
  /** Tool name (platform-specific, e.g. "Bash" or "exec") */
  toolName: string;
  /** Tool parameters */
  toolInput: Record<string, unknown>;
  /** Hook event type */
  eventType: 'pre' | 'post';
  /** Session identifier */
  sessionId?: string;
  /** Working directory */
  cwd?: string;
  /** Raw platform-specific input */
  raw: unknown;
}

/**
 * Hook evaluation result
 */
export interface HookOutput {
  /** Decision */
  decision: 'allow' | 'deny' | 'ask';
  /** Human-readable reason */
  reason?: string;
  /** Risk level */
  riskLevel?: string;
  /** Risk tags */
  riskTags?: string[];
  /** Initiating skill (if detected) */
  initiatingSkill?: string | null;
}

/**
 * Platform adapter interface
 *
 * Each platform (Claude Code, OpenClaw, etc.) implements this interface
 * to bridge its hook protocol to the common AgentGuard decision engine.
 */
export interface HookAdapter {
  /** Platform identifier */
  readonly name: string;

  /** Parse raw platform input into standardized HookInput */
  parseInput(raw: unknown): HookInput;

  /** Map platform tool name to ActionEnvelope action type */
  mapToolToActionType(toolName: string): string | null;

  /** Build an ActionEnvelope from standardized input */
  buildEnvelope(input: HookInput, initiatingSkill?: string | null): ActionEnvelope | null;

  /** Infer which skill initiated the current tool call */
  inferInitiatingSkill(input: HookInput): Promise<string | null>;
}

/**
 * Agentguard instance interface (subset used by engine)
 */
export interface AgentGuardInstance {
  actionScanner: {
    decide(envelope: ActionEnvelope): Promise<PolicyDecision>;
  };
  registry: {
    lookup(skill: { id: string; source: string; version_ref: string; artifact_hash: string }): Promise<{
      effective_trust_level: string;
      effective_capabilities: Record<string, unknown>;
      record: unknown | null;
    }>;
  };
}

/**
 * Engine options
 */
export interface EngineOptions {
  config: { level?: string };
  agentguard: AgentGuardInstance;
}
