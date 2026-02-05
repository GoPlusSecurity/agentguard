import type { HookAdapter, HookInput, HookOutput, EngineOptions } from './types.js';
import {
  isSensitivePath,
  shouldDenyAtLevel,
  shouldAskAtLevel,
  writeAuditLog,
  getSkillTrustPolicy,
  isActionAllowedByCapabilities,
} from './common.js';

/**
 * Evaluate a hook event using the common AgentGuard decision engine.
 *
 * This is the platform-agnostic core — adapters handle I/O protocol,
 * this function handles security logic.
 */
export async function evaluateHook(
  adapter: HookAdapter,
  rawInput: unknown,
  options: EngineOptions
): Promise<HookOutput> {
  const input = adapter.parseInput(rawInput);

  // Post-tool events → audit only
  if (input.eventType === 'post') {
    const skill = await adapter.inferInitiatingSkill(input);
    writeAuditLog(input, null, skill);
    return { decision: 'allow' };
  }

  // Build envelope
  const initiatingSkill = await adapter.inferInitiatingSkill(input);
  const envelope = adapter.buildEnvelope(input, initiatingSkill);

  if (!envelope) {
    return { decision: 'allow' };
  }

  // Fast check: sensitive file paths (Write/Edit)
  const actionType = adapter.mapToolToActionType(input.toolName);
  if (actionType === 'write_file') {
    const filePath = (input.toolInput.file_path as string) ||
                     (input.toolInput.path as string) || '';
    if (isSensitivePath(filePath)) {
      const skillTag = initiatingSkill ? ` (via skill: ${initiatingSkill})` : '';
      const reason = `GoPlus AgentGuard: blocked write to sensitive path "${filePath}"${skillTag}`;
      writeAuditLog(input, { decision: 'deny', risk_level: 'critical', risk_tags: ['SENSITIVE_PATH'] }, initiatingSkill);

      // In permissive mode, ask for user-initiated writes
      if (options.config.level === 'permissive' && !initiatingSkill) {
        return { decision: 'ask', reason, riskLevel: 'critical', riskTags: ['SENSITIVE_PATH'], initiatingSkill };
      }
      return { decision: 'deny', reason, riskLevel: 'critical', riskTags: ['SENSITIVE_PATH'], initiatingSkill };
    }
  }

  // Full ActionScanner evaluation
  try {
    const decision = await options.agentguard.actionScanner.decide(envelope);

    // Skill trust policy enforcement
    if (initiatingSkill) {
      const policy = await getSkillTrustPolicy(initiatingSkill, options.agentguard.registry);

      if (!policy.isKnown || policy.trustLevel === 'untrusted') {
        if (!isActionAllowedByCapabilities(
          envelope.action.type,
          { can_exec: false, can_network: false, can_write: false, can_read: true, can_web3: false }
        )) {
          const reason = `GoPlus AgentGuard: untrusted skill "${initiatingSkill}" attempted ${envelope.action.type} — register it with /agentguard trust attest to allow`;
          writeAuditLog(input, { decision: 'deny', risk_level: 'high', risk_tags: ['UNTRUSTED_SKILL', ...(decision.risk_tags || [])] }, initiatingSkill);
          return { decision: 'ask', reason, riskLevel: 'high', riskTags: ['UNTRUSTED_SKILL'], initiatingSkill };
        }
      }

      if (policy.isKnown && policy.capabilities) {
        if (!isActionAllowedByCapabilities(envelope.action.type, policy.capabilities)) {
          const reason = `GoPlus AgentGuard: skill "${initiatingSkill}" is not allowed to ${envelope.action.type} per its trust policy`;
          writeAuditLog(input, { decision: 'deny', risk_level: 'high', risk_tags: ['CAPABILITY_EXCEEDED', ...(decision.risk_tags || [])] }, initiatingSkill);
          return { decision: 'deny', reason, riskLevel: 'high', riskTags: ['CAPABILITY_EXCEEDED'], initiatingSkill };
        }
      }
    }

    // Write audit log
    writeAuditLog(input, decision, initiatingSkill);

    // Apply protection level thresholds
    const skillTag = initiatingSkill ? ` (via skill: ${initiatingSkill})` : '';
    const tags = (decision.risk_tags || []).join(', ');

    if (shouldDenyAtLevel(decision, options.config)) {
      return {
        decision: 'deny',
        reason: `GoPlus AgentGuard: ${decision.explanation || 'Action blocked'}${skillTag} [${tags}]`,
        riskLevel: decision.risk_level,
        riskTags: decision.risk_tags,
        initiatingSkill,
      };
    }

    if (shouldAskAtLevel(decision, options.config)) {
      return {
        decision: 'ask',
        reason: `GoPlus AgentGuard: ${decision.explanation || 'Action requires confirmation'}${skillTag} [${tags}]`,
        riskLevel: decision.risk_level,
        riskTags: decision.risk_tags,
        initiatingSkill,
      };
    }

    return { decision: 'allow', initiatingSkill };
  } catch {
    // Engine error → fail open
    writeAuditLog(input, { decision: 'error', risk_level: 'low', risk_tags: ['ENGINE_ERROR'] }, initiatingSkill);
    return { decision: 'allow' };
  }
}
