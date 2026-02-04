#!/usr/bin/env node

/**
 * GoPlus AgentGuard PreToolUse / PostToolUse Hook
 *
 * Reads Claude Code hook input from stdin, evaluates safety via ActionScanner,
 * and returns allow / deny / ask decisions.
 *
 * PreToolUse exit codes:
 *   0  = allow (or JSON with permissionDecision)
 *   2  = deny  (stderr = reason shown to Claude)
 *
 * PostToolUse: appends audit log entry to ~/.agentguard/audit.jsonl (async, always exits 0)
 */

import { createRequire } from 'node:module';
import { readFileSync, appendFileSync, mkdirSync, existsSync, openSync, readSync, closeSync, fstatSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

// Resolve agentguard from the parent package
const require = createRequire(import.meta.url);
const agentguardPath = join(import.meta.url.replace('file://', ''), '..', '..', '..', '..', 'dist', 'index.js');

let createAgentGuard;
try {
  const gs = await import(agentguardPath);
  createAgentGuard = gs.createAgentGuard || gs.default;
} catch {
  // Fallback: try to require from node_modules
  try {
    const gs = await import('@goplus/agentguard');
    createAgentGuard = gs.createAgentGuard || gs.default;
  } catch {
    // Cannot load agentguard — allow everything and warn
    process.stderr.write('GoPlus AgentGuard: unable to load engine, allowing action\n');
    process.exit(0);
  }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const AGENTGUARD_DIR = join(homedir(), '.agentguard');
const CONFIG_PATH = join(AGENTGUARD_DIR, 'config.json');
const AUDIT_PATH = join(AGENTGUARD_DIR, 'audit.jsonl');

function ensureDir() {
  if (!existsSync(AGENTGUARD_DIR)) {
    mkdirSync(AGENTGUARD_DIR, { recursive: true });
  }
}

function loadConfig() {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
  } catch {
    return { level: 'balanced' };
  }
}

// ---------------------------------------------------------------------------
// Read stdin
// ---------------------------------------------------------------------------

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve(null);
      }
    });
    // Timeout after 5s to avoid hanging
    setTimeout(() => resolve(null), 5000);
  });
}

// ---------------------------------------------------------------------------
// Infer initiating skill from transcript
// ---------------------------------------------------------------------------

/**
 * Read the last ~4KB of the transcript file and look for the most recent
 * Skill tool invocation to determine which skill (if any) is driving the
 * current tool call.
 *
 * Returns the skill name (e.g. "agentguard") or null if the call appears
 * to come directly from the user / main agent.
 */
function inferInitiatingSkill(transcriptPath) {
  if (!transcriptPath) return null;
  try {
    const fd = openSync(transcriptPath, 'r');
    const stat = fstatSync(fd);
    const TAIL_SIZE = 4096;
    const start = Math.max(0, stat.size - TAIL_SIZE);
    const buf = Buffer.alloc(Math.min(TAIL_SIZE, stat.size));
    readSync(fd, buf, 0, buf.length, start);
    closeSync(fd);

    const tail = buf.toString('utf-8');
    const lines = tail.split('\n').filter(Boolean);

    // Walk backwards — find the most recent Skill tool_use
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const entry = JSON.parse(lines[i]);
        // Claude Code transcript entries with tool_use type
        if (
          entry.type === 'tool_use' &&
          entry.name === 'Skill' &&
          entry.input?.skill
        ) {
          return entry.input.skill;
        }
        // Also check content array format (assistant messages)
        if (entry.role === 'assistant' && Array.isArray(entry.content)) {
          for (const block of entry.content) {
            if (
              block.type === 'tool_use' &&
              block.name === 'Skill' &&
              block.input?.skill
            ) {
              return block.input.skill;
            }
          }
        }
      } catch {
        // Not valid JSON — skip
      }
    }
  } catch {
    // Can't read transcript — not critical
  }
  return null;
}

// ---------------------------------------------------------------------------
// Skill trust policy
// ---------------------------------------------------------------------------

/**
 * Look up a skill in the trust registry and return its effective trust level
 * and capabilities. For unknown/untrusted skills, enforce strict mode.
 */
async function getSkillTrustPolicy(skillId, agentguardInstance) {
  if (!skillId || !agentguardInstance) {
    return { trustLevel: null, capabilities: null, isKnown: false };
  }
  try {
    const result = await agentguardInstance.registry.lookup({
      id: skillId,
      source: skillId,
      version_ref: '0.0.0',
      artifact_hash: '',
    });
    return {
      trustLevel: result.effective_trust_level,
      capabilities: result.effective_capabilities,
      isKnown: result.record !== null,
    };
  } catch {
    return { trustLevel: null, capabilities: null, isKnown: false };
  }
}

/**
 * Check if a skill's capabilities allow the given action type.
 */
function isActionAllowedByCapabilities(actionType, capabilities) {
  if (!capabilities) return true; // No caps info → don't restrict
  switch (actionType) {
    case 'exec_command':
      return capabilities.can_exec !== false;
    case 'network_request':
      return capabilities.can_network !== false;
    case 'write_file':
      return capabilities.can_write !== false;
    case 'read_file':
      return capabilities.can_read !== false;
    case 'web3_tx':
    case 'web3_sign':
      return capabilities.can_web3 !== false;
    default:
      return true;
  }
}

// ---------------------------------------------------------------------------
// Map Claude Code tool calls to ActionScanner envelopes
// ---------------------------------------------------------------------------

function buildEnvelope(input) {
  const toolName = input.tool_name || '';
  const toolInput = input.tool_input || {};

  // Infer which skill (if any) initiated this tool call
  const initiatingSkill = inferInitiatingSkill(input.transcript_path);

  const actor = {
    skill: {
      id: initiatingSkill || 'claude-code-session',
      source: initiatingSkill || 'claude-code',
      version_ref: '0.0.0',
      artifact_hash: '',
    },
  };

  const context = {
    session_id: input.session_id || `hook-${Date.now()}`,
    user_present: true, // Claude Code = interactive session
    env: 'prod',
    time: new Date().toISOString(),
    initiating_skill: initiatingSkill || undefined,
  };

  // Bash → exec_command
  if (toolName === 'Bash') {
    return {
      actor,
      action: {
        type: 'exec_command',
        data: {
          command: toolInput.command || '',
          args: [],
          cwd: input.cwd,
        },
      },
      context,
    };
  }

  // Write / Edit → write_file
  if (toolName === 'Write' || toolName === 'Edit') {
    const filePath = toolInput.file_path || '';
    return {
      actor,
      action: {
        type: 'write_file',
        data: { path: filePath },
      },
      context,
    };
  }

  // WebFetch / WebSearch → network_request
  if (toolName === 'WebFetch' || toolName === 'WebSearch') {
    const url = toolInput.url || toolInput.query || '';
    return {
      actor,
      action: {
        type: 'network_request',
        data: {
          method: 'GET',
          url,
        },
      },
      context,
    };
  }

  // MCP tools that look like network requests
  if (toolName.startsWith('mcp__') && toolInput.url) {
    return {
      actor,
      action: {
        type: 'network_request',
        data: {
          method: toolInput.method || 'GET',
          url: toolInput.url,
          body_preview: toolInput.body,
        },
      },
      context,
    };
  }

  return null; // Not a tool we care about
}

// ---------------------------------------------------------------------------
// Sensitive path detection (fast check before full ActionScanner)
// ---------------------------------------------------------------------------

const SENSITIVE_PATHS = [
  '.env', '.env.local', '.env.production',
  '.ssh/', 'id_rsa', 'id_ed25519',
  '.aws/credentials', '.aws/config',
  '.npmrc', '.netrc',
  'credentials.json', 'serviceAccountKey.json',
  '.kube/config',
];

function isSensitivePath(filePath) {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/');
  return SENSITIVE_PATHS.some(
    (p) => normalized.includes(`/${p}`) || normalized.endsWith(p)
  );
}

// ---------------------------------------------------------------------------
// Protection level thresholds
// ---------------------------------------------------------------------------

function shouldDenyAtLevel(decision, config) {
  const level = config.level || 'balanced';

  // In strict mode, deny anything that's not explicitly allowed
  if (level === 'strict') {
    return decision.decision === 'deny' || decision.decision === 'confirm';
  }

  // In balanced mode (default), deny 'deny' decisions, ask for 'confirm'
  if (level === 'balanced') {
    return decision.decision === 'deny';
  }

  // In permissive mode, only deny critical
  if (level === 'permissive') {
    return decision.decision === 'deny' && decision.risk_level === 'critical';
  }

  return decision.decision === 'deny';
}

function shouldAskAtLevel(decision, config) {
  const level = config.level || 'balanced';

  if (level === 'strict') {
    // In strict mode, we already deny confirm decisions above
    return false;
  }

  if (level === 'balanced') {
    return decision.decision === 'confirm';
  }

  if (level === 'permissive') {
    // In permissive, ask only for high/critical that aren't already denied
    return (
      decision.decision === 'deny' && decision.risk_level !== 'critical'
    ) || (
      decision.decision === 'confirm' &&
      (decision.risk_level === 'high' || decision.risk_level === 'critical')
    );
  }

  return decision.decision === 'confirm';
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

function writeAuditLog(input, decision, initiatingSkill) {
  try {
    ensureDir();
    const entry = {
      timestamp: new Date().toISOString(),
      tool_name: input.tool_name,
      tool_input_summary: summarizeToolInput(input),
      decision: decision?.decision || 'allow',
      risk_level: decision?.risk_level || 'low',
      risk_tags: decision?.risk_tags || [],
    };
    if (initiatingSkill) {
      entry.initiating_skill = initiatingSkill;
    }
    appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n');
  } catch {
    // Non-critical — don't block on audit log failure
  }
}

function summarizeToolInput(input) {
  const toolInput = input.tool_input || {};
  if (input.tool_name === 'Bash') return toolInput.command?.slice(0, 200) || '';
  if (input.tool_name === 'Write' || input.tool_name === 'Edit') return toolInput.file_path || '';
  if (input.tool_name === 'WebFetch') return toolInput.url || '';
  if (input.tool_name === 'WebSearch') return toolInput.query || '';
  return JSON.stringify(toolInput).slice(0, 200);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const input = await readStdin();
  if (!input) {
    process.exit(0); // Can't parse → allow
  }

  const hookEvent = input.hook_event_name || '';

  // ------- PostToolUse: audit log only -------
  if (hookEvent === 'PostToolUse' || hookEvent === 'PostToolUseFailure') {
    const skillName = inferInitiatingSkill(input.transcript_path);
    writeAuditLog(input, null, skillName);
    process.exit(0);
  }

  // ------- PreToolUse: evaluate safety -------
  const config = loadConfig();
  const envelope = buildEnvelope(input);

  if (!envelope) {
    // Not a tool we guard — allow
    process.exit(0);
  }

  // Extract the initiating skill from the envelope we just built
  const initiatingSkill = envelope.context.initiating_skill || null;

  // Quick check for sensitive file paths (Write/Edit)
  if (
    (input.tool_name === 'Write' || input.tool_name === 'Edit') &&
    isSensitivePath(input.tool_input?.file_path)
  ) {
    const skillTag = initiatingSkill ? ` (via skill: ${initiatingSkill})` : '';
    const reason = `GoPlus AgentGuard: blocked write to sensitive path "${input.tool_input.file_path}"${skillTag}`;
    writeAuditLog(input, { decision: 'deny', risk_level: 'critical', risk_tags: ['SENSITIVE_PATH'] }, initiatingSkill);

    if (config.level === 'permissive' && !initiatingSkill) {
      // In permissive mode, ask instead of deny — but only for direct user actions.
      // Skill-initiated writes to sensitive paths are always denied.
      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason: reason,
        },
      }));
      process.exit(0);
    }

    process.stderr.write(reason + '\n');
    process.exit(2);
  }

  // Full ActionScanner evaluation
  try {
    const agentguard = createAgentGuard();
    const { actionScanner } = agentguard;
    const decision = await actionScanner.decide(envelope);

    // If a skill initiated this action, apply skill trust policy
    if (initiatingSkill) {
      const policy = await getSkillTrustPolicy(initiatingSkill, agentguard);

      // Unknown/untrusted skill: escalate protection
      if (!policy.isKnown || policy.trustLevel === 'untrusted') {
        // Check if this action type exceeds default (none) capabilities
        if (!isActionAllowedByCapabilities(envelope.action.type, { can_exec: false, can_network: false, can_write: false, can_read: true, can_web3: false })) {
          const reason = `GoPlus AgentGuard: untrusted skill "${initiatingSkill}" attempted ${envelope.action.type} — register it with /agentguard trust attest to allow`;
          writeAuditLog(input, { decision: 'deny', risk_level: 'high', risk_tags: ['UNTRUSTED_SKILL', ...decision.risk_tags] }, initiatingSkill);
          // Ask user instead of hard deny — let them decide
          console.log(JSON.stringify({
            hookSpecificOutput: {
              hookEventName: 'PreToolUse',
              permissionDecision: 'ask',
              permissionDecisionReason: reason,
            },
          }));
          process.exit(0);
        }
      }

      // Registered skill with restricted capabilities: enforce them
      if (policy.isKnown && policy.capabilities) {
        if (!isActionAllowedByCapabilities(envelope.action.type, policy.capabilities)) {
          const reason = `GoPlus AgentGuard: skill "${initiatingSkill}" is not allowed to ${envelope.action.type} per its trust policy`;
          writeAuditLog(input, { decision: 'deny', risk_level: 'high', risk_tags: ['CAPABILITY_EXCEEDED', ...decision.risk_tags] }, initiatingSkill);
          process.stderr.write(reason + '\n');
          process.exit(2);
        }
      }
    }

    // Write audit log
    writeAuditLog(input, decision, initiatingSkill);

    // Determine action based on protection level
    if (shouldDenyAtLevel(decision, config)) {
      const skillTag = initiatingSkill ? ` (via skill: ${initiatingSkill})` : '';
      const reason = `GoPlus AgentGuard: ${decision.explanation || 'Action blocked'}${skillTag} [${(decision.risk_tags || []).join(', ')}]`;
      process.stderr.write(reason + '\n');
      process.exit(2);
    }

    if (shouldAskAtLevel(decision, config)) {
      const skillTag = initiatingSkill ? ` (via skill: ${initiatingSkill})` : '';
      const reason = `GoPlus AgentGuard: ${decision.explanation || 'Action requires confirmation'}${skillTag} [${(decision.risk_tags || []).join(', ')}]`;
      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason: reason,
        },
      }));
      process.exit(0);
    }

    // Allow
    process.exit(0);
  } catch (err) {
    // ActionScanner error — fail open (allow) but log
    writeAuditLog(input, { decision: 'error', risk_level: 'low', risk_tags: ['ENGINE_ERROR'] }, initiatingSkill);
    process.exit(0);
  }
}

main();
