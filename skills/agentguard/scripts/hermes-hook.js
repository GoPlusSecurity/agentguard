#!/usr/bin/env node

/**
 * GoPlus AgentGuard Hermes shell hook.
 *
 * Hermes shell hooks read JSON from stdin and use stdout JSON to influence
 * behavior. For pre_tool_call, returning a block decision vetoes tool
 * execution. There is no native "ask" decision in Hermes' pre_tool_call
 * contract, so AgentGuard's confirmation decision is represented as a block
 * with a confirmation-oriented message.
 */

import { join } from 'node:path';

function isPostHook(input) {
  const event = typeof input?.hook_event_name === 'string' ? input.hook_event_name : '';
  return event.startsWith('post');
}

function isPreHook(input) {
  return !isPostHook(input);
}

function toolNameFrom(input) {
  return typeof input?.tool_name === 'string' ? input.tool_name : '';
}

function toolInputFrom(input) {
  const toolInput = input?.tool_input ?? input?.args;
  return toolInput && typeof toolInput === 'object' && !Array.isArray(toolInput)
    ? toolInput
    : {};
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function validatePreToolPayload(input) {
  const toolName = toolNameFrom(input);
  const toolInput = toolInputFrom(input);

  switch (toolName) {
    case 'terminal':
      if (!firstString(toolInput.command)) return 'Hermes terminal hook payload is missing command';
      return null;
    case 'execute_code':
      if (!firstString(toolInput.code, toolInput.command)) return 'Hermes execute_code hook payload is missing code';
      return null;
    case 'write_file':
    case 'patch':
    case 'read_file':
      if (!firstString(toolInput.path, toolInput.file_path)) return `Hermes ${toolName} hook payload is missing path`;
      return null;
    case 'skill_manage':
      if (!firstString(toolInput.path, toolInput.file_path, toolInput.target, toolInput.skill_path)) {
        return 'Hermes skill_manage hook payload is missing target path';
      }
      return null;
    case 'web_extract':
    case 'browser_navigate':
    case 'browser_open':
    case 'web_open':
    case 'open_url':
    case 'visit_url':
    case 'open':
      if (!firstString(toolInput.url, toolInput.href, toolInput.target)) return `Hermes ${toolName} hook payload is missing URL`;
      return null;
    case 'web_search':
      if (!firstString(toolInput.query, toolInput.url)) return 'Hermes web_search hook payload is missing query';
      return null;
    default:
      return `Hermes tool "${toolName || '(missing)'}" is not recognized by AgentGuard`;
  }
}

function shouldFailClosed(input) {
  return !input || isPreHook(input);
}

// ---------------------------------------------------------------------------
// Load AgentGuard engine + Hermes adapter
// ---------------------------------------------------------------------------

const agentguardPath = join(import.meta.url.replace('file://', ''), '..', '..', '..', '..', 'dist', 'index.js');

let loadRuntimeConfig, loadHookConfig, protectAction, createAgentGuard, HermesAdapter, evaluateHook;

async function loadEngine() {
  if (process.env.AGENTGUARD_TEST_FORCE_ENGINE_LOAD_FAILURE === '1') {
    return null;
  }

  try {
    const gs = await import(agentguardPath);
    return {
      loadRuntimeConfig: gs.loadAgentGuardConfig || gs.ensureConfig,
      loadHookConfig: gs.loadConfig,
      protectAction: gs.protectAction,
      createAgentGuard: gs.createAgentGuard || gs.default,
      HermesAdapter: gs.HermesAdapter,
      evaluateHook: gs.evaluateHook,
    };
  } catch {
    try {
      const gs = await import('@goplus/agentguard');
      return {
        loadRuntimeConfig: gs.loadAgentGuardConfig || gs.ensureConfig,
        loadHookConfig: gs.loadConfig,
        protectAction: gs.protectAction,
        createAgentGuard: gs.createAgentGuard || gs.default,
        HermesAdapter: gs.HermesAdapter,
        evaluateHook: gs.evaluateHook,
      };
    } catch {
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// Read stdin
// ---------------------------------------------------------------------------

function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), 5000);

    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => {
      try {
        finish(JSON.parse(data));
      } catch {
        finish(null);
      }
    });
    process.stdin.on('error', () => finish(null));
  });
}

// ---------------------------------------------------------------------------
// Hermes output helpers
// ---------------------------------------------------------------------------

function outputBlock(reason) {
  console.log(JSON.stringify({
    action: 'block',
    decision: 'block',
    block: true,
    message: reason || 'GoPlus AgentGuard blocked this action',
    reason: reason || 'GoPlus AgentGuard blocked this action',
  }));
  process.exit(0);
}

function outputAllow() {
  console.log('{}');
  process.exit(0);
}

function runtimeActionTypeFrom(toolName) {
  switch (toolName) {
    case 'terminal':
    case 'execute_code':
      return 'shell';
    case 'write_file':
    case 'patch':
    case 'skill_manage':
      return 'file_write';
    case 'read_file':
      return 'file_read';
    case 'web_search':
      return 'web_search';
    case 'web_extract':
    case 'browser_navigate':
    case 'browser_open':
    case 'web_open':
    case 'open_url':
    case 'visit_url':
    case 'open':
      return 'network';
    default:
      return 'other';
  }
}

function runtimeToolNameFrom(toolName) {
  return toolName || 'HermesTool';
}

function debugLog(message, details) {
  if (process.env.AGENTGUARD_HERMES_DEBUG !== '1') return;
  const suffix = details === undefined ? '' : ` ${JSON.stringify(details)}`;
  console.error(`[AgentGuard Hermes] ${message}${suffix}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const input = await readStdin();
  if (!input) {
    outputBlock('GoPlus AgentGuard: invalid or missing Hermes hook payload');
  }

  const validationError = isPreHook(input) ? validatePreToolPayload(input) : null;
  if (validationError) {
    outputBlock(`GoPlus AgentGuard: ${validationError}`);
  }

  const engine = await loadEngine();
  if (!engine) {
    if (shouldFailClosed(input)) {
      outputBlock('GoPlus AgentGuard: unable to load Hermes hook engine; blocking fail-closed');
    }
    outputAllow();
  }

  ({ loadRuntimeConfig, loadHookConfig, protectAction, createAgentGuard, HermesAdapter, evaluateHook } = engine);

  if (isPostHook(input)) {
    try {
      if (protectAction) {
        const config = loadRuntimeConfig();
        await protectAction({
          config,
          rawInput: input,
          agentHost: 'hermes',
          actionType: runtimeActionTypeFrom(toolNameFrom(input)),
          toolName: runtimeToolNameFrom(toolNameFrom(input)),
          sessionId: typeof input.session_id === 'string' ? input.session_id : undefined,
          phase: 'post',
        });
      } else if (createAgentGuard && HermesAdapter && evaluateHook) {
        const adapter = new HermesAdapter();
        const config = loadHookConfig ? loadHookConfig() : { level: loadRuntimeConfig().level };
        const agentguard = createAgentGuard();
        await evaluateHook(adapter, input, { config, agentguard });
      }
    } catch {
      // Post hooks are audit-only; never affect Hermes execution.
    }
    outputAllow();
  }

  const config = loadRuntimeConfig();
  const result = await protectAction({
    config,
    rawInput: input,
    agentHost: 'hermes',
    actionType: runtimeActionTypeFrom(toolNameFrom(input)),
    toolName: runtimeToolNameFrom(toolNameFrom(input)),
    sessionId: typeof input.session_id === 'string' ? input.session_id : undefined,
  });

  if (!result) {
    debugLog('allow: no runtime action was built');
    outputAllow();
  }

  debugLog('decision', {
    decision: result.decision.decision,
    riskLevel: result.decision.riskLevel,
    riskScore: result.decision.riskScore,
    policySource: result.policySource,
  });

  if (result.decision.decision === 'block') {
    outputBlock(formatDecisionReason(result, 'blocked this Hermes tool call'));
  } else if (result.decision.decision === 'require_approval') {
    outputBlock(formatDecisionReason(result, 'requires confirmation for this Hermes tool call'));
  } else {
    outputAllow();
  }
}

function formatDecisionReason(result, fallback) {
  const titles = result.decision.reasons
    .map((item) => item.title)
    .filter(Boolean)
    .slice(0, 3)
    .join(', ');
  const suffix = titles ? ` Reasons: ${titles}.` : '';
  return `GoPlus AgentGuard ${fallback} (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}).${suffix}`;
}

main();
