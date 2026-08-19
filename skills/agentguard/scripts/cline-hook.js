#!/usr/bin/env node

/**
 * GoPlus AgentGuard — Cline file-hook bridge.
 *
 * Cline file hooks (~/.cline/hooks/PreToolUse.js, PostToolUse.js) read a JSON
 * event on stdin and influence behavior by writing a JSON control object on
 * stdout. See https://github.com/cline/cline/tree/main/sdk/examples/hooks.
 *
 * PreToolUse payload (excerpt):
 *   {
 *     "hookName": "tool_call",
 *     "taskId": "...",
 *     "workspaceRoots": ["/repo"],
 *     "tool_call": { "id": "...", "name": "run_commands", "input": {...} }
 *   }
 *
 * Control output we emit:
 *   {}                                       -> allow
 *   {"cancel": true, "errorMessage": "..."}  -> block (AgentGuard deny)
 *   {"review": true, "context": "..."}       -> require user confirm (AgentGuard ask)
 *
 * This script delegates to the unified `protectAction` runtime API with
 * `agentHost: 'cline'`, falling back to `ClineAdapter` + `evaluateHook` when
 * the host installed an older AgentGuard build.
 */

import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function existsAtPath(p) {
  try {
    return existsSync(p);
  } catch {
    return false;
  }
}

function isPostHook(input) {
  const event = typeof input?.hookName === 'string' ? input.hookName : '';
  return event === 'tool_result' || event.startsWith('after');
}

function isPreHook(input) {
  return !isPostHook(input);
}

function toolCallFrom(input) {
  const tc = input?.tool_call ?? input?.toolCall;
  return tc && typeof tc === 'object' && !Array.isArray(tc) ? tc : {};
}

function toolNameFrom(input) {
  const tc = toolCallFrom(input);
  return typeof tc.name === 'string'
    ? tc.name
    : typeof tc.toolName === 'string'
    ? tc.toolName
    : '';
}

function toolInputFrom(input) {
  const tc = toolCallFrom(input);
  const ti = tc?.input;
  return ti && typeof ti === 'object' && !Array.isArray(ti) ? ti : {};
}

function firstString(...values) {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return '';
}

function envBool(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  return value === '1' || value.toLowerCase() === 'true';
}

const FAIL_OPEN = envBool('AGENTGUARD_CLINE_FAIL_OPEN', false);

// ---------------------------------------------------------------------------
// Tool → runtime action type mapping (mirrors src/adapters/cline.ts)
// ---------------------------------------------------------------------------

function runtimeActionTypeFrom(toolName) {
  switch (toolName) {
    case 'run_commands':
    case 'execute_command':
      return 'shell';
    case 'write_to_file':
    case 'write_file':
    case 'replace_in_file':
    case 'editor':
      return 'file_write';
    case 'read_files':
    case 'read_file':
      return 'file_read';
    case 'web_search':
      return 'web_search';
    case 'web_fetch':
    case 'browser_action':
      return 'network';
    default:
      return 'other';
  }
}

function runtimeToolNameFrom(toolName) {
  return toolName || 'ClineTool';
}

function shouldFailClosed(input) {
  if (FAIL_OPEN) return false;
  return !input || isPreHook(input);
}

function validatePreToolPayload(input) {
  const toolName = toolNameFrom(input);
  const toolInput = toolInputFrom(input);

  switch (toolName) {
    case 'run_commands':
    case 'execute_command': {
      const command =
        firstString(toolInput.command, toolInput.cmd) ||
        (Array.isArray(toolInput.commands)
          ? toolInput.commands.filter((c) => typeof c === 'string').join(' && ')
          : '');
      if (!command) return `Cline ${toolName} hook payload is missing command`;
      return null;
    }
    case 'write_to_file':
    case 'write_file':
    case 'replace_in_file':
    case 'editor':
    case 'read_files':
    case 'read_file':
      if (!firstString(toolInput.path, toolInput.file_path, toolInput.filePath, toolInput.target)) {
        // read_files can pass `files: [...]`
        if (toolName !== 'read_files' || !Array.isArray(toolInput.files)) {
          return `Cline ${toolName} hook payload is missing path`;
        }
      }
      return null;
    case 'web_fetch':
    case 'browser_action':
      if (!firstString(toolInput.url, toolInput.href, toolInput.target)) {
        return `Cline ${toolName} hook payload is missing URL`;
      }
      return null;
    case 'web_search':
      if (!firstString(toolInput.query, toolInput.q, toolInput.search)) {
        return `Cline web_search hook payload is missing query`;
      }
      return null;
    default:
      // Out-of-scope tools pass through without engine evaluation.
      return null;
  }
}

function isInScope(toolName) {
  return runtimeActionTypeFrom(toolName) !== 'other';
}

// ---------------------------------------------------------------------------
// Load AgentGuard engine + Cline adapter
// ---------------------------------------------------------------------------

// Resolve the bundled engine path safely across platforms. The script ships as
// `<pkg>/skills/agentguard/scripts/cline-hook.js`; the engine entry is at
// `<pkg>/dist/index.js`. fileURLToPath handles Windows `file:///C:/...` URLs
// correctly where a naive string replace would not.
const scriptDir = dirname(fileURLToPath(import.meta.url));
const bundledEnginePath = resolve(scriptDir, '..', '..', '..', 'dist', 'index.js');

async function loadEngine() {
  if (process.env.AGENTGUARD_TEST_FORCE_ENGINE_LOAD_FAILURE === '1') return null;

  const tryImport = async (specifier) => {
    try {
      return await import(specifier);
    } catch {
      return null;
    }
  };

  // 1) Bundled engine (in-repo or installed via `npm i -g @goplus/agentguard`
  //    where the skill folder lives next to dist/).
  // 2) Bare specifier (resolves when the host process has @goplus/agentguard
  //    in scope — e.g. invoked from a node_modules-aware cwd).
  const gs =
    (existsAtPath(bundledEnginePath) ? await tryImport(bundledEnginePath) : null) ||
    (await tryImport('@goplus/agentguard'));
  if (!gs) return null;

  return {
    loadRuntimeConfig: gs.loadAgentGuardConfig || gs.ensureConfig,
    loadHookConfig: gs.loadConfig,
    protectAction: gs.protectAction,
    createAgentGuard: gs.createAgentGuard || gs.default,
    ClineAdapter: gs.ClineAdapter,
    evaluateHook: gs.evaluateHook,
  };
}

// ---------------------------------------------------------------------------
// Stdin / stdout helpers
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

function outputBlock(reason) {
  const message = reason || 'GoPlus AgentGuard blocked this action';
  process.stdout.write(JSON.stringify({ cancel: true, errorMessage: message }) + '\n');
  process.exit(0);
}

function outputReview(reason) {
  const message = reason || 'GoPlus AgentGuard requires confirmation for this action';
  process.stdout.write(JSON.stringify({ review: true, context: message }) + '\n');
  process.exit(0);
}

function outputAllow() {
  process.stdout.write('{}\n');
  process.exit(0);
}

function debugLog(message, details) {
  if (process.env.AGENTGUARD_CLINE_DEBUG !== '1') return;
  const suffix = details === undefined ? '' : ` ${JSON.stringify(details)}`;
  process.stderr.write(`[AgentGuard Cline] ${message}${suffix}\n`);
}

function formatDecisionReason(result, fallback) {
  const titles = (result.decision.reasons || [])
    .map((item) => item.title)
    .filter(Boolean)
    .slice(0, 3)
    .join(', ');
  const suffix = titles ? ` Reasons: ${titles}.` : '';
  return `GoPlus AgentGuard ${fallback} (action: ${result.decision.actionId}, risk: ${result.decision.riskScore}/100, level: ${result.decision.riskLevel}).${suffix}`;
}

// ---------------------------------------------------------------------------
// Payload normalization — Cline uses tool_call.{name,input}; runtime expects
// the standard tool_name/tool_input shape. Normalize before protectAction.
// ---------------------------------------------------------------------------

function normalizeForRuntime(input) {
  const toolName = toolNameFrom(input);
  const toolInput = { ...toolInputFrom(input) };

  // Cline's run_commands accepts a `commands: string[]` shape. The runtime
  // engine's input-picker only looks at `command`/`cmd`, so flatten the
  // array into a single shell expression before handing it off.
  if (
    (toolName === 'run_commands' || toolName === 'execute_command') &&
    !firstString(toolInput.command, toolInput.cmd) &&
    Array.isArray(toolInput.commands)
  ) {
    const joined = toolInput.commands
      .filter((c) => typeof c === 'string' && c.length > 0)
      .join(' && ');
    if (joined) toolInput.command = joined;
  }

  return {
    ...input,
    tool_name: toolName,
    tool_input: toolInput,
    session_id: firstString(input?.taskId, input?.session_id, input?.sessionId),
    cwd:
      (Array.isArray(input?.workspaceRoots) && typeof input.workspaceRoots[0] === 'string'
        ? input.workspaceRoots[0]
        : input?.cwd) || undefined,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const input = await readStdin();
  if (!input) {
    if (FAIL_OPEN) outputAllow();
    outputBlock('GoPlus AgentGuard: invalid or missing Cline hook payload');
  }

  const toolName = toolNameFrom(input);

  // Out-of-scope tools always allow — no need to load the engine.
  if (isPreHook(input) && !isInScope(toolName)) {
    debugLog('out-of-scope tool, passthrough', { toolName });
    outputAllow();
  }

  const validationError = isPreHook(input) ? validatePreToolPayload(input) : null;
  if (validationError) {
    if (FAIL_OPEN) outputAllow();
    outputBlock(`GoPlus AgentGuard: ${validationError}`);
  }

  const engine = await loadEngine();
  if (!engine) {
    debugLog('engine load failed');
    if (shouldFailClosed(input)) {
      outputBlock('GoPlus AgentGuard: unable to load Cline hook engine; blocking fail-closed');
    }
    outputAllow();
  }

  const normalized = normalizeForRuntime(input);

  // Post hooks — audit only, never block.
  if (isPostHook(input)) {
    try {
      if (engine.protectAction) {
        const config = engine.loadRuntimeConfig();
        await engine.protectAction({
          config,
          rawInput: normalized,
          agentHost: 'cline',
          actionType: runtimeActionTypeFrom(toolName),
          toolName: runtimeToolNameFrom(toolName),
          sessionId: normalized.session_id || undefined,
          phase: 'post',
        });
      } else if (engine.ClineAdapter && engine.evaluateHook && engine.createAgentGuard) {
        const adapter = new engine.ClineAdapter();
        const config = engine.loadHookConfig
          ? engine.loadHookConfig()
          : { level: engine.loadRuntimeConfig?.()?.level };
        const agentguard = engine.createAgentGuard();
        await engine.evaluateHook(adapter, input, { config, agentguard });
      }
    } catch {
      // Post hooks must never affect Cline.
    }
    outputAllow();
  }

  // Pre hooks — make a real decision.
  try {
    if (engine.protectAction) {
      const config = engine.loadRuntimeConfig();
      const result = await engine.protectAction({
        config,
        rawInput: normalized,
        agentHost: 'cline',
        actionType: runtimeActionTypeFrom(toolName),
        toolName: runtimeToolNameFrom(toolName),
        sessionId: normalized.session_id || undefined,
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
        outputBlock(formatDecisionReason(result, 'blocked this Cline tool call'));
      } else if (result.decision.decision === 'require_approval') {
        outputReview(formatDecisionReason(result, 'requires confirmation for this Cline tool call'));
      } else {
        outputAllow();
      }
    }

    // Fallback: ClineAdapter + evaluateHook path.
    if (engine.ClineAdapter && engine.evaluateHook && engine.createAgentGuard) {
      const adapter = new engine.ClineAdapter();
      const config = engine.loadHookConfig
        ? engine.loadHookConfig()
        : { level: engine.loadRuntimeConfig?.()?.level };
      const agentguard = engine.createAgentGuard();
      const decision = await engine.evaluateHook(adapter, input, { config, agentguard });

      if (decision.decision === 'deny') outputBlock(decision.reason || 'GoPlus AgentGuard blocked this action');
      if (decision.decision === 'ask') outputReview(decision.reason || 'GoPlus AgentGuard requires confirmation');
      outputAllow();
    }

    outputAllow();
  } catch (err) {
    debugLog('engine error', { message: err instanceof Error ? err.message : String(err) });
    if (shouldFailClosed(input)) {
      outputBlock(`GoPlus AgentGuard engine error: ${err instanceof Error ? err.message : 'unknown'}`);
    }
    outputAllow();
  }
}

main();
