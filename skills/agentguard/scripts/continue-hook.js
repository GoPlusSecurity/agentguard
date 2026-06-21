#!/usr/bin/env node

/**
 * GoPlus AgentGuard — Continue file-hook bridge.
 *
 * Continue (the `cn` CLI) ships a Claude-Code-compatible hook system. Hooks are
 * registered in `~/.continue/settings.json` (or `~/.claude/settings.json`,
 * cwd variants, and `*.local.json`) and invoked with a JSON event on stdin.
 * They return a JSON control object on stdout. See
 * `continuedev/continue/extensions/cli/src/hooks/types.ts`.
 *
 * PreToolUse stdin (excerpt):
 *   {
 *     "hook_event_name": "PreToolUse",
 *     "tool_name": "run_terminal_command",
 *     "tool_input": {...},
 *     "tool_use_id": "...",
 *     "session_id": "...",
 *     "cwd": "/repo"
 *   }
 *
 * Stdout we emit:
 *   {}                                                  -> allow
 *   { hookSpecificOutput: { hookEventName: "PreToolUse",
 *                           permissionDecision: "deny",
 *                           permissionDecisionReason: "..." } }   -> block
 *   { hookSpecificOutput: { ..., permissionDecision: "ask",
 *                           permissionDecisionReason: "..." } }    -> review
 *
 * This script delegates to the unified `protectAction` runtime API with
 * `agentHost: 'continue'`, falling back to `ContinueAdapter` + `evaluateHook`
 * on older AgentGuard installs.
 */

import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function existsAtPath(p) {
  try {
    return existsSync(p);
  } catch {
    return false;
  }
}

// Resolve the bundled engine path safely across platforms. Mirrors the
// pattern used in cline-hook.js — fileURLToPath handles Windows correctly.
const scriptDir = dirname(fileURLToPath(import.meta.url));
const bundledEnginePath = resolve(scriptDir, '..', '..', '..', 'dist', 'index.js');

function isPostHook(input) {
  const event = typeof input?.hook_event_name === 'string' ? input.hook_event_name : '';
  return event.startsWith('Post');
}

function isPreHook(input) {
  return !isPostHook(input);
}

function toolNameFrom(input) {
  return typeof input?.tool_name === 'string' ? input.tool_name : '';
}

function toolInputFrom(input) {
  const ti = input?.tool_input ?? input?.toolInput;
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

const FAIL_OPEN = envBool('AGENTGUARD_CONTINUE_FAIL_OPEN', false);

// ---------------------------------------------------------------------------
// Tool → runtime action type mapping (mirrors src/adapters/continue.ts)
// ---------------------------------------------------------------------------

function runtimeActionTypeFrom(toolName) {
  switch (toolName) {
    case 'run_terminal_command':
      return 'shell';
    case 'create_new_file':
    case 'edit_existing_file':
    case 'single_find_and_replace':
    case 'multi_edit':
      return 'file_write';
    case 'read_file':
    case 'read_file_range':
    case 'read_currently_open_file':
      return 'file_read';
    case 'search_web':
      return 'web_search';
    case 'fetch_url_content':
      return 'network';
    default:
      return 'other';
  }
}

function runtimeToolNameFrom(toolName) {
  return toolName || 'ContinueTool';
}

function shouldFailClosed(input) {
  if (FAIL_OPEN) return false;
  return !input || isPreHook(input);
}

function isInScope(toolName) {
  return runtimeActionTypeFrom(toolName) !== 'other';
}

function validatePreToolPayload(input) {
  const toolName = toolNameFrom(input);
  const toolInput = toolInputFrom(input);

  switch (toolName) {
    case 'run_terminal_command': {
      const command = firstString(toolInput.command, toolInput.cmd);
      if (!command) return `Continue ${toolName} hook payload is missing command`;
      if (command.length > 1024 * 64) return `Continue ${toolName} command exceeds 64 KiB`;
      return null;
    }
    case 'create_new_file':
    case 'edit_existing_file':
    case 'single_find_and_replace':
    case 'read_file':
    case 'read_file_range':
    case 'read_currently_open_file': {
      const path = firstString(
        toolInput.filepath,
        toolInput.file_path,
        toolInput.filePath,
        toolInput.path,
        toolInput.target
      );
      if (!path) return `Continue ${toolName} hook payload is missing filepath`;
      if (path.includes('\0')) return `Continue ${toolName} filepath contains NUL byte`;
      return null;
    }
    case 'multi_edit': {
      const topPath = firstString(toolInput.filepath, toolInput.file_path, toolInput.filePath, toolInput.path);
      const edits = Array.isArray(toolInput.edits) ? toolInput.edits : null;
      if (!topPath && (!edits || edits.length === 0)) {
        return `Continue multi_edit hook payload is missing edits / filepath`;
      }
      // Validate every edit entry — each must be an object with a non-empty
      // filepath/path or contribute at least an old_string/new_string when
      // a top-level filepath is provided.
      if (edits) {
        for (let i = 0; i < edits.length; i++) {
          const entry = edits[i];
          if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
            return `Continue multi_edit edits[${i}] is not an object`;
          }
          const editPath = firstString(entry.filepath, entry.file_path, entry.filePath, entry.path);
          if (!editPath && !topPath) {
            return `Continue multi_edit edits[${i}] is missing filepath and no top-level filepath was provided`;
          }
          if (editPath && editPath.includes('\0')) {
            return `Continue multi_edit edits[${i}].filepath contains NUL byte`;
          }
        }
      }
      return null;
    }
    case 'fetch_url_content': {
      const url = firstString(toolInput.url, toolInput.uri, toolInput.href);
      if (!url) return `Continue fetch_url_content hook payload is missing URL`;
      // Cheap shape check — full URL validation lives in the engine.
      try {
        // eslint-disable-next-line no-new
        new URL(url);
      } catch {
        return `Continue fetch_url_content URL is not parseable`;
      }
      return null;
    }
    case 'search_web': {
      const query = firstString(toolInput.query, toolInput.q, toolInput.search);
      if (!query) return `Continue search_web hook payload is missing query`;
      return null;
    }
    default:
      // Out-of-scope tools pass through without engine evaluation.
      return null;
  }
}

// ---------------------------------------------------------------------------
// Engine loader
// ---------------------------------------------------------------------------

async function loadEngine() {
  if (process.env.AGENTGUARD_TEST_FORCE_ENGINE_LOAD_FAILURE === '1') return null;

  const tryImport = async (specifier) => {
    try {
      return await import(specifier);
    } catch {
      return null;
    }
  };

  const gs =
    (existsAtPath(bundledEnginePath) ? await tryImport(bundledEnginePath) : null) ||
    (await tryImport('@goplus/agentguard'));
  if (!gs) return null;

  return {
    loadRuntimeConfig: gs.loadAgentGuardConfig || gs.ensureConfig,
    loadHookConfig: gs.loadConfig,
    protectAction: gs.protectAction,
    createAgentGuard: gs.createAgentGuard || gs.default,
    ContinueAdapter: gs.ContinueAdapter,
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

function continueDecisionPayload(permissionDecision, reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: reason,
    },
  };
}

function outputBlock(reason) {
  const message = reason || 'GoPlus AgentGuard blocked this action';
  process.stdout.write(JSON.stringify(continueDecisionPayload('deny', message)) + '\n');
  process.exit(0);
}

function outputAsk(reason) {
  const message = reason || 'GoPlus AgentGuard requires confirmation for this action';
  process.stdout.write(JSON.stringify(continueDecisionPayload('ask', message)) + '\n');
  process.exit(0);
}

function outputAllow() {
  process.stdout.write('{}\n');
  process.exit(0);
}

function debugLog(message, details) {
  if (process.env.AGENTGUARD_CONTINUE_DEBUG !== '1') return;
  const suffix = details === undefined ? '' : ` ${JSON.stringify(details)}`;
  process.stderr.write(`[AgentGuard Continue] ${message}${suffix}\n`);
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
// Payload normalization — protectAction's input picker uses tool_input.path /
// file_path / url shapes. Continue is already mostly compatible (it uses
// `filepath` in some tools); normalize so the engine doesn't miss fields.
// ---------------------------------------------------------------------------

function normalizeForRuntime(input) {
  const toolName = toolNameFrom(input);
  const toolInput = { ...toolInputFrom(input) };

  // `filepath` -> `file_path` for tools that use Continue's spelling.
  if (typeof toolInput.filepath === 'string' && !toolInput.file_path) {
    toolInput.file_path = toolInput.filepath;
  }

  return {
    ...input,
    tool_name: toolName,
    tool_input: toolInput,
    session_id: firstString(input?.session_id, input?.sessionId, input?.tool_use_id),
    cwd: firstString(input?.cwd) || undefined,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const input = await readStdin();
  if (!input) {
    // Unparseable stdin — we have no way to know if it's an in-scope tool, so
    // this is always fail-closed regardless of AGENTGUARD_CONTINUE_FAIL_OPEN.
    // The override exists for engine-load failures, not for "we have no idea
    // what we're being asked to allow".
    outputBlock('GoPlus AgentGuard: invalid or missing Continue hook payload');
  }

  const toolName = toolNameFrom(input);

  // Out-of-scope tools always allow — no need to load the engine.
  if (isPreHook(input) && !isInScope(toolName)) {
    debugLog('out-of-scope tool, passthrough', { toolName });
    outputAllow();
  }

  const validationError = isPreHook(input) ? validatePreToolPayload(input) : null;
  if (validationError) {
    // Malformed payload for an in-scope (security-sensitive) tool. Block
    // regardless of fail-open — the override is for cases where AgentGuard
    // itself is unavailable, not for "we got a half-formed shell command
    // and aren't sure what it is."
    outputBlock(`GoPlus AgentGuard: ${validationError}`);
  }

  const engine = await loadEngine();
  if (!engine) {
    debugLog('engine load failed');
    if (shouldFailClosed(input)) {
      outputBlock('GoPlus AgentGuard: unable to load Continue hook engine; blocking fail-closed');
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
          agentHost: 'continue',
          actionType: runtimeActionTypeFrom(toolName),
          toolName: runtimeToolNameFrom(toolName),
          sessionId: normalized.session_id || undefined,
          phase: 'post',
        });
      } else if (engine.ContinueAdapter && engine.evaluateHook && engine.createAgentGuard) {
        const adapter = new engine.ContinueAdapter();
        const config = engine.loadHookConfig
          ? engine.loadHookConfig()
          : { level: engine.loadRuntimeConfig?.()?.level };
        const agentguard = engine.createAgentGuard();
        await engine.evaluateHook(adapter, input, { config, agentguard });
      }
    } catch {
      // Post hooks must never affect Continue.
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
        agentHost: 'continue',
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
        outputBlock(formatDecisionReason(result, 'blocked this Continue tool call'));
      } else if (result.decision.decision === 'require_approval') {
        outputAsk(formatDecisionReason(result, 'requires confirmation for this Continue tool call'));
      } else {
        outputAllow();
      }
    }

    // Fallback: ContinueAdapter + evaluateHook path.
    if (engine.ContinueAdapter && engine.evaluateHook && engine.createAgentGuard) {
      const adapter = new engine.ContinueAdapter();
      const config = engine.loadHookConfig
        ? engine.loadHookConfig()
        : { level: engine.loadRuntimeConfig?.()?.level };
      const agentguard = engine.createAgentGuard();
      const decision = await engine.evaluateHook(adapter, input, { config, agentguard });

      if (decision.decision === 'deny') outputBlock(decision.reason || 'GoPlus AgentGuard blocked this action');
      if (decision.decision === 'ask') outputAsk(decision.reason || 'GoPlus AgentGuard requires confirmation');
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
