#!/usr/bin/env node

/**
 * GoPlus AgentGuard Hermes shell hook.
 *
 * Hermes shell hooks read JSON from stdin and use stdout JSON to influence
 * behavior. For pre_tool_call, returning { action: "block", message: "..." }
 * vetoes tool execution. There is no native "ask" decision in Hermes'
 * pre_tool_call contract, so AgentGuard's ask decision is represented as a
 * block with a confirmation-oriented message.
 */

import { join } from 'node:path';

// ---------------------------------------------------------------------------
// Load AgentGuard engine + Hermes adapter
// ---------------------------------------------------------------------------

const agentguardPath = join(import.meta.url.replace('file://', ''), '..', '..', '..', '..', 'dist', 'index.js');

let createAgentGuard, HermesAdapter, evaluateHook, loadConfig;
try {
  const gs = await import(agentguardPath);
  createAgentGuard = gs.createAgentGuard || gs.default;
  HermesAdapter = gs.HermesAdapter;
  evaluateHook = gs.evaluateHook;
  loadConfig = gs.loadConfig;
} catch {
  try {
    const gs = await import('@goplus/agentguard');
    createAgentGuard = gs.createAgentGuard || gs.default;
    HermesAdapter = gs.HermesAdapter;
    evaluateHook = gs.evaluateHook;
    loadConfig = gs.loadConfig;
  } catch {
    process.stderr.write('GoPlus AgentGuard: unable to load Hermes hook engine, allowing action\n');
    console.log('{}');
    process.exit(0);
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
    setTimeout(() => resolve(null), 5000);
  });
}

// ---------------------------------------------------------------------------
// Hermes output helpers
// ---------------------------------------------------------------------------

function outputBlock(reason) {
  console.log(JSON.stringify({
    action: 'block',
    message: reason || 'GoPlus AgentGuard blocked this action',
  }));
  process.exit(0);
}

function outputAllow() {
  console.log('{}');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const input = await readStdin();
  if (!input) {
    outputAllow();
  }

  const adapter = new HermesAdapter();
  const config = loadConfig();
  const agentguard = createAgentGuard();

  const result = await evaluateHook(adapter, input, { config, agentguard });

  if (result.decision === 'deny') {
    outputBlock(result.reason || 'GoPlus AgentGuard blocked this Hermes tool call');
  } else if (result.decision === 'ask') {
    outputBlock(result.reason || 'GoPlus AgentGuard requires confirmation for this Hermes tool call');
  } else {
    outputAllow();
  }
}

main();
