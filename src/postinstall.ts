#!/usr/bin/env node

import { ensureConfig, getAgentGuardPaths } from './config.js';

function printNextSteps(): void {
  console.log('Next steps:');
  console.log('  agentguard init --agent <agent>');
  console.log('  agentguard connect');
  console.log('  agentguard checkup');
}

try {
  ensureConfig();
  const paths = getAgentGuardPaths();
  console.log(`AgentGuard local config ready: ${paths.configPath}`);
} catch {
  // Postinstall must never break package installation.
} finally {
  printNextSteps();
}
