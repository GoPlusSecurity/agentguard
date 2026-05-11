#!/usr/bin/env node

import { ensureConfig, getAgentGuardPaths } from './config.js';

try {
  ensureConfig();
  const paths = getAgentGuardPaths();
  console.log(`AgentGuard local config ready: ${paths.configPath}`);
} catch {
  // Postinstall must never break package installation.
}
