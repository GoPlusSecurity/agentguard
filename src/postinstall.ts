#!/usr/bin/env node

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ensureConfig, getAgentGuardPaths } from './config.js';

const NEXT_STEPS = [
  'Next step:',
  '  agentguard init --agent auto',
  '',
].join('\n');

function printNextSteps(): void {
  process.stdout.write(NEXT_STEPS);
}

function writeNextStepsFile(path: string, mode = 0o600): void {
  try {
    writeFileSync(path, NEXT_STEPS, { mode });
  } catch {
    // Installation guidance is best-effort and must never break npm install.
  }
}

function writePackageNextStepsFile(): void {
  if (process.env.AGENTGUARD_SKIP_PACKAGE_NEXT_STEPS === '1') return;
  const packageDir = resolve(__dirname, '..');
  writeNextStepsFile(resolve(packageDir, 'next-steps.txt'), 0o644);
}

try {
  ensureConfig();
  const paths = getAgentGuardPaths();
  writeNextStepsFile(resolve(paths.home, 'next-steps.txt'));
  console.log(`AgentGuard local config ready: ${paths.configPath}`);
} catch {
  // Postinstall must never break package installation.
} finally {
  writePackageNextStepsFile();
  printNextSteps();
}
