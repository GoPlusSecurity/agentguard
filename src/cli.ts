#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Command } from 'commander';
import { AgentGuardCloudClient } from './cloud/client.js';
import {
  connectCloud,
  ensureConfig,
  getAgentGuardPaths,
  loadConfig,
  maskApiKey,
  normalizeCloudUrl,
  saveConfig,
} from './config.js';
import { SkillScanner } from './scanner/index.js';
import { formatProtectResult, protectAction, exitCodeForDecision } from './runtime/protect.js';
import { saveCachedPolicy } from './runtime/policy.js';
import type { RuntimeActionType, RuntimeAgentHost } from './runtime/types.js';
import { installAgentTemplates, type AgentInstaller } from './installers.js';

async function main() {
  const program = new Command();

  program
    .name('agentguard')
    .description('Local-first security guard for AI agents, with optional AgentGuard Cloud control plane')
    .version(readPackageVersion());

  program
    .command('init')
    .description('Create ~/.agentguard/config.json and local runtime paths')
    .option('--level <level>', 'Protection level: strict | balanced | permissive')
    .option('--agent <agent>', 'Install hook/template for claude-code, codex, or openclaw')
    .option('--cloud <url>', 'AgentGuard Cloud URL to store in local config')
    .option('--force', 'Overwrite existing hook/template files')
    .action((options) => {
      const config = ensureConfig();
      if (options.level) {
        if (!['strict', 'balanced', 'permissive'].includes(options.level)) {
          throw new Error('Invalid level. Use strict, balanced, or permissive.');
        }
        config.level = options.level;
        saveConfig(config);
      }
      if (options.cloud) {
        config.cloudUrl = normalizeCloudUrl(options.cloud);
        saveConfig(config);
      }
      const paths = getAgentGuardPaths();
      console.log(`AgentGuard initialized at ${paths.home}`);
      console.log(`Config: ${paths.configPath}`);
      if (options.agent) {
        if (!['claude-code', 'codex', 'openclaw'].includes(options.agent)) {
          throw new Error('Invalid agent. Use claude-code, codex, or openclaw.');
        }
        const result = installAgentTemplates(options.agent as AgentInstaller, { force: options.force });
        console.log(`Installed ${result.agent} template:`);
        for (const file of result.files) console.log(`- ${file}`);
      }
    });

  program
    .command('connect')
    .description('Connect local AgentGuard to AgentGuard Cloud')
    .option('--key <key>', 'AgentGuard Cloud API key (prefer AGENTGUARD_API_KEY to avoid shell history)')
    .option('--api-key <key>', 'AgentGuard Cloud API key (prefer AGENTGUARD_API_KEY to avoid shell history)')
    .option('--url <url>', 'AgentGuard Cloud URL', 'https://agentguard.gopluslabs.io')
    .option('--cloud <url>', 'AgentGuard Cloud URL')
    .action(async (options) => {
      const apiKey = options.key || options.apiKey || process.env.AGENTGUARD_API_KEY;
      if (!apiKey) {
        throw new Error('Missing API key. Pass --key, --api-key, or set AGENTGUARD_API_KEY.');
      }
      const config = connectCloud({ apiKey, cloudUrl: options.cloud || options.url });
      const client = new AgentGuardCloudClient(config);
      try {
        const policy = await client.fetchEffectivePolicy();
        saveCachedPolicy(config.policyCachePath, policy);
        console.log(`Connected to AgentGuard Cloud (${config.cloudUrl}).`);
        console.log(`Cached policy ${policy.policyVersion} at ${config.policyCachePath}.`);
      } catch (error) {
        console.log(`Saved Cloud configuration for ${config.cloudUrl}.`);
        console.log(`Policy fetch failed; local protection still works offline. ${error instanceof Error ? error.message : ''}`.trim());
      }
    });

  program
    .command('status')
    .description('Show local and Cloud connection status')
    .action(() => {
      const config = ensureConfig();
      const paths = getAgentGuardPaths();
      console.log(`Config: ${paths.configPath}`);
      console.log(`Protection level: ${config.level}`);
      console.log(`Cloud URL: ${config.cloudUrl || 'not configured'}`);
      console.log(`API key: ${maskApiKey(config.apiKey)}`);
      console.log(`Policy cache: ${config.policyCachePath}`);
      console.log(`Audit log: ${config.auditPath}`);
    });

  program
    .command('doctor')
    .description('Check local AgentGuard setup')
    .action(async () => {
      const config = ensureConfig();
      const paths = getAgentGuardPaths();
      console.log(`✓ Home: ${paths.home}`);
      console.log(`✓ Config: ${paths.configPath}`);
      console.log(`✓ Node: ${process.version}`);
      if (config.apiKey) {
        const client = new AgentGuardCloudClient(config);
        try {
          const status = await client.status();
          console.log(`✓ Cloud: ${status.status}${status.version ? ` (${status.version})` : ''}`);
        } catch {
          console.log('! Cloud: unreachable; local protection remains active');
        }
      } else {
        console.log('! Cloud: not connected');
      }
    });

  program
    .command('scan')
    .description('Scan a local skill/plugin directory')
    .argument('<path>', 'Directory to scan')
    .option('--json', 'Print JSON output')
    .action(async (path, options) => {
      const scanner = new SkillScanner({ useExternalScanner: false });
      const result = await scanner.quickScan(path);
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`${result.risk_level.toUpperCase()}: ${result.summary}`);
        if (result.risk_tags.length) console.log(`Tags: ${result.risk_tags.join(', ')}`);
      }
      process.exitCode = result.risk_level === 'critical' ? 2 : 0;
    });

  program
    .command('protect')
    .description('Evaluate one runtime action from stdin or hook environment')
    .option('--agent <agent>', 'Agent host, e.g. claude-code, codex, openclaw')
    .option('--action-type <type>', 'Runtime action type, e.g. shell, file_read, file_write')
    .option('--tool-name <name>', 'Tool name from host')
    .option('--session-id <id>', 'Stable agent session id')
    .option('--decision-mode <mode>', 'local-first or cloud', 'local-first')
    .option('--json', 'Print JSON output')
    .action(async (options) => {
      const stdinText = readStdinIfAvailable();
      const result = await protectAction({
        config: ensureConfig(),
        stdinText,
        agentHost: options.agent as RuntimeAgentHost | undefined,
        actionType: options.actionType as RuntimeActionType | undefined,
        toolName: options.toolName,
        sessionId: options.sessionId,
        decisionMode: options.decisionMode,
      });
      if (!result) return;
      console.log(formatProtectResult(result, Boolean(options.json)));
      process.exitCode = exitCodeForDecision(result.decision);
    });

  await program.parseAsync(process.argv);
}

function readStdinIfAvailable(): string {
  if (process.stdin.isTTY) return '';
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function readPackageVersion(): string {
  const packageJson = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')) as { version?: string };
  return packageJson.version || '0.0.0';
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
