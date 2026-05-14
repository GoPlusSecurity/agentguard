#!/usr/bin/env node

import { readFileSync } from 'node:fs';
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
import { packageVersion } from './version.js';
import { runSelfCheckForAdvisory } from './feed/selfcheck.js';
import { loadFeedState, markAdvisorySeen, saveFeedState } from './feed/state.js';
import type { Advisory, SelfCheckResult } from './feed/types.js';

async function main() {
  const program = new Command();

  program
    .name('agentguard')
    .description('Local-first security guard for AI agents, with optional AgentGuard Cloud control plane')
    .version(packageVersion);

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

  program
    .command('subscribe')
    .description('Pull new threat-feed advisories from AgentGuard Cloud and run a self-check against locally installed skills')
    .option('--since <iso>', 'Override the persisted last-pulled timestamp')
    .option('--json', 'Emit machine-readable summary instead of human text')
    .option('--no-report', 'Skip uploading self-check results back to Cloud')
    .action(async (options) => {
      const config = ensureConfig();
      const client = new AgentGuardCloudClient(config);
      const state = loadFeedState();
      const since = (options.since as string | undefined) ?? state.lastPulledAt;

      let advisories: Advisory[] | null;
      try {
        advisories = await client.pullAdvisories(since);
      } catch (err) {
        console.error(`! Could not reach AgentGuard Cloud: ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
      if (advisories === null) {
        // 404 — older Cloud build without the feed endpoint. Not an error.
        if (options.json) {
          console.log(JSON.stringify({ supported: false, results: [] }));
        } else {
          console.log('AgentGuard Cloud does not expose /api/v1/feed/advisories yet — nothing to do.');
        }
        return;
      }

      const seen = new Set(state.seenAdvisoryIds ?? []);
      // Process oldest-first so the cursor can advance monotonically and we
      // never skip over an advisory that failed mid-batch.
      const fresh = advisories
        .filter((a) => !seen.has(a.id))
        .sort((a, b) => (a.publishedAt < b.publishedAt ? -1 : 1));
      const results: SelfCheckResult[] = [];
      let cursorOk = true; // stops advancing on the first hard failure
      let latestPublishedAt = state.lastPulledAt;
      let hardFailures = 0;

      for (const advisory of fresh) {
        let processed = true;
        let result: SelfCheckResult;
        try {
          result = await runSelfCheckForAdvisory(advisory);
        } catch (err) {
          // runSelfCheck shouldn't throw, but if it does the advisory has
          // not been evaluated — don't mark it seen and don't advance.
          console.error(`! Self-check threw for ${advisory.id}: ${(err as Error).message}`);
          hardFailures += 1;
          cursorOk = false;
          continue;
        }
        results.push(result);

        if (options.report !== false && client.connected && result.matchedArtifacts.length > 0) {
          // Report is on the critical path — if Cloud doesn't see the
          // match, we must NOT mark the advisory seen, otherwise a
          // transient network blip silently buries a real hit.
          try {
            await client.reportSelfCheck(advisory.id, result.matchedArtifacts, {
              elapsedMs: result.elapsedMs,
              warnings: result.warnings,
            });
          } catch (err) {
            console.error(`! Failed to report self-check for ${advisory.id}: ${(err as Error).message}`);
            processed = false;
            hardFailures += 1;
          }
        }

        if (processed) {
          Object.assign(state, markAdvisorySeen(state, advisory.id));
          if (cursorOk && (!latestPublishedAt || advisory.publishedAt > latestPublishedAt)) {
            latestPublishedAt = advisory.publishedAt;
          }
        } else {
          // From this point we no longer advance the pull cursor — the
          // failed advisory must be re-pulled on the next run.
          cursorOk = false;
        }
      }

      state.lastPulledAt = latestPublishedAt;
      saveFeedState(state);

      if (options.json) {
        console.log(JSON.stringify({ supported: true, pulled: advisories.length, fresh: fresh.length, results }, null, 2));
        return;
      }

      const totalMatches = results.reduce((acc, r) => acc + r.matchedArtifacts.length, 0);
      console.log(`Pulled ${advisories.length} advisory record(s); ${fresh.length} new.`);
      if (fresh.length === 0) return;
      console.log(`Self-check found ${totalMatches} match(es) across the new advisories.`);
      for (const r of results) {
        if (r.matchedArtifacts.length === 0) continue;
        console.log(`  - ${r.advisoryId}: ${r.matchedArtifacts.length} match(es)`);
        for (const m of r.matchedArtifacts) {
          console.log(`      · ${m.path}  [${m.matchedBy}]`);
        }
      }
      // Exit codes: 2 = matches found, 1 = at least one advisory failed
      // to evaluate or report (cursor was held back), 0 = clean.
      if (hardFailures > 0) {
        console.error(`! ${hardFailures} advisory record(s) failed to process and will be re-pulled next run.`);
        process.exitCode = 1;
      } else if (totalMatches > 0) {
        process.exitCode = 2;
      } else {
        process.exitCode = 0;
      }
    });

  program
    .command('checkup')
    .description('Run a self-check immediately. Without --against-advisory, scans for everything in the feed cache.')
    .option('--against-advisory <id>', 'Restrict the check to a single advisory id (fetches it from Cloud if needed)')
    .option('--json', 'Emit machine-readable result')
    .action(async (options) => {
      const config = ensureConfig();
      const client = new AgentGuardCloudClient(config);
      const advisoryId = options.againstAdvisory as string | undefined;

      if (!advisoryId) {
        console.log('Tip: pass --against-advisory <id> for now. A broader, full-fleet checkup is coming.');
        console.log('Meanwhile, run `agentguard subscribe` to pull the feed and self-check new entries.');
        return;
      }

      let advisory: Advisory | null = null;
      try {
        const all = await client.pullAdvisories();
        advisory = all?.find((a) => a.id === advisoryId) ?? null;
      } catch (err) {
        console.error(`! Could not reach AgentGuard Cloud: ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
      if (!advisory) {
        console.error(`No advisory with id "${advisoryId}" found in the current feed window.`);
        process.exitCode = 1;
        return;
      }

      const result = await runSelfCheckForAdvisory(advisory);
      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(`Advisory ${result.advisoryId}: ${result.matchedArtifacts.length} match(es)`);
        for (const m of result.matchedArtifacts) {
          console.log(`  · ${m.path}  [${m.matchedBy}]`);
        }
        if (result.warnings.length) {
          console.log('Warnings:');
          for (const w of result.warnings) console.log(`  ! ${w}`);
        }
      }
      process.exitCode = result.matchedArtifacts.length > 0 ? 2 : 0;
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

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
