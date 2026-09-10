#!/usr/bin/env node

import { appendFileSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, extname, join, relative, resolve, sep } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { Command } from 'commander';
import { AgentGuardCloudClient } from './cloud/client.js';
import {
  connectCloud,
  connectAgentJwt,
  clearAgentJwt,
  clearAgentRegisterUrl,
  disconnectCloud,
  ensureConfig,
  getAgentGuardPaths,
  loadConfig,
  maskApiKey,
  normalizeCloudUrl,
  saveConfig,
} from './config.js';
import type { AgentGuardAgentHost, AgentGuardConfig } from './config.js';
import { SkillScanner } from './scanner/index.js';
import type { DirectoryScanSnapshot } from './scanner/file-walker.js';
import { SkillRegistry } from './registry/index.js';
import type { TrustRecord } from './types/registry.js';
import { resolveScanSource } from './scanner/source.js';
import { formatProtectResult, protectAction, exitCodeForDecision } from './runtime/protect.js';
import { approvePendingApproval, listPendingApprovals } from './runtime/approvals.js';
import { getDefaultEffectiveRuntimePolicy, loadCachedPolicy, saveCachedPolicy } from './runtime/policy.js';
import type { RuntimeActionType, RuntimeAgentHost } from './runtime/types.js';
import { installAgentTemplates, type AgentInstaller, type InstallResult } from './installers.js';
import { packageVersion } from './version.js';
import { runSelfCheckForAdvisory } from './feed/selfcheck.js';
import { discoverDshSelfCheckRoots } from './feed/dsh-discovery.js';
import { scanDshPluginsForCheckup, type DshCheckupPluginResult } from './checkup/dsh.js';
import { getSeenAdvisoryIds, loadFeedState, prependFeedStateEntry, saveFeedState } from './feed/state.js';
import type { Advisory, SelfCheckResult } from './feed/types.js';
import { CloudRequestError } from './cloud/client.js';
import { notifyOpenClawMessage, notifyOpenClawRegistrationLink } from './cloud/openclaw-notify.js';
import { scanDshPlugin } from './dsh/scan.js';
import { parseDshBatchManifest, scanDshPlugins } from './dsh/batch.js';
import { renderDshHtml, renderDshMarkdown } from './reports/dsh-report.js';
import { renderDshBatchMarkdown } from './reports/dsh-batch-report.js';
import { compareDshReports, parseDshPluginScanReport } from './dsh/compare.js';
import { renderDshComparisonMarkdown } from './reports/dsh-compare-report.js';
import {
  installThreatFeedCron,
  removeThreatFeedCron,
  runWindowsCronTick,
  validateCronExpression,
  type OpenClawCronInstallResult,
  type CronBackend,
  type ThreatFeedCronRemovalResult,
  type OpenClawGatewayOptions,
} from './feed/cron.js';
import { loadDshThreatFeedSubscription } from './feed/dsh-subscription.js';
import {
  buildDshThreatFeedNotification,
  enqueueDshThreatFeedNotification,
} from './feed/dsh-notifications.js';

const SUPPORTED_AGENT_INSTALLERS: AgentInstaller[] = ['claude-code', 'codex', 'openclaw', 'hermes', 'qclaw', 'dsh'];
const AUTO_AGENT_DETECTION: Array<{ agent: AgentInstaller; dir: string }> = [
  { agent: 'claude-code', dir: '.claude' },
  { agent: 'openclaw', dir: '.openclaw' },
  { agent: 'hermes', dir: '.hermes' },
  { agent: 'qclaw', dir: '.qclaw' },
  { agent: 'codex', dir: '.codex' },
];
const REQUIRED_INIT_COMMAND = 'agentguard init';

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
    .option('--agent <agent>', 'Install integration for auto, claude-code, codex, openclaw, hermes, qclaw, or dsh (default: auto)')
    .option('--cloud <url>', 'AgentGuard Cloud URL to store in local config')
    .option('--shell-hooks', 'For Hermes: install legacy shell hooks instead of the native plugin')
    .option('--force', 'Overwrite existing hook/template files')
    .option('--no-force', 'Do not overwrite existing hook/template files')
    .action((options) => {
      const forceTemplates = options.force !== false;
      let config = ensureConfig();
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
      {
        const normalizedAgent = options.agent === undefined
          ? 'auto'
          : String(options.agent).trim().toLowerCase();
        if (normalizedAgent === 'auto') {
          const results = initAutoAgents(config, forceTemplates);
          if (results.detected.length === 0) {
            console.log('No supported agent installation found. Looked for DSH and .claude, .openclaw, .hermes, .qclaw, and .codex.');
          } else if (results.installed.length === 0) {
            console.log('No agent integrations were installed; all detected agent initializers failed.');
          }
          for (const result of results.installed) {
            printInstallResult(result);
            if (result.agent === 'hermes') printHermesNativePluginEnabled();
          }
          for (const failure of results.failed) {
            console.error(`! Failed to initialize ${failure.agent}: ${failure.error}`);
          }
          return;
        }
        if (!SUPPORTED_AGENT_INSTALLERS.includes(normalizedAgent as AgentInstaller)) {
          throw new Error('Invalid agent. Use auto, claude-code, codex, openclaw, hermes, qclaw, or dsh.');
        }
        const agent = normalizedAgent as AgentInstaller;
        const shellHooks = Boolean(options.shellHooks);
        const result = installAgentTemplates(agent, { force: forceTemplates, shellHooks });
        config.agentHost = agent;
        config.agentHosts = appendAgentHost(config.agentHosts, agent);
        saveConfig(config);
        printInstallResult(result);
        if (agent === 'hermes' && !shellHooks) {
          printHermesNativePluginEnabled();
        }
      }
    });

  program
    .command('connect')
    .description('Connect local AgentGuard to AgentGuard Cloud')
    .option('--key <key>', 'AgentGuard Cloud API key (prefer AGENTGUARD_API_KEY to avoid shell history)')
    .option('--api-key <key>', 'AgentGuard Cloud API key (prefer AGENTGUARD_API_KEY to avoid shell history)')
    .option('--url <url>', 'AgentGuard Cloud URL', 'https://www.agentguard.one')
    .option('--cloud <url>', 'AgentGuard Cloud URL')
    .action(async (options) => {
      const apiKey = options.key || options.apiKey || process.env.AGENTGUARD_API_KEY;
      if (!apiKey) {
        let config = ensureConfig();
        if (!isAgentJwtHostConfigured(config)) {
          throw new Error('AgentGuard Cloud connect supports API-key auth or Agent JWT registration for OpenClaw, Hermes, and DSH. No API key was provided, and no supported Agent JWT host has been initialized. Run `agentguard init` to auto-detect the host, then rerun `agentguard connect`; or pass --key, --api-key, or AGENTGUARD_API_KEY for API-key auth.');
        }
        config = withDetectedAgentJwtHost(config);
        const cloudUrl = normalizeCloudUrl(options.cloud || options.url || config.cloudUrl || 'https://www.agentguard.one');
        if (config.agentId && config.agentJwt) {
          const existingConfig = { ...config, cloudUrl };
          const client = new AgentGuardCloudClient(existingConfig);
          try {
            const policy = await client.fetchEffectivePolicy();
            const savedConfig = connectAgentJwt({
              agentId: config.agentId,
              agentJwt: config.agentJwt,
              agentRegisterUrl: config.agentRegisterUrl,
              cloudUrl,
            });
            const activeConfig = clearAgentRegisterUrl(savedConfig);
            saveCachedPolicy(activeConfig.policyCachePath, policy);
            console.log(`Connected to AgentGuard Cloud (${activeConfig.cloudUrl}).`);
            console.log(`Agent JWT is active for local agent ${activeConfig.agentId}.`);
            console.log(`Cached policy ${policy.policyVersion} at ${activeConfig.policyCachePath}.`);
            return;
          } catch (err) {
            if (!(err instanceof CloudRequestError && err.status === 401)) {
              console.log(`Agent JWT is configured for ${cloudUrl}.`);
              console.log(`Could not verify it right now; local protection still works offline. ${err instanceof Error ? err.message : ''}`.trim());
              return;
            }
          }
        }
        let registration: AgentCredentialRegistration;
        try {
          registration = await registerAgentCredential({
            cloudUrl,
            reason: 'connect',
            notifyOpenClaw: false,
            resetExistingJwt: true,
          });
        } catch (err) {
          throw new Error(`Could not register AgentGuard agent: ${err instanceof Error ? err.message : String(err)}`);
        }
        console.log(`Registered local AgentGuard agent (${registration.config.agentId}).`);
        console.log('Open this link to bind this agent to your account:');
        console.log(registration.registerUrl);
        if (registration.openClawNotification.notified) {
          console.log('Sent the activation link to the last OpenClaw channel.');
        } else if (registration.openClawNotification.reason) {
          console.log(`OpenClaw notification skipped: ${registration.openClawNotification.reason}`);
        }
        return;
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
    .command('windows-cron-run', { hidden: true })
    .description('Internal: evaluate and run a Windows Task Scheduler cron tick')
    .requiredOption('--config <path>', 'Managed Windows cron config path')
    .action(async (options) => {
      await runWindowsCronTick(resolve(options.config as string));
    });

  program
    .command('disconnect')
    .description('Disconnect local AgentGuard from AgentGuard Cloud')
    .action(async () => {
      const currentConfig = ensureConfig();
      const cronRemoval = await removeThreatFeedCron({
        name: currentConfig.threatFeedCronName || 'agentguard-threat-feed',
        backend: 'auto',
        agentHost: resolveCronAgentHost(currentConfig),
        agentGuardHome: getAgentGuardPaths().home,
      });
      const config = disconnectCloud();
      console.log('Disconnected from AgentGuard Cloud.');
      console.log('Removed local Cloud API key, Agent JWT, connection timestamp, pending event spool, and cached Cloud policy.');
      printCronRemovalSummary(cronRemoval);
      console.log(`Local protection remains active using the built-in policy. Audit log: ${config.auditPath}`);
    });

  program
    .command('status')
    .description('Show local and Cloud connection status')
    .action(async () => {
      const config = await refreshAgentAccountBinding(ensureConfig());
      const paths = getAgentGuardPaths();
      console.log(`Config: ${paths.configPath}`);
      console.log(`Protection level: ${config.level}`);
      console.log(`Cloud URL: ${config.cloudUrl || 'not configured'}`);
      printCloudAuthStatus(config);
      console.log(`Agent host: ${config.agentHost || 'not configured'}`);
      console.log(`Agent hosts: ${config.agentHosts?.join(', ') || 'not configured'}`);
      console.log(`Policy cache: ${config.policyCachePath}`);
      console.log(`Audit log: ${config.auditPath}`);
      printInitGuidanceIfNeeded(config);
    });

  const policy = program
    .command('policy')
    .description('Manage local runtime policy cache');

  policy
    .command('pull')
    .description('Pull the latest effective runtime policy from AgentGuard Cloud into the local cache')
    .option('--json', 'Print JSON output')
    .action(async (options) => {
      let config = ensureConfig();
      let client = new AgentGuardCloudClient(config);
      if (!client.connected) {
        const message = 'AgentGuard Cloud is not connected. Run `agentguard connect` first.';
        if (options.json) {
          console.log(JSON.stringify({ success: false, error: message }, null, 2));
        } else {
          console.error(message);
        }
        process.exitCode = 1;
        return;
      }

      try {
        const result = await runCloudRequestWithAgentJwtReauth({
          config,
          client,
          reason: 'reauth',
          notifyOpenClaw: true,
          operation: (activeClient) => activeClient.fetchEffectivePolicy(),
        });
        config = result.config;
        client = result.client;
        const pulledPolicy = result.value;
        saveCachedPolicy(config.policyCachePath, pulledPolicy);
        if (options.json) {
          console.log(JSON.stringify({
            success: true,
            policyVersion: pulledPolicy.policyVersion,
            updatedAt: pulledPolicy.updatedAt,
            cachePath: config.policyCachePath,
          }, null, 2));
        } else {
          console.log(`Pulled policy ${pulledPolicy.policyVersion}.`);
          console.log(`Policy cache: ${config.policyCachePath}`);
        }
      } catch (err) {
        const message = `Policy pull failed: ${(err as Error).message}`;
        if (options.json) {
          console.log(JSON.stringify({ success: false, error: message }, null, 2));
        } else {
          console.error(message);
        }
        process.exitCode = 1;
      }
    });

  policy
    .command('show')
    .description('Show the cached effective runtime policy, or the bundled default policy when no cache exists')
    .option('--json', 'Print JSON output')
    .action((options) => {
      const config = ensureConfig();
      const cachedPolicy = loadCachedPolicy(config.policyCachePath);
      const source = cachedPolicy ? 'cache' : 'default';
      const shownPolicy = cachedPolicy ?? getDefaultEffectiveRuntimePolicy();

      if (options.json) {
        console.log(JSON.stringify({
          success: true,
          source,
          cachePath: config.policyCachePath,
          policy: shownPolicy,
          networkPolicyWarning: networkDefaultOutboundWarning(shownPolicy.network.defaultOutbound),
        }, null, 2));
        return;
      }

      console.log(`Policy source: ${source}`);
      console.log(`Policy version: ${shownPolicy.policyVersion}`);
      console.log(`Mode: ${shownPolicy.mode}`);
      console.log(`Updated at: ${shownPolicy.updatedAt}`);
      console.log(`Cache path: ${config.policyCachePath}`);
      console.log('Decisions:');
      for (const [name, decision] of Object.entries(shownPolicy.decisions)) {
        console.log(`- ${name}: ${decision}`);
      }
      console.log(`Protected paths: ${shownPolicy.protectedPaths.length}`);
      console.log(`Blocked command patterns: ${shownPolicy.blockedCommandPatterns.length}`);
      console.log(`Allowed command patterns: ${shownPolicy.allowedCommandPatterns.length}`);
      console.log(`Approval action types: ${shownPolicy.approvalActionTypes.join(', ') || 'none'}`);
      console.log(`Network default outbound: ${shownPolicy.network.defaultOutbound}`);
      console.log(`Blocked domains: ${shownPolicy.network.blockedDomains.length}`);
      console.log(`Approval domains: ${shownPolicy.network.approvalDomains.length}`);
      const networkWarning = networkDefaultOutboundWarning(shownPolicy.network.defaultOutbound);
      if (networkWarning) console.log(`! ${networkWarning}`);
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
      const client = new AgentGuardCloudClient(config);
      if (client.connected) {
        try {
          const status = await client.status();
          const label = status.status || (status.ok ? 'ok' : status.service || 'reachable');
          console.log(`✓ Cloud: ${label}${status.version ? ` (${status.version})` : ''}`);
        } catch {
          console.log('! Cloud: unreachable; local protection remains active');
        }
      } else {
        console.log('! Cloud: not connected');
      }
      printInitGuidanceIfNeeded(config);
    });

  program
    .command('scan')
    .description('Scan a local skill/plugin directory or HTTPS GitHub repository')
    .argument('<repo-or-path>', 'Local directory or https://github.com/owner/repo URL')
    .option('--ref <ref>', 'GitHub branch, tag, fully qualified ref, or full commit SHA')
    .option('--json', 'Print JSON output')
    .action(async (input, options) => {
      const source = await resolveScanSource(String(input), {
        ref: options.ref === undefined ? undefined : String(options.ref),
      });
      try {
        const scanner = new SkillScanner({ useExternalScanner: false });
        const result = await scanner.quickScan(source.rootDir);
        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
        } else {
          console.log(`${result.risk_level.toUpperCase()}: ${result.summary}`);
          if (result.risk_tags.length) console.log(`Tags: ${result.risk_tags.join(', ')}`);
        }
        process.exitCode = result.risk_level === 'critical' ? 2 : 0;
      } finally {
        await source.cleanup();
      }
    });

  program
    .command('dsh-scan')
    .description('Audit a local DSH plugin directory or HTTPS GitHub repository')
    .argument('<repo-or-path>', 'Local directory or https://github.com/owner/repo URL')
    .option('--ref <ref>', 'GitHub branch, tag, fully qualified ref, or full commit SHA')
    .option('-f, --format <format>', 'Report format: json | markdown | html', 'markdown')
    .option('-o, --output <path>', 'Write the report to a file instead of stdout')
    .action(async (input, options) => {
      const format = String(options.format).toLowerCase();
      if (!['json', 'markdown', 'html'].includes(format)) {
        throw new Error('Invalid format. Use json, markdown, or html.');
      }
      const report = await scanDshPlugin(String(input), {
        ref: options.ref === undefined ? undefined : String(options.ref),
      });
      const rendered = format === 'json'
        ? `${JSON.stringify(report, null, 2)}\n`
        : format === 'html'
          ? renderDshHtml(report)
          : renderDshMarkdown(report);
      if (options.output) {
        const outputPath = resolve(String(options.output));
        mkdirSync(dirname(outputPath), { recursive: true });
        writeFileSync(outputPath, rendered, 'utf8');
        console.error(`DSH scan report written to ${outputPath}`);
      } else {
        process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
      }
      process.exitCode = report.riskLevel === 'critical' ? 2 : 0;
    });

  program
    .command('dsh-scan-batch')
    .description('Audit a bounded JSON manifest of DSH plugin directories or GitHub repositories')
    .argument('<manifest>', 'JSON file containing a targets array')
    .option('-f, --format <format>', 'Report format: json | markdown', 'markdown')
    .option('-o, --output <path>', 'Write the report to a file instead of stdout')
    .action(async (manifest, options) => {
      const format = String(options.format).toLowerCase();
      if (!['json', 'markdown'].includes(format)) throw new Error('Invalid format. Use json or markdown.');
      const manifestPath = resolve(String(manifest));
      if (statSync(manifestPath).size > 256 * 1024) throw new Error('DSH batch manifest exceeds the 256 KiB limit');
      const targets = parseDshBatchManifest(JSON.parse(readFileSync(manifestPath, 'utf8'))).map(entry => ({
        ...entry,
        target: /^https?:\/\//i.test(entry.target) ? entry.target : resolve(dirname(manifestPath), entry.target),
      }));
      const batch = await scanDshPlugins(targets);
      const rendered = format === 'json' ? `${JSON.stringify(batch, null, 2)}\n` : renderDshBatchMarkdown(batch);
      if (options.output) {
        const outputPath = resolve(String(options.output));
        mkdirSync(dirname(outputPath), { recursive: true });
        writeFileSync(outputPath, rendered, 'utf8');
        console.error(`DSH batch scan report written to ${outputPath}`);
      } else {
        process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
      }
      process.exitCode = batch.failed > 0 ? 1 : batch.highestRisk === 'critical' ? 2 : 0;
    });

  program
    .command('dsh-compare')
    .description('Compare two saved DSH JSON scan reports before updating a plugin')
    .argument('<before-report>', 'Previously approved DSH JSON report')
    .argument('<after-report>', 'Candidate DSH JSON report')
    .option('-f, --format <format>', 'Report format: json | markdown', 'markdown')
    .option('-o, --output <path>', 'Write the comparison to a file instead of stdout')
    .action((beforeInput, afterInput, options) => {
      const format = String(options.format).toLowerCase();
      if (!['json', 'markdown'].includes(format)) throw new Error('Invalid format. Use json or markdown.');
      const readReport = (input: string, label: string) => {
        const path = resolve(input);
        if (statSync(path).size > 32 * 1024 * 1024) throw new Error(`${label} exceeds the 32 MiB limit`);
        return parseDshPluginScanReport(JSON.parse(readFileSync(path, 'utf8')), label);
      };
      const comparison = compareDshReports(readReport(String(beforeInput), 'before report'), readReport(String(afterInput), 'after report'));
      const rendered = format === 'json' ? `${JSON.stringify(comparison, null, 2)}\n` : renderDshComparisonMarkdown(comparison);
      if (options.output) {
        const outputPath = resolve(String(options.output));
        mkdirSync(dirname(outputPath), { recursive: true });
        writeFileSync(outputPath, rendered, 'utf8');
        console.error(`DSH comparison written to ${outputPath}`);
      } else {
        process.stdout.write(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
      }
      process.exitCode = comparison.assessment === 'review-required' ? 2 : 0;
    });

  program
    .command('approve')
    .description('Approve one pending runtime action')
    .option('--action-id <id>', 'Pending action id returned by agentguard protect')
    .option('--last', 'Approve the most recent unambiguous pending action')
    .option('--once', 'Approve only the next matching retry')
    .option('--json', 'Print JSON output')
    .action((options) => {
      if (!options.once) {
        throw new Error('Approvals must be scoped with --once.');
      }
      const config = ensureConfig();
      const approved = approvePendingApproval(config.approvalStorePath!, {
        actionId: options.actionId,
        last: Boolean(options.last),
        once: true,
        sessionId: process.env.AGENTGUARD_SESSION_ID,
      });
      if (options.json) {
        console.log(JSON.stringify({ success: true, approval: approved }, null, 2));
      } else {
        console.log(`Approved once: ${approved.actionId}`);
        console.log(`Expires: ${approved.expiresAt}`);
      }
    });

  const approvals = program
    .command('approvals')
    .description('Inspect pending runtime approvals');

  approvals
    .command('list')
    .description('List unexpired pending approvals')
    .option('--json', 'Print JSON output')
    .action((options) => {
      const config = ensureConfig();
      const pending = listPendingApprovals(config.approvalStorePath!);
      if (options.json) {
        console.log(JSON.stringify({ success: true, approvals: pending }, null, 2));
      } else if (pending.length === 0) {
        console.log('No pending approvals.');
      } else {
        for (const approval of pending) {
          console.log(`${approval.actionId} ${approval.actionType} ${approval.toolName} expires=${approval.expiresAt}`);
          console.log(`  ${approval.inputPreview}`);
        }
      }
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
      process.exitCode = exitCodeForDecision(result.decision, result);
    });

  program
    .command('subscribe')
    .description('Pull new threat-feed advisories from AgentGuard Cloud and run a self-check against locally installed skills')
    .option('--since <iso>', 'Override the persisted last-pulled timestamp')
    .option('--json', 'Emit machine-readable summary instead of human text')
    .option('--quiet', 'Run the full pull, self-check, and match-reporting flow with minimal output')
    .option('--no-report', 'Skip uploading self-check results back to Cloud')
    .option('--cron <expr>', 'Install a cron job with a five-field cron expression, for example "0 * * * *"')
    .option('--cron-target <target>', 'Cron backend: auto, openclaw, qclaw, hermes, system, or windows', 'auto')
    .option('--cron-name <name>', 'Cron job name', 'agentguard-threat-feed')
    .option('--force', 'Replace an existing cron job with the same name')
    .option('--cron-run', 'Internal: run from the OpenClaw cron prompt without trying to install cron again')
    .option('--cron-notify-run', 'Internal: run from an OpenClaw cron prompt and print only the notification body or NO_REPLY')
    .action(async (options) => {
      let config = ensureConfig();
      let client = new AgentGuardCloudClient(config);
      const cronAgentHost = resolveCronAgentHost(config);
      const state = loadFeedState();
      const since = options.since as string | undefined;
      const quiet = Boolean(options.quiet);
      const cronNotifyRun = Boolean(options.cronNotifyRun);
      const cronInternalRun = Boolean(options.cronRun || options.cronNotifyRun);
      const cronTarget = validateCronTarget(options.cronTarget);
      const cronRunSendsToOpenClaw = Boolean(options.cronRun) && cronAgentHost === 'openclaw';
      const cronExpression = options.cron && !options.cronRun
        ? validateCronExpression(options.cron as string)
        : undefined;

      let registration: AgentCredentialRegistration | null = null;
      if (!client.connected) {
        if (!isAgentJwtHostConfigured(config)) {
          const message = 'AgentGuard Cloud is not connected. Run `agentguard connect --key <key>` first, or run `agentguard init` to auto-detect an OpenClaw, Hermes, or DSH host for Agent JWT registration.';
          if (cronNotifyRun) {
            console.log('NO_REPLY');
          } else if (options.json) {
            console.log(JSON.stringify({ success: false, error: message }, null, 2));
          } else {
            console.error(message);
          }
          process.exitCode = 1;
          return;
        }
        try {
          registration = await registerAgentCredential({
            cloudUrl: config.cloudUrl,
            reason: 'subscribe',
            notifyOpenClaw: resolveCronAgentHost(config) === 'openclaw',
          });
          config = registration.config;
          client = registration.client;
        } catch (err) {
          if (cronNotifyRun) {
            console.log('NO_REPLY');
            process.exitCode = 0;
            return;
          }
          console.error(`! Could not register AgentGuard agent: ${(err as Error).message}`);
          process.exitCode = 1;
          return;
        }
      }

      if (!cronInternalRun) {
        try {
          await client.subscribeFeed();
        } catch (err) {
          if (err instanceof CloudRequestError && err.status === 401) {
            if (!isAgentJwtHostConfigured(config)) {
              console.error('! AgentGuard Cloud credential was rejected. Run `agentguard connect --key <key>` again.');
              process.exitCode = 1;
              return;
            }
            try {
              registration = await registerAgentCredential({
                cloudUrl: config.cloudUrl,
                reason: 'subscribe',
                notifyOpenClaw: resolveCronAgentHost(config) === 'openclaw',
                resetExistingJwt: true,
              });
              config = registration.config;
              client = registration.client;
              await client.subscribeFeed();
            } catch (retryErr) {
              printAgentActivationRequired(registration, retryErr);
              process.exitCode = 1;
              return;
            }
          } else {
            console.error(`! Could not subscribe to AgentGuard Cloud feed: ${(err as Error).message}`);
            process.exitCode = 1;
            return;
          }
        }
      }

      if (registration && !cronNotifyRun && !quiet && !options.json) {
        printAgentRegistrationNotice(registration);
      }

      let advisories: Advisory[] | null;
      try {
        advisories = await client.pullAdvisories(since);
      } catch (err) {
        if (err instanceof CloudRequestError && err.status === 401) {
          if (cronInternalRun) {
            await printSubscribeConnectRequired(options, cronRunSendsToOpenClaw);
            process.exitCode = 1;
            return;
          }
          if (!isAgentJwtHostConfigured(config)) {
            console.error('! AgentGuard Cloud credential was rejected. Run `agentguard connect --key <key>` again.');
            process.exitCode = 1;
            return;
          }
          try {
            registration = await registerAgentCredential({
              cloudUrl: config.cloudUrl,
              reason: 'subscribe',
              notifyOpenClaw: resolveCronAgentHost(config) === 'openclaw',
              resetExistingJwt: true,
            });
            config = registration.config;
            client = registration.client;
            advisories = await client.pullAdvisories(since);
          } catch (retryErr) {
            if (cronNotifyRun) {
              console.log('NO_REPLY');
              process.exitCode = 0;
              return;
            }
            printAgentActivationRequired(registration, retryErr);
            process.exitCode = 1;
            return;
          }
        } else {
          if (cronNotifyRun) {
            console.log('NO_REPLY');
            process.exitCode = 0;
            return;
          }
          console.error(`! Could not reach AgentGuard Cloud: ${(err as Error).message}`);
          process.exitCode = 1;
          return;
        }
      }
      if (advisories === null) {
        // 404 — older Cloud build without the feed endpoint. Not an error.
        if (cronNotifyRun) {
          console.log('NO_REPLY');
        } else if (options.json) {
          console.log(JSON.stringify({ supported: false, shouldNotify: false, results: [], cron: { requested: false, installed: false } }));
        } else if (!quiet) {
          console.log('AgentGuard Cloud does not expose /api/v1/feed/advisories yet — nothing to do.');
        }
        return;
      }

      const seen = new Set(getSeenAdvisoryIds(state));
      // Process oldest-first so output stays deterministic when Cloud returns
      // multiple fresh advisories.
      const fresh = advisories
        .filter((a) => !seen.has(a.id))
        .sort((a, b) => (a.publishedAt < b.publishedAt ? -1 : 1));
      const results: SelfCheckResult[] = [];
      let hardFailures = 0;
      const newSeenIds: string[] = [];
      const foundIds: string[] = [];
      const pulledAt = new Date().toISOString();

      if (quiet) {
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
            continue;
          }
          results.push(result);

          if (options.report !== false && client.connected && result.matchedArtifacts.length > 0) {
            // Report is on the critical path — if Cloud doesn't see the
            // match, we must NOT mark the advisory seen, otherwise a
            // transient network blip silently buries a real hit.
            try {
              if (cronInternalRun) {
                await client.reportSelfCheck(advisory.id, result.matchedArtifacts, {
                  elapsedMs: result.elapsedMs,
                  warnings: result.warnings,
                });
              } else {
                const reportResult = await runCloudRequestWithAgentJwtReauth({
                  config,
                  client,
                  reason: 'reauth',
                  notifyOpenClaw: resolveCronAgentHost(config) === 'openclaw',
                  operation: (activeClient) => activeClient.reportSelfCheck(advisory.id, result.matchedArtifacts, {
                    elapsedMs: result.elapsedMs,
                    warnings: result.warnings,
                  }),
                });
                config = reportResult.config;
                client = reportResult.client;
                if (reportResult.registration) registration = reportResult.registration;
              }
            } catch (err) {
              if (cronInternalRun && err instanceof CloudRequestError && err.status === 401) {
                await printSubscribeConnectRequired(options, cronRunSendsToOpenClaw);
                process.exitCode = 1;
                return;
              }
              console.error(`! Failed to report self-check for ${advisory.id}: ${(err as Error).message}`);
              processed = false;
              hardFailures += 1;
            }
          }

          if (processed) {
            newSeenIds.push(advisory.id);
            if (result.matchedArtifacts.length > 0) {
              foundIds.push(advisory.id);
            }
          } else {
            // Failed advisories are left out of newSeenIds, so the ID-based
            // state will re-process them on the next subscribe run.
          }
        }
      } else {
        for (const advisory of fresh) {
          newSeenIds.push(advisory.id);
        }
      }

      const pendingStateEntry = newSeenIds.length > 0 || foundIds.length > 0
        ? {
            pulledAt,
            newSeenIds,
            foundIds,
          }
        : null;

      const totalMatches = results.reduce((acc, r) => acc + r.matchedArtifacts.length, 0);
      const summary = buildSubscribeSummary({
        supported: true,
        pulled: advisories.length,
        fresh: fresh.length,
        freshAdvisories: fresh,
        results,
        hardFailures,
        quiet,
      });

      if (options.cron && !options.cronRun) {
        summary.cron.requested = true;
        try {
          summary.cron.result = await installThreatFeedCron({
            name: options.cronName as string,
            cronExpression: cronExpression!,
            quiet,
            force: Boolean(options.force),
            backend: cronTarget,
            agentHost: resolveCronAgentHost(config),
            agentGuardHome: getAgentGuardPaths().home,
          }, {
            gateway: resolveOpenClawGatewayOptionsFromEnv(),
          });
          saveConfig({
            ...config,
            threatFeedCronName: summary.cron.result.name,
            threatFeedCronInstalledAt: new Date().toISOString(),
          });
          summary.cron.installed = true;
        } catch (err) {
          summary.cron.error = (err as Error).message;
          throw err;
        }
      }

      if (cronRunSendsToOpenClaw) {
        if (summary.shouldNotify && summary.hardFailures === 0) {
          const body = summary.notification?.body;
          if (!body) {
            console.error('! OpenClaw cron notification was requested, but no notification body was generated.');
            process.exitCode = 1;
            return;
          }
          const notification = await notifyOpenClawMessage(body, resolveOpenClawGatewayOptionsFromEnv(), {
            idempotencyKeyPrefix: 'agentguard-subscribe',
          });
          if (!notification.notified) {
            console.error(`! Could not send OpenClaw cron notification: ${notification.reason ?? 'Unknown error'}`);
            process.exitCode = 1;
            return;
          }
        }
        if (pendingStateEntry) {
          saveFeedState(prependFeedStateEntry(state, pendingStateEntry));
        }
        console.log('NO_REPLY');
        process.exitCode = hardFailures > 0 ? 1 : 0;
        return;
      }

      if (cronInternalRun && cronAgentHost === 'dsh' && summary.shouldNotify) {
        const agentGuardHome = getAgentGuardPaths().home;
        const subscription = await loadDshThreatFeedSubscription(agentGuardHome);
        if (!subscription) {
          throw new Error('DSH threat-feed subscription state is missing. Run the DSH subscribe tool again.');
        }
        if (subscription.selfCheck !== quiet) {
          throw new Error('DSH threat-feed subscription mode does not match the cron runner. Run the DSH subscribe tool again.');
        }
        const notification = buildDshThreatFeedNotification({
          subscription,
          freshAdvisories: fresh,
          results,
          selfCheck: quiet,
        });
        if (notification) {
          await enqueueDshThreatFeedNotification(notification, agentGuardHome);
        }
      }

      if (pendingStateEntry) {
        saveFeedState(prependFeedStateEntry(state, pendingStateEntry));
      }

      if (cronNotifyRun) {
        console.log(summary.shouldNotify && summary.hardFailures === 0 ? summary.notification?.body ?? 'NO_REPLY' : 'NO_REPLY');
        process.exitCode = 0;
        return;
      }

      if (options.json) {
        console.log(JSON.stringify(summary, null, 2));
        return;
      }

      if (quiet && fresh.length === 0 && !summary.cron.result) {
        process.exitCode = 0;
        return;
      }

      console.log(`Pulled ${advisories.length} advisory record(s); ${fresh.length} new.`);
      if (!quiet && fresh.length > 0) {
        console.log(summary.notification?.body ?? formatNewAdvisoryNotification(fresh));
      } else if (quiet && (fresh.length > 0 || summary.cron.result)) {
        console.log(`Self-check found ${totalMatches} match(es) across ${fresh.length} new advisory record(s).`);
        for (const r of results) {
          if (r.matchedArtifacts.length === 0) continue;
          console.log(`  - ${r.advisoryId}: ${r.matchedArtifacts.length} match(es)`);
          for (const m of r.matchedArtifacts) {
            console.log(`      · ${m.path}  [${m.matchedBy}]`);
          }
        }
      }
      if (summary.cron.result) {
        const label = summary.cron.result.backend ?? 'cron';
        const action = summary.cron.result.created ? `Installed ${label} cron job` : `${label} cron job already exists and was left unchanged`;
        console.log(`${action} "${summary.cron.result.name}" (${summary.cron.result.schedule}, ${summary.cron.result.timezone}).`);
        if (!summary.cron.result.created) {
          console.log('Existing cron jobs are not reconfigured unless --force is passed; rerun with --force to apply the requested quiet/manual mode and schedule.');
        }
        if (summary.cron.result.backend === 'system' || summary.cron.result.backend === 'windows-task-scheduler') {
          console.log(`Scheduled task output: ${join(getAgentGuardPaths().home, 'feed-cron.log')}`);
        } else {
          console.log('Notification rule: non-quiet cron notifies on new advisories; quiet cron notifies on local matches.');
        }
      }

      // Exit codes: 2 = matches found, 1 = at least one advisory failed
      // to evaluate or report, 0 = clean.
      if (hardFailures > 0) {
        console.error(`! ${hardFailures} advisory record(s) failed to process and will be re-pulled next run.`);
        process.exitCode = 1;
      } else if (quiet && totalMatches > 0) {
        process.exitCode = 2;
      } else {
        process.exitCode = 0;
      }
    });

  program
    .command('checkup')
    .description('Run a local agent health checkup. Use --against-advisory only for targeted threat-feed self-checks.')
    .option('--against-advisory <id>', 'Restrict the check to a single advisory id (fetches it from Cloud if needed)')
    .option('--json', 'Emit machine-readable result')
    .action(async (options) => {
      let config = ensureConfig();
      const advisoryId = options.againstAdvisory as string | undefined;

      if (!advisoryId) {
        const report = await runLocalHealthCheckup(config);
        if (options.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          const htmlPath = await generateCheckupHtml(report).catch((err) => {
            console.error(`! Could not generate visual checkup report: ${(err as Error).message}`);
            return null;
          });
          printHealthCheckupSummary(report, htmlPath);
          printInitGuidanceIfNeeded(config);
        }
        appendCheckupAudit(config.auditPath, report);
        process.exitCode = 0;
        return;
      }

      let client = new AgentGuardCloudClient(config);
      if (!client.connected) {
        const message = 'AgentGuard Cloud is not connected. Run `agentguard connect` first.';
        if (options.json) {
          console.log(JSON.stringify({ success: false, error: message }, null, 2));
        } else {
          console.error(message);
        }
        process.exitCode = 1;
        return;
      }

      let advisory: Advisory | null = null;
      try {
        const result = await runCloudRequestWithAgentJwtReauth({
          config,
          client,
          reason: 'reauth',
          notifyOpenClaw: true,
          operation: (activeClient) => activeClient.getAdvisory(advisoryId),
        });
        config = result.config;
        client = result.client;
        advisory = result.value;
      } catch (err) {
        const message = `Could not reach AgentGuard Cloud: ${(err as Error).message}`;
        if (options.json) {
          console.log(JSON.stringify({ success: false, error: message }, null, 2));
        } else {
          console.error(`! ${message}`);
        }
        process.exitCode = 1;
        return;
      }
      if (!advisory) {
        console.error(`No advisory with id "${advisoryId}" found in AgentGuard Cloud.`);
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

  if (process.argv.length <= 2) {
    printInstalledGuidance();
    return;
  }

  await program.parseAsync(process.argv);
}

function validateCronTarget(value: unknown): CronBackend {
  if (value === 'auto' || value === 'openclaw' || value === 'qclaw' || value === 'hermes' || value === 'system' || value === 'windows') return value;
  throw new Error('Invalid cron target. Use auto, openclaw, qclaw, hermes, system, or windows.');
}

function initAutoAgents(config: AgentGuardConfig, force: boolean): {
  installed: InstallResult[];
  failed: Array<{ agent: AgentInstaller; error: string }>;
  detected: AgentInstaller[];
} {
  const installed: InstallResult[] = [];
  const failed: Array<{ agent: AgentInstaller; error: string }> = [];
  const directoryAgents = AUTO_AGENT_DETECTION
    .filter(({ dir }) => existsSync(join(process.cwd(), dir)))
    .map(({ agent }) => agent);
  const isDshManagedShell = detectDshManagedShell();
  const dshAgents: AgentInstaller[] = isDshManagedShell || detectInstalledDshWebProfile() ? ['dsh'] : [];
  const detectedAgents: AgentInstaller[] = isDshManagedShell
    ? [...dshAgents, ...directoryAgents]
    : [...directoryAgents, ...dshAgents];

  for (const agent of detectedAgents) {
    try {
      installed.push(installAgentTemplates(agent, { cwd: process.cwd(), force }));
    } catch (err) {
      failed.push({
        agent,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  if (installed.length > 0) {
    config.agentHosts = installed.map((result) => result.agent);
    config.agentHost = installed[0].agent;
    saveConfig(config);
  }

  return { installed, failed, detected: detectedAgents };
}

function printInstallResult(result: InstallResult): void {
  if (result.agent === 'dsh') {
    console.log('Installed dsh integration in profile web.');
    console.log('Restart DSH to activate AgentGuard in that profile.');
    return;
  }
  console.log(`Installed ${result.agent} template:`);
  for (const file of result.files) console.log(`- ${file}`);
}

function appendAgentHost(
  agentHosts: AgentGuardConfig['agentHosts'] | undefined,
  agent: AgentGuardAgentHost
): AgentGuardAgentHost[] {
  const next = agentHosts ? [...agentHosts] : [];
  if (!next.includes(agent)) next.push(agent);
  return next;
}

function hasSavedAgentHost(config: AgentGuardConfig): boolean {
  return Boolean(config.agentHost || config.agentHosts?.length);
}

function printInstalledGuidance(): void {
  console.log('AgentGuard is installed.');
  console.log('');
  console.log('Required next step:');
  console.log(`  ${REQUIRED_INIT_COMMAND}`);
  console.log('');
  console.log('This detects installed agent directories and configures supported hooks/plugins.');
  console.log('Run `agentguard --help` to see all commands.');
}

function printHermesNativePluginEnabled(): void {
  console.log('');
  console.log('Hermes native plugin enabled in config.yaml.');
  console.log('It takes effect on the next Hermes session.');
  console.log('Use `hermes plugins list` to verify, or re-run with --shell-hooks for the legacy shell-hook flow.');
}

function printInitGuidanceIfNeeded(config: AgentGuardConfig): void {
  if (hasSavedAgentHost(config)) return;
  console.log('');
  console.log('Required next step:');
  console.log(`  ${REQUIRED_INIT_COMMAND}`);
}

function printCloudAuthStatus(config: AgentGuardConfig): void {
  if (config.agentJwt) {
    console.log('Cloud auth: connected via Agent JWT');
    console.log('API key: not used for this connection');
    console.log(`Agent ID: ${config.agentId || 'configured'}`);
    console.log('Agent JWT: configured');
    if (config.agentRegisterUrl) {
      console.log('Agent account: not bound (activation required)');
      console.log(`Agent activation URL: ${config.agentRegisterUrl}`);
    } else {
      console.log('Agent account: bound');
      console.log('Agent activation URL: not required');
    }
    return;
  }
  if (config.apiKey) {
    console.log('Cloud auth: connected via API key');
    console.log(`API key: ${maskApiKey(config.apiKey)}`);
    console.log('Agent JWT: not used for this connection');
    return;
  }

  console.log('Cloud auth: not connected');
  console.log('API key: not configured');
  console.log('Agent JWT: not configured');
}

function networkDefaultOutboundWarning(value: string): string | undefined {
  if (value !== 'block' && value !== 'require_approval') return undefined;
  return `network.defaultOutbound is ${value}; ordinary external GET/HEAD/OPTIONS requests may be interrupted unless domains are explicitly allowed.`;
}

async function printSubscribeConnectRequired(
  options: { json?: boolean; cronNotifyRun?: boolean },
  notifyOpenClaw: boolean
): Promise<void> {
  const message = 'AgentGuard Cloud credential was rejected. Run `agentguard connect` again before the next subscribe cron run.';
  if (notifyOpenClaw) {
    const notification = await notifyOpenClawMessage(message, resolveOpenClawGatewayOptionsFromEnv(), {
      idempotencyKeyPrefix: 'agentguard-subscribe-auth',
    });
    if (notification.notified) {
      console.log('NO_REPLY');
      return;
    }
    console.error(`! Could not send OpenClaw cron auth notification: ${notification.reason ?? 'Unknown error'}`);
    return;
  }
  if (options.cronNotifyRun) {
    console.log(message);
  } else if (options.json) {
    console.log(JSON.stringify({ success: false, error: message }, null, 2));
  } else {
    console.error(`! ${message}`);
  }
}

async function refreshAgentAccountBinding(config: AgentGuardConfig): Promise<AgentGuardConfig> {
  if (!config.agentJwt || !config.agentRegisterUrl) return config;
  const client = new AgentGuardCloudClient(config);
  try {
    const policy = await client.fetchEffectivePolicy();
    const activeConfig = clearAgentRegisterUrl(config);
    saveCachedPolicy(activeConfig.policyCachePath, policy);
    return activeConfig;
  } catch {
    return config;
  }
}

function printCronRemovalSummary(results: ThreatFeedCronRemovalResult[]): void {
  const removed = results.filter((result) => result.removed);
  if (removed.length > 0) {
    console.log(`Removed AgentGuard subscribe cron job "${removed[0]!.name}" from: ${removed.map((result) => result.backend).join(', ')}.`);
    return;
  }

  const errors = results.filter((result) => result.error);
  if (errors.length > 0) {
    console.log('No AgentGuard subscribe cron job was removed; some cron backends were unavailable.');
    for (const result of errors) {
      console.error(`! ${result.backend}: ${result.error}`);
    }
    return;
  }

  console.log('No AgentGuard subscribe cron job was found.');
}

function resolveCronAgentHost(config: AgentGuardConfig): AgentGuardAgentHost | undefined {
  return config.agentHost ?? config.agentHosts?.[0];
}

function readStdinIfAvailable(): string {
  if (process.stdin.isTTY) return '';
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

interface CheckupFinding {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  text: string;
}

interface CheckupDimension {
  score: number | null;
  na?: boolean;
  findings: CheckupFinding[];
  details: string;
}

interface HealthCheckupReport {
  timestamp: string;
  composite_score: number;
  tier: 'S' | 'A' | 'B' | 'F';
  dimensions: {
    code_safety: CheckupDimension;
    credential_safety: CheckupDimension;
    network_exposure: CheckupDimension;
    runtime_protection: CheckupDimension;
    web3_safety: CheckupDimension;
  };
  skills_scanned: number;
  dsh_plugins_scanned: number;
  dsh_plugins: DshCheckupPluginResult[];
  protection_level: string;
  analysis: string;
  recommendations: CheckupFinding[];
}

async function runLocalHealthCheckup(config: AgentGuardConfig): Promise<HealthCheckupReport> {
  const skillRoots = [
    join(homedir(), '.claude', 'skills'),
    join(homedir(), '.codex', 'skills'),
    join(homedir(), '.openclaw', 'skills'),
    join(homedir(), '.openclaw', 'workspace', 'skills'),
    join(homedir(), '.qclaw', 'skills'),
    join(homedir(), '.qclaw', 'workspace', 'skills'),
    join(homedir(), '.hermes', 'skills'),
  ];
  const dshRoots = await discoverDshSelfCheckRoots();
  const skillDirs = discoverSkillDirs([...skillRoots, ...dshRoots.skillRoots]);
  const dshPluginDirs = dshRoots.installedPluginDirs;
  const scanner = new SkillScanner({ useExternalScanner: false });
  const registry = new SkillRegistry();
  const registrySnapshot = await registry.list({ include_expired: true })
    .then((records) => normalizeTrustRecords(records))
    .catch(() => null);
  const registryRecords = registrySnapshot?.records ?? null;
  const patrolFileCollection = collectPatrolFiles([...dshRoots.skillRoots, ...dshPluginDirs]);
  const patrolFiles = patrolFileCollection.files;

  const codeFindings: CheckupFinding[] = [];
  let codeScore = skillDirs.length === 0 && dshPluginDirs.length === 0 ? 70 : 100;
  if (skillDirs.length === 0 && dshPluginDirs.length === 0) {
    codeFindings.push({ severity: 'LOW', text: 'No installed third-party skills or DSH plugins were found to audit.' });
  }
  for (const dir of skillDirs) {
    const name = dir.split(/[\\/]/).pop() || dir;
    try {
      const result = await scanner.quickScan(dir);
      if (result.risk_level === 'critical') codeScore -= 15;
      if (result.risk_level === 'high') codeScore -= 8;
      if (result.risk_level === 'medium') codeScore -= 3;
      if (result.risk_level !== 'low') {
        codeFindings.push({
          severity: riskLevelToSeverity(result.risk_level),
          text: `[Patrol 1] ${name}: ${result.summary}${result.risk_tags.length ? ` (${result.risk_tags.join(', ')})` : ''}`,
        });
      }
      const artifactHash = await scanner.calculateArtifactHash(dir);
      const sourceRecords = registryRecords?.filter((record) => record.skill.source === dir) ?? [];
      const matchingRecord = sourceRecords.find((record) => record.skill.artifact_hash === artifactHash);
      const integrityFinding = registryRecords === null
        ? patrolFinding(1, 'HIGH', `Trust metadata for installed skill ${name} could not be inspected.`)
        : sourceRecords.length === 0
          ? patrolFinding(1, 'MEDIUM', `Installed skill ${name} has no trust-registry record.`)
          : !matchingRecord
            ? patrolFinding(1, 'HIGH', `Installed skill ${name} no longer matches its recorded artifact hash.`)
            : null;
      if (integrityFinding) {
        codeFindings.push(integrityFinding);
        codeScore -= findingScoreDeduction([integrityFinding]);
      }
    } catch {
      const finding = patrolFinding(1, 'HIGH', `Installed skill ${name} could not be scanned safely.`);
      codeFindings.push(finding);
      codeScore -= findingScoreDeduction([finding]);
    }
  }
  const dshScan = await scanDshPluginsForCheckup(dshPluginDirs);
  codeScore -= dshScan.scoreDeduction;
  codeFindings.push(...dshScan.findings.map((finding) => ({
    ...finding,
    text: `[Patrol 1] ${finding.text}`,
  })));
  for (const dir of dshPluginDirs) {
    const name = dir.split(/[\\/]/).pop() || dir;
    try {
      const artifactHash = await scanner.calculateArtifactHash(dir);
      const sourceRecords = registryRecords?.filter((record) => record.skill.source === dir) ?? [];
      const matchingRecord = sourceRecords.find((record) => record.skill.artifact_hash === artifactHash);
      const integrityFinding = registryRecords === null
        ? patrolFinding(1, 'HIGH', `Trust metadata for installed DSH plugin ${name} could not be inspected.`)
        : sourceRecords.length === 0
          ? patrolFinding(1, 'MEDIUM', `Installed DSH plugin ${name} has no trust-registry record.`)
          : !matchingRecord
            ? patrolFinding(1, 'HIGH', `Installed DSH plugin ${name} no longer matches its recorded artifact hash.`)
            : null;
      if (integrityFinding) {
        codeFindings.push(integrityFinding);
        codeScore -= findingScoreDeduction([integrityFinding]);
      }
    } catch {
      const finding = patrolFinding(1, 'HIGH', `Installed DSH plugin ${name} could not be hashed safely.`);
      codeFindings.push(finding);
      codeScore -= findingScoreDeduction([finding]);
    }
  }
  const recentFileFindings = await checkRecentFilesystemChanges(patrolFileCollection, scanner);
  const installedSources = new Set([...skillDirs, ...dshPluginDirs]);
  const trustFindings = checkTrustRegistryHealth(
    registryRecords,
    registrySnapshot?.invalidRecords ?? (registrySnapshot === null ? 1 : 0),
    installedSources,
  );
  codeFindings.push(...recentFileFindings, ...trustFindings);
  codeScore -= findingScoreDeduction([...recentFileFindings, ...trustFindings]);
  codeScore = clampScore(codeScore);

  const credential = await checkCredentialSafety(skillDirs, patrolFileCollection);
  const networkExposure = await checkNetworkExposure();
  const schedulerFindings = await checkScheduledTaskSafety();
  const network = combineCheckupDimension(networkExposure, schedulerFindings, 'network and scheduled-task');
  const runtimeProtection = checkRuntimeProtection(config, skillDirs.length);
  const auditFindings = checkAuditLogSafety(config.auditPath);
  const configurationFindings = checkEnvironmentConfiguration(config);
  const runtime = combineCheckupDimension(
    runtimeProtection,
    [...auditFindings, ...configurationFindings],
    'runtime, audit, and configuration',
  );
  const web3 = checkWeb3Safety(skillDirs);

  const dimensions = {
    code_safety: {
      score: codeScore,
      findings: codeFindings,
      details: `${skillDirs.length} installed skill(s) and ${dshScan.pluginsScanned} DSH plugin(s) scanned with AgentGuard rules.`,
    },
    credential_safety: credential,
    network_exposure: network,
    runtime_protection: runtime,
    web3_safety: web3,
  };
  const composite = calculateCompositeScore(dimensions);
  const recommendations = Object.values(dimensions)
    .flatMap((d) => d.findings)
    .filter((f) => f.severity !== 'LOW')
    .slice(0, 8);

  return {
    timestamp: new Date().toISOString(),
    composite_score: composite,
    tier: tierForScore(composite),
    dimensions,
    skills_scanned: skillDirs.length,
    protection_level: config.level,
    analysis: buildHealthAnalysis(composite, dimensions),
    recommendations,
    dsh_plugins_scanned: dshScan.pluginsScanned,
    dsh_plugins: dshScan.plugins,
  };
}

function discoverSkillDirs(roots: string[]): string[] {
  const dirs: string[] = [];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    let entries;
    try {
      entries = readdirSync(root, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
      const dir = join(root, entry.name);
      try {
        if (!statSync(dir).isDirectory()) continue;
      } catch {
        continue;
      }
      if (!existsSync(join(dir, 'SKILL.md'))) continue;
      if (isManagedAgentGuardSkillDir(dir)) continue;
      dirs.push(dir);
    }
  }
  return dirs;
}

function isManagedAgentGuardSkillDir(dir: string): boolean {
  if (!/[/\\]agentguard$/i.test(dir)) return false;
  const manifest = join(dir, 'SKILL.md');
  let body = '';
  try {
    body = readFileSync(manifest, 'utf8').slice(0, 16 * 1024);
  } catch {
    return false;
  }
  const hasAgentGuardIdentity = /^name:\s*agentguard\s*$/im.test(body) &&
    /GoPlus AgentGuard|GoPlusSecurity/i.test(body);
  if (!hasAgentGuardIdentity) return false;
  const expectedScripts = [
    join(dir, 'scripts', 'guard-hook.js'),
    join(dir, 'scripts', 'hermes-hook.js'),
    join(dir, 'scripts', 'checkup-report.js'),
  ];
  if (!expectedScripts.every((path) => existsSync(path))) return false;

  return true;
}

interface PatrolFile {
  path: string;
  mtimeMs: number;
  size: number;
}

interface PatrolFileCollection {
  files: PatrolFile[];
  truncated: boolean;
  traversalErrors: number;
}

function patrolFinding(check: number, severity: CheckupFinding['severity'], text: string): CheckupFinding {
  return { severity, text: `[Patrol ${check}] ${text}` };
}

function findingScoreDeduction(findings: CheckupFinding[]): number {
  return findings.reduce((total, finding) => total + (
    finding.severity === 'CRITICAL' ? 25 :
      finding.severity === 'HIGH' ? 15 :
        finding.severity === 'MEDIUM' ? 8 : 2
  ), 0);
}

function combineCheckupDimension(
  base: CheckupDimension,
  additions: CheckupFinding[],
  label: string,
): CheckupDimension {
  const findings = [...base.findings, ...additions];
  return {
    score: clampScore((base.score ?? 100) - findingScoreDeduction(additions)),
    findings,
    details: findings.length ? `${findings.length} ${label} issue(s) found.` : `No ${label} issues found.`,
  };
}

function collectPatrolFiles(additionalRoots: string[] = []): PatrolFileCollection {
  const roots = [...new Set([
    join(homedir(), '.claude'),
    join(homedir(), '.codex'),
    join(homedir(), '.openclaw'),
    join(homedir(), '.qclaw'),
    join(homedir(), '.hermes'),
    join(homedir(), '.ssh'),
    join(homedir(), '.gnupg'),
    ...additionalRoots,
  ])];
  const files: PatrolFile[] = [];
  const pending = roots.filter(existsSync);
  let totalBytes = 0;
  let traversalErrors = 0;
  let skippedForLimits = false;
  while (pending.length > 0 && files.length < 1000 && totalBytes < 8 * 1024 * 1024) {
    const directory = pending.shift()!;
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      traversalErrors += 1;
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        traversalErrors += 1;
        continue;
      }
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!['node_modules', '.git', 'dist', 'coverage'].includes(entry.name)) pending.push(path);
        continue;
      }
      if (!entry.isFile()) continue;
      try {
        const info = statSync(path);
        if (info.size > 512 * 1024 || totalBytes + info.size > 8 * 1024 * 1024) {
          skippedForLimits = true;
          continue;
        }
        files.push({ path, mtimeMs: info.mtimeMs, size: info.size });
        totalBytes += info.size;
        if (files.length >= 1000) break;
      } catch {
        traversalErrors += 1;
        continue;
      }
    }
  }
  return {
    files,
    truncated: skippedForLimits || pending.length > 0 || files.length >= 1000 || totalBytes >= 8 * 1024 * 1024,
    traversalErrors,
  };
}

function readPatrolFile(file: PatrolFile): string {
  if (file.size > 512 * 1024) return '';
  try {
    return readFileSync(file.path, 'utf8');
  } catch {
    return '';
  }
}

async function checkCredentialSafety(skillDirs: string[], collection: PatrolFileCollection): Promise<CheckupDimension> {
  let score = 100;
  const findings: CheckupFinding[] = [];
  const patrolFiles = collection.files;
  const privateDirectories = [join(homedir(), '.ssh'), join(homedir(), '.gnupg')];
  if (process.platform === 'win32') {
    findings.push(...await checkWindowsAclExposure(privateDirectories, 2));
  } else {
    for (const [path, severity] of [
      [privateDirectories[0], 'HIGH'],
      [privateDirectories[1], 'MEDIUM'],
    ] as const) {
      const mode = permissionMode(path);
      if (mode !== null && mode > 0o700) {
        findings.push(patrolFinding(2, severity, `${path} permissions are ${mode.toString(8)}; expected 700 or stricter.`));
      }
    }
  }

  const secretPatterns = [
    { re: /(?:\bprivate[_ -]?key\b\s*[:=]\s*['"]?0x[a-fA-F0-9]{64}\b|['"]0x[a-fA-F0-9]{64}['"]|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i, severity: 'CRITICAL' as const, label: 'Plaintext private key pattern' },
    { re: /\b(seed_phrase|mnemonic)\b\s*[:=]\s*['"][^'"\r\n]{16,}/i, severity: 'CRITICAL' as const, label: 'Mnemonic or seed phrase assignment' },
    { re: /\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}\b/, severity: 'HIGH' as const, label: 'API key or token pattern' },
  ];
  for (const dir of skillDirs) {
    const manifest = join(dir, 'SKILL.md');
    if (!existsSync(manifest)) continue;
    let body = '';
    try {
      body = readFileSync(manifest, 'utf8').slice(0, 256 * 1024);
    } catch {
      continue;
    }
    for (const pattern of secretPatterns) {
      if (!pattern.re.test(body)) continue;
      findings.push(patrolFinding(2, pattern.severity, `${pattern.label} found in ${manifest}.`));
    }
  }
  const inspected = new Set(skillDirs.map((dir) => join(dir, 'SKILL.md')));
  for (const file of patrolFiles) {
    if (inspected.has(file.path) || isInsideManagedAgentGuardSkill(file.path) || !isSecurityRelevantPatrolFile(file.path)) continue;
    const body = readPatrolFile(file);
    for (const pattern of secretPatterns) {
      if (!pattern.re.test(body)) continue;
      findings.push(patrolFinding(2, pattern.severity, `${pattern.label} found in ${file.path}.`));
      break;
    }
  }
  if (collection.truncated || collection.traversalErrors > 0) {
    findings.push(patrolFinding(2, 'MEDIUM', 'Credential scanning coverage was incomplete because one or more agent files could not be enumerated within safety limits.'));
  }
  score -= findingScoreDeduction(findings);
  return {
    score: clampScore(score),
    findings,
    details: findings.length ? `${findings.length} credential hygiene issue(s) found.` : 'Credential permissions and scanned manifests look clean.',
  };
}

function isInsideManagedAgentGuardSkill(path: string): boolean {
  const match = path.match(/^(.*[\\/]skills[\\/]agentguard)(?:[\\/]|$)/i);
  return Boolean(match && isManagedAgentGuardSkillDir(match[1]));
}

async function checkWindowsAclExposure(paths: string[], patrolCheck: number): Promise<CheckupFinding[]> {
  const findings: CheckupFinding[] = [];
  for (const path of paths) {
    if (!existsSync(path)) continue;
    const result = await runCommandText('icacls.exe', [path]);
    if (!result.available) {
      findings.push(patrolFinding(patrolCheck, 'MEDIUM', `Windows ACLs for ${path} could not be inspected with icacls.exe.`));
      continue;
    }
    if (/(?:Everyone|Authenticated Users|BUILTIN\\Users|\*S-1-1-0|\*S-1-5-11|\*S-1-5-32-545):(?:\([^\r\n)]*\))*\([^\r\n)]*[FMWR]/i.test(result.output)) {
      findings.push(patrolFinding(patrolCheck, 'HIGH', `${path} grants broad Windows account groups access to security-sensitive data.`));
    }
  }
  return findings;
}

function isSecurityRelevantPatrolFile(path: string): boolean {
  return /(?:^|[\\/])\.env[^\\/]*$|\.(?:js|cjs|mjs|ts|py|sh|md|json|ya?ml|toml|txt|log)$/i.test(path);
}

async function checkNetworkExposure(): Promise<CheckupDimension> {
  const findings: CheckupFinding[] = [];
  const listenerResult = process.platform === 'win32'
    ? await runCommandText('netstat.exe', ['-ano'])
    : await firstAvailableCommand([
      ['lsof', ['-i', '-P', '-n']],
      ['ss', ['-tlnp']],
    ]);
  const listeners = listenerResult.output;
  if (!listenerResult.available) {
    findings.push(patrolFinding(3, 'MEDIUM', 'Network listeners could not be inspected with an available system collector.'));
  }
  for (const port of ['2375', '3306', '5432', '6379', '27017']) {
    const exposed = new RegExp(`(?:\\*|0\\.0\\.0\\.0|\\[?::\\]?):${port}\\b`).test(listeners);
    if (exposed) {
      findings.push(patrolFinding(3, 'HIGH', `High-risk service appears exposed on 0.0.0.0:${port}.`));
    }
  }

  const firewallResult = process.platform === 'win32'
    ? await runCommandText('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      'Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress',
    ])
    : await firstAvailableCommand([
      ['ufw', ['status']],
      ['iptables', ['-L', 'INPUT', '-n']],
    ]);
  if (!firewallResult.available) {
    findings.push(patrolFinding(3, 'MEDIUM', 'Firewall state could not be inspected with an available system collector.'));
  } else if (/Status:\s*inactive/i.test(firewallResult.output) || /Chain INPUT \(policy ACCEPT\)/i.test(firewallResult.output)) {
    findings.push(patrolFinding(3, 'MEDIUM', 'The host firewall appears inactive or has a default-accept inbound policy.'));
  } else if (process.platform === 'win32') {
    try {
      const parsed = JSON.parse(firewallResult.output || '[]') as Record<string, unknown> | Array<Record<string, unknown>>;
      const profiles = Array.isArray(parsed) ? parsed : [parsed];
      if (profiles.some((profile) => profile.Enabled === false)) {
        findings.push(patrolFinding(3, 'MEDIUM', 'One or more Windows Firewall profiles are disabled.'));
      }
    } catch {
      findings.push(patrolFinding(3, 'MEDIUM', 'Windows Firewall state was returned in an unreadable format.'));
    }
  }

  const outboundResult = process.platform === 'win32'
    ? await runCommandText('netstat.exe', ['-ao'])
    : await firstAvailableCommand([
      ['ss', ['-tp', 'state', 'established']],
      ['lsof', ['-i', '-P']],
    ]);
  if (!outboundResult.available) {
    findings.push(patrolFinding(3, 'MEDIUM', 'Established outbound connections could not be inspected.'));
  } else if (/(?:webhook\.site|requestbin\.|ngrok(?:-free)?\.|\.onion\b|\.(?:top|xyz|click|work)\b)/i.test(outboundResult.output)) {
    findings.push(patrolFinding(3, 'HIGH', 'An established connection references a known exfiltration service or high-risk domain.'));
  }

  return {
    score: clampScore(100 - findingScoreDeduction(findings)),
    findings,
    details: findings.length ? `${findings.length} network exposure issue(s) found.` : 'No dangerous public listeners were found.',
  };
}

async function checkScheduledTaskSafety(): Promise<CheckupFinding[]> {
  if (process.platform === 'win32') {
    const result = await runCommandText('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      'Get-ScheduledTask | Select-Object TaskName,TaskPath,@{n="UserId";e={$_.Principal.UserId}},@{n="LogonType";e={$_.Principal.LogonType}},@{n="RunLevel";e={$_.Principal.RunLevel}},@{n="Execute";e={($_.Actions.Execute -join " ")}},@{n="Arguments";e={($_.Actions.Arguments -join " ")}} | ConvertTo-Json -Compress',
    ]);
    if (!result.available) {
      return [patrolFinding(4, 'MEDIUM', 'Windows scheduled tasks could not be inspected with PowerShell.')];
    }
    let tasks: Array<Record<string, unknown>>;
    try {
      const parsed = JSON.parse(result.output || '[]') as Record<string, unknown> | Array<Record<string, unknown>>;
      tasks = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      return [patrolFinding(4, 'HIGH', 'Windows scheduled-task metadata was returned in an unreadable format.')];
    }
    const findings: CheckupFinding[] = [];
    const suspiciousCandidates = tasks.filter((task) => {
      const command = `${String(task.Execute || '')} ${String(task.Arguments || '')}`;
      return /agentguard/i.test(String(task.TaskName || '')) ||
        hasScheduledDownloadAndExecute(command) ||
        touchesAgentRoot(command);
    });
    const inspectable = suspiciousCandidates.slice(0, 20);
    if (suspiciousCandidates.length > inspectable.length) {
      findings.push(patrolFinding(4, 'MEDIUM', 'More suspicious Windows tasks were found than could be deeply inspected in one patrol.'));
    }
    for (const task of inspectable) {
      const command = `${String(task.Execute || '')} ${String(task.Arguments || '')}`;
      const taskName = `${String(task.TaskPath || '')}${String(task.TaskName || '')}`;
      if (hasScheduledDownloadAndExecute(command)) {
        findings.push(patrolFinding(4, 'CRITICAL', `Scheduled task ${taskName} contains a download-and-execute command pattern.`));
      }
      if (touchesAgentRoot(command) && !/agentguard(?:\.cmd)?["']?\s+checkup\s+--json/i.test(command)) {
        findings.push(patrolFinding(4, 'HIGH', `Unknown scheduled task ${taskName} modifies or inspects an agent installation root.`));
      }
      if (/agentguard/i.test(taskName) && String(task.RunLevel || '').toLowerCase() === 'highest') {
        findings.push(patrolFinding(4, 'HIGH', `AgentGuard-related scheduled task ${taskName} requests the highest run level.`));
      }
      if (/agentguard/i.test(taskName) && !/interactive/i.test(String(task.LogonType || ''))) {
        findings.push(patrolFinding(4, 'MEDIUM', `AgentGuard-related scheduled task ${taskName} is not configured for interactive-token logon.`));
      }
      const xml = await runCommandText('schtasks.exe', ['/Query', '/TN', taskName, '/XML']);
      if (!xml.available) {
        findings.push(patrolFinding(4, 'MEDIUM', `Scheduled task ${taskName} could not be verified through Task Scheduler XML.`));
      } else if (/agentguard/i.test(taskName) && /<RunLevel>HighestAvailable<\/RunLevel>/i.test(xml.output)) {
        findings.push(patrolFinding(4, 'HIGH', `AgentGuard-related scheduled task ${taskName} has a highest-privilege XML principal.`));
      }
    }
    return findings;
  }

  const [userCron, timers, openClawCron] = await Promise.all([
    runCommandText('crontab', ['-l']),
    runCommandText('systemctl', ['list-timers', '--all', '--no-pager']),
    runCommandText('openclaw', ['cron', 'list']),
  ]);
  const systemCron = readSystemCronText();
  const systemdDefinitions = timers.available
    ? await readSystemdTimerDefinitions(timers.output)
    : { available: false, output: '' };
  const available = userCron.available || timers.available || openClawCron.available || systemCron.available;
  if (!available) return [patrolFinding(4, 'MEDIUM', 'Scheduled tasks could not be inspected with an available system collector.')];
  const output = [userCron.output, timers.output, systemdDefinitions.output, openClawCron.output, systemCron.output].join('\n');
  const findings: CheckupFinding[] = [];
  if (hasScheduledDownloadAndExecute(output)) {
    findings.push(patrolFinding(4, 'CRITICAL', 'A scheduled task contains a download-and-execute command pattern.'));
  }
  if (/[^\r\n]*(?:\.ssh|authorized_keys)[^\r\n]*/i.test(output)) {
    findings.push(patrolFinding(4, 'HIGH', 'A scheduled task accesses SSH material.'));
  }
  const agentRootLines = output.split(/\r?\n/).filter((line) =>
    touchesAgentRoot(line) && !/agentguard(?:\.cmd)?["']?\s+checkup\s+--json/i.test(line));
  if (agentRootLines.length > 0) {
    findings.push(patrolFinding(4, 'HIGH', 'An unknown scheduled job modifies or inspects a detected agent installation root.'));
  }
  if (/\[(?:unreadable scheduled-task source|systemd timer coverage truncated)/i.test(output)) {
    findings.push(patrolFinding(4, 'MEDIUM', 'Scheduled-task coverage was incomplete because one or more system definitions could not be inspected.'));
  }
  return findings;
}

function hasScheduledDownloadAndExecute(text: string): boolean {
  return /(curl\b[^\r\n]*\|\s*(?:bash|sh)|wget\b[^\r\n]*\|\s*(?:bash|sh)|base64\s+-d[^\r\n]*\|\s*bash|eval\s*["'(]*\$?\(?curl)/i.test(text);
}

function touchesAgentRoot(text: string): boolean {
  return /(?:^|[\\/])\.(?:claude|codex|openclaw|qclaw|hermes|dsh)(?:[\\/]|\b)/i.test(text);
}

function readSystemCronText(): CommandTextResult {
  const paths = ['/etc/crontab'];
  try {
    if (existsSync('/etc/cron.d')) {
      for (const entry of readdirSync('/etc/cron.d', { withFileTypes: true })) {
        if (entry.isFile()) paths.push(join('/etc/cron.d', entry.name));
      }
    }
  } catch {
    // Keep any readable system crontab paths collected so far.
  }
  let available = false;
  const output: string[] = [];
  for (const path of paths.slice(0, 100)) {
    if (!existsSync(path)) continue;
    available = true;
    try {
      const info = statSync(path);
      if (info.isFile() && info.size <= 512 * 1024) output.push(readFileSync(path, 'utf8'));
      else output.push(`[unreadable scheduled-task source: ${path}]`);
    } catch {
      output.push(`[unreadable scheduled-task source: ${path}]`);
    }
  }
  return { available, output: output.join('\n') };
}

async function readSystemdTimerDefinitions(timerList: string): Promise<CommandTextResult> {
  const timerNames = [...new Set(
    [...timerList.matchAll(/\b([A-Za-z0-9@_.-]+\.timer)\b/g)].map((match) => match[1]),
  )];
  if (timerNames.length === 0) return { available: true, output: '' };
  const selected = timerNames.slice(0, 32);
  const timerResults = await Promise.all(selected.map((timer) => runCommandText('systemctl', ['cat', '--no-pager', timer])));
  const output = timerResults.filter((result) => result.available).map((result) => result.output);
  const serviceNames = new Set(selected.map((timer) => timer.replace(/\.timer$/, '.service')));
  for (const result of timerResults) {
    for (const match of result.output.matchAll(/^\s*Unit\s*=\s*([A-Za-z0-9@_.-]+\.service)\s*$/gmi)) {
      serviceNames.add(match[1]);
    }
  }
  const serviceResults = await Promise.all([...serviceNames].map((service) =>
    runCommandText('systemctl', ['cat', '--no-pager', service])));
  output.push(...serviceResults.filter((result) => result.available).map((result) => result.output));
  if (timerResults.some((result) => !result.available) || serviceResults.some((result) => !result.available)) {
    output.push('[unreadable scheduled-task source: systemd unit]');
  }
  if (timerNames.length > selected.length) output.push('[systemd timer coverage truncated]');
  return { available: true, output: output.join('\n') };
}

async function checkRecentFilesystemChanges(collection: PatrolFileCollection, scanner: SkillScanner): Promise<CheckupFinding[]> {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const findings: CheckupFinding[] = [];
  const recentFiles = collection.files.filter((file) => file.mtimeMs >= cutoff);
  let unreadable = 0;
  const scannable = recentFiles.filter((file) => isSecurityRelevantPatrolFile(file.path)).flatMap((file) => {
    const content = readPatrolFile(file);
    if (!content && file.size > 0) {
      unreadable += 1;
      return [];
    }
    return [{
      path: file.path,
      relativePath: relative(homedir(), file.path),
      content,
      extension: extname(file.path),
    }];
  });
  if (scannable.length > 0) {
    const snapshot: DirectoryScanSnapshot = {
      files: scannable,
      coverage: {
        discovered: scannable.length,
        scanned: scannable.length,
        skipped: unreadable + collection.traversalErrors + (collection.truncated ? 1 : 0),
        skippedByReason: {
          fileLimit: collection.truncated ? 1 : 0,
          oversized: 0,
          unreadable: unreadable + collection.traversalErrors,
        },
        complete: !collection.truncated && collection.traversalErrors === 0 && unreadable === 0,
      },
    };
    try {
      const result = await scanner.scan({
        skill: {
          id: 'agentguard-patrol-recent-files',
          source: homedir(),
          version_ref: 'current',
          artifact_hash: 'sha256:patrol-recent-files',
        },
        payload: { type: 'dir', ref: homedir() },
      }, snapshot);
      if (result.risk_level !== 'low') {
        const evidencePaths = [...new Set(result.evidence.map((evidence) => evidence.file))].slice(0, 5);
        findings.push(patrolFinding(
          5,
          riskLevelToSeverity(result.risk_level),
          `Recent-file scan found ${result.risk_tags.join(', ') || 'security-rule'} patterns${evidencePaths.length ? ` in ${evidencePaths.join(', ')}` : ''}.`,
        ));
      }
    } catch {
      findings.push(patrolFinding(5, 'HIGH', 'The complete security-rule scan of recently modified files could not finish.'));
    }
  }

  const sensitivePaths = [
    join(homedir(), '.openclaw', 'openclaw.json'),
    join(homedir(), '.openclaw', 'devices', 'paired.json'),
    join(homedir(), '.ssh', 'authorized_keys'),
  ];
  if (process.platform === 'win32') {
    findings.push(...await checkWindowsAclExposure(sensitivePaths, 5));
  } else {
    for (const path of sensitivePaths) {
      const mode = permissionMode(path);
      if (mode !== null && mode > 0o600) {
        findings.push(patrolFinding(5, 'MEDIUM', `${path} permissions are ${mode.toString(8)}; expected 600 or stricter.`));
      }
    }
  }
  if (process.platform !== 'win32') {
    for (const file of recentFiles) {
      if (!/[\\/]workspace(?:[\\/]|-)/i.test(file.path)) continue;
      try {
        if ((statSync(file.path).mode & 0o111) !== 0) {
          findings.push(patrolFinding(5, 'MEDIUM', `A recently modified workspace file is executable: ${file.path}.`));
        }
      } catch {
        continue;
      }
    }
  }
  if (collection.truncated || collection.traversalErrors > 0 || unreadable > 0) {
    findings.push(patrolFinding(5, 'MEDIUM', 'Recent-file patrol coverage was incomplete because one or more files could not be enumerated or read within safety limits.'));
  }
  return findings;
}

function checkAuditLogSafety(auditPath: string): CheckupFinding[] {
  if (!existsSync(auditPath)) {
    return [patrolFinding(6, 'MEDIUM', 'No AgentGuard audit log is available for the previous 24 hours.')];
  }
  let lines: string[];
  let truncated = false;
  try {
    const info = statSync(auditPath);
    const maxBytes = 16 * 1024 * 1024;
    const bytesToRead = Math.min(info.size, maxBytes);
    const buffer = Buffer.alloc(bytesToRead);
    const descriptor = openSync(auditPath, 'r');
    let bytesRead = 0;
    try {
      bytesRead = readSync(descriptor, buffer, 0, bytesToRead, Math.max(0, info.size - bytesToRead));
    } finally {
      closeSync(descriptor);
    }
    truncated = info.size > maxBytes;
    const raw = buffer.subarray(0, bytesRead).toString('utf8');
    lines = raw.split(/\r?\n/).filter(Boolean);
    if (truncated && lines.length > 0) lines.shift();
  } catch {
    return [patrolFinding(6, 'HIGH', 'The AgentGuard audit log could not be read.')];
  }
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const denials = new Map<string, number>();
  let sawCritical = false;
  let sawExfiltration = false;
  let sawPromptInjection = false;
  let malformedEvents = 0;
  for (const line of lines) {
    try {
      const parsed: unknown = JSON.parse(line);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        malformedEvents += 1;
        continue;
      }
      const event = parsed as Record<string, unknown>;
      const timestamp = Date.parse(String(event.timestamp || ''));
      if (!Number.isFinite(timestamp) || timestamp < cutoff) continue;
      const runtimeEvent = event.event === 'runtime_action' || (
        typeof event.actionId === 'string' && typeof event.actionType === 'string'
      );
      if (!runtimeEvent) continue;
      const reasons = Array.isArray(event.reasons) ? event.reasons : [];
      const tags = [
        ...(Array.isArray(event.risk_tags) ? event.risk_tags.map(String) : []),
        ...reasons.flatMap((reason) => reason && typeof reason === 'object'
          ? [String((reason as Record<string, unknown>).code || '')]
          : []),
      ].filter(Boolean);
      const actor = event.actor as { skill?: { id?: unknown } } | undefined;
      const skillValue = event.sourceSkill || event.initiating_skill || actor?.skill?.id;
      const skill = typeof skillValue === 'string' ? skillValue.trim() : '';
      if ((event.decision === 'deny' || event.decision === 'block') && skill) {
        denials.set(skill, (denials.get(skill) || 0) + 1);
      }
      if (String(event.risk_level || event.riskLevel).toLowerCase() === 'critical') sawCritical = true;
      if (tags.some((tag) => tag === 'WEBHOOK_EXFIL' || tag === 'NET_EXFIL_UNRESTRICTED')) sawExfiltration = true;
      if (tags.includes('PROMPT_INJECTION')) sawPromptInjection = true;
    } catch {
      malformedEvents += 1;
      continue;
    }
  }
  const findings: CheckupFinding[] = [];
  for (const [skill, count] of denials) {
    if (count >= 3) findings.push(patrolFinding(6, 'HIGH', `Skill ${skill} was denied ${count} times in the previous 24 hours.`));
  }
  if (sawCritical) findings.push(patrolFinding(6, 'CRITICAL', 'Critical-risk runtime activity was recorded in the previous 24 hours.'));
  if (sawExfiltration) findings.push(patrolFinding(6, 'HIGH', 'Possible data-exfiltration activity was recorded in the previous 24 hours.'));
  if (sawPromptInjection) findings.push(patrolFinding(6, 'CRITICAL', 'Prompt-injection activity was recorded in the previous 24 hours.'));
  if (malformedEvents > 0) findings.push(patrolFinding(6, 'MEDIUM', `${malformedEvents} malformed audit event(s) could not be analyzed.`));
  if (truncated) findings.push(patrolFinding(6, 'MEDIUM', 'Audit-log analysis was limited to the newest 16 MiB; older events within the 24-hour window may require log rotation or archival review.'));
  return findings;
}

function checkEnvironmentConfiguration(config: AgentGuardConfig): CheckupFinding[] {
  const findings: CheckupFinding[] = [];
  const expectedCredentialVariables = new Set(['GOPLUS_API_KEY', 'GOPLUS_API_SECRET', 'AGENTGUARD_API_KEY']);
  const sensitiveEnvNames = Object.keys(process.env)
    .filter((name) => /API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE|CREDENTIAL/i.test(name))
    .filter((name) => !expectedCredentialVariables.has(name))
    .slice(0, 8);
  if (sensitiveEnvNames.length > 0) {
    findings.push(patrolFinding(7, 'MEDIUM', `Sensitive environment variable names are present: ${sensitiveEnvNames.join(', ')}.`));
  }
  if (config.level === 'permissive') {
    findings.push(patrolFinding(7, 'MEDIUM', 'Protection level is permissive; production agents should normally use balanced or strict.'));
  }
  findings.push(...checkConfigurationBaseline(join(homedir(), '.openclaw')));
  return findings;
}

function checkConfigurationBaseline(root: string): CheckupFinding[] {
  const baselinePath = join(root, '.config-baseline.sha256');
  if (!existsSync(baselinePath)) return [];
  let lines: string[];
  try {
    const info = statSync(baselinePath);
    if (!info.isFile() || info.size > 512 * 1024) throw new Error('invalid baseline file');
    lines = readFileSync(baselinePath, 'utf8').split(/\r?\n/).filter(Boolean);
  } catch {
    return [patrolFinding(7, 'HIGH', 'The OpenClaw configuration baseline could not be read safely.')];
  }
  const findings: CheckupFinding[] = [];
  for (const line of lines.slice(0, 1000)) {
    const match = line.match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (!match) {
      findings.push(patrolFinding(7, 'MEDIUM', 'The OpenClaw configuration baseline contains an invalid entry.'));
      continue;
    }
    const candidate = resolve(root, match[2]);
    if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) {
      findings.push(patrolFinding(7, 'HIGH', 'The OpenClaw configuration baseline references a path outside its agent root.'));
      continue;
    }
    try {
      const info = statSync(candidate);
      if (!info.isFile() || info.size > 8 * 1024 * 1024) throw new Error('unsafe baseline target');
      const actual = createHash('sha256').update(readFileSync(candidate)).digest('hex');
      if (actual.toLowerCase() !== match[1].toLowerCase()) {
        findings.push(patrolFinding(7, 'HIGH', `Configuration baseline mismatch: ${candidate}.`));
      }
    } catch {
      findings.push(patrolFinding(7, 'HIGH', `Configuration baseline target could not be verified: ${candidate}.`));
    }
  }
  if (lines.length > 1000) findings.push(patrolFinding(7, 'MEDIUM', 'Configuration baseline coverage exceeded the patrol safety limit.'));
  return findings;
}

interface TrustRegistrySnapshot {
  records: TrustRecord[];
  invalidRecords: number;
}

function normalizeTrustRecords(value: unknown): TrustRegistrySnapshot {
  if (!Array.isArray(value)) return { records: [], invalidRecords: 1 };
  const records: TrustRecord[] = [];
  let invalidRecords = 0;
  for (const candidate of value) {
    if (!isTrustRecord(candidate)) {
      invalidRecords += 1;
      continue;
    }
    records.push(candidate);
  }
  return { records, invalidRecords };
}

function isTrustRecord(value: unknown): value is TrustRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const skill = record.skill;
  const review = record.review;
  const capabilities = record.capabilities;
  const reviewedAt = review && typeof review === 'object' && !Array.isArray(review)
    ? (review as Record<string, unknown>).reviewed_at
    : undefined;
  const validReviewedAt = typeof reviewedAt === 'string' && Number.isFinite(Date.parse(reviewedAt));
  const validExpiresAt = record.expires_at === undefined || (
    typeof record.expires_at === 'string' && Number.isFinite(Date.parse(record.expires_at))
  );
  return Boolean(
    skill && typeof skill === 'object' && !Array.isArray(skill) &&
    typeof (skill as Record<string, unknown>).id === 'string' &&
    typeof (skill as Record<string, unknown>).source === 'string' &&
    typeof (skill as Record<string, unknown>).artifact_hash === 'string' &&
    review && typeof review === 'object' && !Array.isArray(review) &&
    validReviewedAt &&
    validExpiresAt &&
    capabilities && typeof capabilities === 'object' && !Array.isArray(capabilities) &&
    typeof (capabilities as Record<string, unknown>).exec === 'string' &&
    Array.isArray((capabilities as Record<string, unknown>).network_allowlist) &&
    (record.status === 'active' || record.status === 'revoked') &&
    (record.trust_level === 'trusted' || record.trust_level === 'restricted' || record.trust_level === 'untrusted')
  );
}

function checkTrustRegistryHealth(
  records: TrustRecord[] | null,
  invalidRecords: number,
  installedSources: Set<string>,
): CheckupFinding[] {
  if (records === null) {
    return [patrolFinding(8, 'HIGH', 'The trust registry could not be read.')];
  }
  const findings: CheckupFinding[] = [];
  if (invalidRecords > 0) {
    findings.push(patrolFinding(8, 'HIGH', `${invalidRecords} malformed trust-registry record(s) could not be evaluated.`));
  }
  const now = Date.now();
  for (const record of records) {
    if (record.status !== 'active') continue;
    const label = record.skill.id || record.skill.source;
    if (record.expires_at && Date.parse(record.expires_at) < now) {
      findings.push(patrolFinding(8, 'HIGH', `Trust record for ${label} has expired.`));
    }
    const reviewedAt = Date.parse(record.review.reviewed_at || record.updated_at);
    if (record.trust_level === 'trusted' && Number.isFinite(reviewedAt) && now - reviewedAt > 30 * 24 * 60 * 60 * 1000) {
      findings.push(patrolFinding(8, 'MEDIUM', `Trust record for ${label} has not been reviewed in more than 30 days.`));
    }
    if (record.trust_level === 'untrusted' && installedSources.has(record.skill.source)) {
      findings.push(patrolFinding(8, 'HIGH', `Installed artifact ${label} has an untrusted registry record.`));
    }
    if (record.trust_level !== 'untrusted' && record.capabilities.exec === 'allow' && record.capabilities.network_allowlist.includes('*')) {
      findings.push(patrolFinding(8, 'HIGH', `Trust record for ${label} combines command execution with unrestricted network access.`));
    }
  }
  return findings;
}

function checkRuntimeProtection(config: AgentGuardConfig, skillsScanned: number): CheckupDimension {
  let score = 0;
  const findings: CheckupFinding[] = [];
  const hookFiles = [
    join(homedir(), '.claude', 'settings.json'),
    join(homedir(), '.openclaw', 'openclaw.json'),
    join(homedir(), '.hermes', 'config.yaml'),
  ];
  const hasHook = hookFiles.some((path) => {
    if (!existsSync(path)) return false;
    try {
      return /agentguard|guard-hook|hermes-hook/i.test(readFileSync(path, 'utf8'));
    } catch {
      return false;
    }
  });
  if (hasHook) score += 40;
  else findings.push(patrolFinding(7, 'HIGH', 'No AgentGuard runtime hook was detected in known agent configuration files.'));

  if (existsSync(config.auditPath)) score += 30;

  if (skillsScanned > 0) score += 30;
  else findings.push(patrolFinding(1, 'MEDIUM', 'No installed skills were scanned during this checkup.'));

  return {
    score: clampScore(score),
    findings,
    details: findings.length ? `${findings.length} runtime protection gap(s) found.` : 'Runtime hooks, audit logging, and skill scanning are present.',
  };
}

function checkWeb3Safety(skillDirs: string[]): CheckupDimension {
  const web3Detected = ['GOPLUS_API_KEY', 'CHAIN_ID', 'RPC_URL'].some((name) => process.env[name]) ||
    skillDirs.some((dir) => /web3|wallet|chain|defi|token/i.test(dir));
  if (!web3Detected) {
    return { score: null, na: true, findings: [], details: 'No Web3 usage detected.' };
  }

  const findings: CheckupFinding[] = [];
  let score = process.env.GOPLUS_API_KEY ? 100 : 70;
  if (!process.env.GOPLUS_API_KEY) {
    findings.push(patrolFinding(7, 'MEDIUM', 'Web3 usage detected but GOPLUS_API_KEY is not configured for transaction checks.'));
  }
  return {
    score,
    findings,
    details: findings.length ? 'Web3 usage detected with missing transaction security configuration.' : 'Web3 safety configuration is present.',
  };
}

function permissionMode(path: string): number | null {
  if (!existsSync(path)) return null;
  try {
    return statSync(path).mode & 0o777;
  } catch {
    return null;
  }
}

interface CommandTextResult {
  available: boolean;
  output: string;
}

async function firstAvailableCommand(commands: Array<[string, string[]]>): Promise<CommandTextResult> {
  for (const [command, args] of commands) {
    const result = await runCommandText(command, args);
    if (result.available) return result;
  }
  return { available: false, output: '' };
}

function runCommandText(command: string, args: string[]): Promise<CommandTextResult> {
  return new Promise((resolvePromise) => {
    try {
      const child = execFile(command, args, { timeout: 3000, maxBuffer: 512 * 1024 }, (error, stdout, stderr) => {
        const output = `${stdout || ''}${stderr || ''}`;
        if (!error) return resolvePromise({ available: true, output });
        const benignEmptyCrontab = command === 'crontab' && /no crontab/i.test(output);
        return resolvePromise(benignEmptyCrontab
          ? { available: true, output }
          : { available: false, output });
      });
      child.on('error', () => resolvePromise({ available: false, output: '' }));
    } catch {
      resolvePromise({ available: false, output: '' });
    }
  });
}

interface AgentCredentialRegistration {
  config: AgentGuardConfig;
  client: AgentGuardCloudClient;
  registerUrl: string;
  openClawNotification: {
    notified: boolean;
    reason?: string;
  };
}

interface AgentJwtReauthResult<T> {
  value: T;
  config: AgentGuardConfig;
  client: AgentGuardCloudClient;
  registration: AgentCredentialRegistration | null;
}

async function runCloudRequestWithAgentJwtReauth<T>(options: {
  config: AgentGuardConfig;
  client: AgentGuardCloudClient;
  reason: 'reauth';
  notifyOpenClaw: boolean;
  operation: (client: AgentGuardCloudClient) => Promise<T>;
}): Promise<AgentJwtReauthResult<T>> {
  try {
    return {
      value: await options.operation(options.client),
      config: options.config,
      client: options.client,
      registration: null,
    };
  } catch (err) {
    if (
      !(err instanceof CloudRequestError && err.status === 401) ||
      !options.config.agentJwt ||
      !isAgentJwtHostConfigured(options.config)
    ) {
      throw err;
    }
    const registration = await registerAgentCredential({
      cloudUrl: options.config.cloudUrl,
      reason: options.reason,
      notifyOpenClaw: options.notifyOpenClaw,
      resetExistingJwt: true,
    });
    return {
      value: await options.operation(registration.client),
      config: registration.config,
      client: registration.client,
      registration,
    };
  }
}

async function registerAgentCredential(options: {
  cloudUrl?: string;
  reason: 'connect' | 'subscribe' | 'reauth';
  notifyOpenClaw: boolean;
  resetExistingJwt?: boolean;
}): Promise<AgentCredentialRegistration> {
  if (options.resetExistingJwt) {
    clearAgentJwt();
  }
  const baseConfig = ensureConfig();
  const cloudUrl = normalizeCloudUrl(options.cloudUrl || baseConfig.cloudUrl || 'https://www.agentguard.one');
  const client = new AgentGuardCloudClient({ ...baseConfig, cloudUrl });
  const registration = await client.registerAgent({
    metadata: {
      agentHost: baseConfig.agentHost,
      agentHosts: baseConfig.agentHosts,
      agentVersion: packageVersion,
      platform: process.platform,
      arch: process.arch,
      reason: options.reason,
    },
  });
  const config = connectAgentJwt({
    agentId: registration.agentId,
    agentJwt: registration.jwt,
    agentRegisterUrl: registration.registerUrl,
    cloudUrl,
  });
  const nextClient = new AgentGuardCloudClient(config);
  const openClawNotification = options.notifyOpenClaw
    ? await notifyOpenClawRegistrationLink(registration.registerUrl, resolveOpenClawGatewayOptionsFromEnv())
    : { notified: false, reason: 'OpenClaw notification was not requested.' };
  return {
    config,
    client: nextClient,
    registerUrl: registration.registerUrl,
    openClawNotification,
  };
}

function printAgentRegistrationNotice(registration: AgentCredentialRegistration): void {
  console.log('AgentGuard Cloud activation is ready:');
  console.log(registration.registerUrl);
  if (registration.openClawNotification.notified) {
    console.log('Sent the activation link to the last OpenClaw channel.');
  }
}

function printAgentActivationRequired(
  registration: AgentCredentialRegistration | null,
  err: unknown
): void {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`! AgentGuard Cloud authorization is not active yet. ${message}`);
  const registerUrl = registration?.registerUrl || ensureConfig().agentRegisterUrl;
  if (registerUrl) {
    console.error('Open this link to bind this agent to your account, then rerun the command:');
    console.error(registerUrl);
  }
}

function isOpenClawAgentConfigured(config: AgentGuardConfig): boolean {
  return config.agentHost === 'openclaw' || config.agentHosts?.includes('openclaw') === true || detectOpenClawRuntime();
}

function isHermesAgentConfigured(config: AgentGuardConfig): boolean {
  return config.agentHost === 'hermes' || config.agentHosts?.includes('hermes') === true || detectHermesRuntime();
}

function isDshAgentConfigured(config: AgentGuardConfig): boolean {
  return config.agentHost === 'dsh' || config.agentHosts?.includes('dsh') === true || detectDshManagedShell();
}

function isAgentJwtHostConfigured(config: AgentGuardConfig): boolean {
  return isOpenClawAgentConfigured(config) || isHermesAgentConfigured(config) || isDshAgentConfigured(config);
}

function withDetectedAgentJwtHost(config: AgentGuardConfig): AgentGuardConfig {
  if (isAgentJwtAgentHost(config.agentHost)) return config;
  const savedAgentJwtHost = config.agentHosts?.find(isAgentJwtAgentHost);
  if (savedAgentJwtHost) return withDetectedAgentHost(config, savedAgentJwtHost);
  if (detectDshManagedShell()) return withDetectedAgentHost(config, 'dsh');
  if (detectOpenClawRuntime()) return withDetectedAgentHost(config, 'openclaw');
  if (detectHermesRuntime()) return withDetectedAgentHost(config, 'hermes');
  return config;
}

function isAgentJwtAgentHost(value: AgentGuardAgentHost | undefined): value is 'openclaw' | 'hermes' | 'dsh' {
  return value === 'openclaw' || value === 'hermes' || value === 'dsh';
}

function detectDshManagedShell(): boolean {
  return process.env.DSH_SHELL === '1';
}

function detectInstalledDshWebProfile(): boolean {
  const configuredHome = process.env.DSH_HOME?.trim();
  const dshHome = configuredHome
    ? configuredHome === '~'
      ? homedir()
      : /^~[\\/]/.test(configuredHome)
        ? join(homedir(), configuredHome.slice(2))
        : resolve(configuredHome)
    : join(homedir(), '.dsh');
  return existsSync(join(dshHome, 'profiles', 'web', 'package.json'));
}

function withDetectedAgentHost(config: AgentGuardConfig, agentHost: AgentGuardAgentHost): AgentGuardConfig {
  const next: AgentGuardConfig = {
    ...config,
    agentHost,
    agentHosts: appendAgentHost(config.agentHosts, agentHost),
  };
  saveConfig(next);
  return next;
}

function detectOpenClawRuntime(): boolean {
  const configPath = process.env.OPENCLAW_CONFIG_PATH?.trim();
  if (configPath && existsSync(configPath)) return true;

  const stateDir = process.env.OPENCLAW_STATE_DIR?.trim();
  if (stateDir && (existsSync(stateDir) || existsSync(join(stateDir, 'openclaw.json')))) return true;

  return existsSync(join(homedir(), '.openclaw', 'openclaw.json'));
}

function detectHermesRuntime(): boolean {
  const hermesHome = process.env.HERMES_HOME?.trim();
  if (hermesHome && (existsSync(hermesHome) || existsSync(join(hermesHome, 'config.yaml')))) return true;

  const defaultHome = join(homedir(), '.hermes');
  return existsSync(join(defaultHome, 'config.yaml')) || existsSync(defaultHome);
}

function resolveOpenClawGatewayOptionsFromEnv(): OpenClawGatewayOptions {
  const url = process.env.AGENTGUARD_OPENCLAW_GATEWAY_URL?.trim();
  const host = process.env.AGENTGUARD_OPENCLAW_GATEWAY_HOST?.trim();
  const token = process.env.AGENTGUARD_OPENCLAW_GATEWAY_TOKEN?.trim();
  const portRaw = process.env.AGENTGUARD_OPENCLAW_GATEWAY_PORT?.trim();
  const timeoutRaw = process.env.AGENTGUARD_OPENCLAW_GATEWAY_TIMEOUT_MS?.trim();
  const port = portRaw ? Number(portRaw) : undefined;
  const timeoutMs = timeoutRaw ? Number(timeoutRaw) : undefined;
  return {
    ...(url ? { url } : {}),
    ...(host ? { host } : {}),
    ...(token ? { token } : {}),
    ...(Number.isFinite(port) ? { port } : {}),
    ...(Number.isFinite(timeoutMs) ? { timeoutMs } : {}),
  };
}

function calculateCompositeScore(dimensions: HealthCheckupReport['dimensions']): number {
  const web3Score = dimensions.web3_safety.score;
  if (web3Score === null || dimensions.web3_safety.na) {
    return Math.round(
      (dimensions.code_safety.score ?? 0) * 0.294 +
      (dimensions.credential_safety.score ?? 0) * 0.294 +
      (dimensions.network_exposure.score ?? 0) * 0.235 +
      (dimensions.runtime_protection.score ?? 0) * 0.176
    );
  }
  return Math.round(
    (dimensions.code_safety.score ?? 0) * 0.25 +
    (dimensions.credential_safety.score ?? 0) * 0.25 +
    (dimensions.network_exposure.score ?? 0) * 0.20 +
    (dimensions.runtime_protection.score ?? 0) * 0.15 +
    web3Score * 0.15
  );
}

async function generateCheckupHtml(report: HealthCheckupReport): Promise<string> {
  const tempDir = mkdtempSync(join(tmpdir(), 'agentguard-checkup-'));
  const dataPath = join(tempDir, 'data.json');
  writeFileSync(dataPath, JSON.stringify(report, null, 2), 'utf8');
  const scriptPath = process.env.AGENTGUARD_CHECKUP_REPORT_SCRIPT
    ? resolve(process.env.AGENTGUARD_CHECKUP_REPORT_SCRIPT)
    : resolve(__dirname, '..', 'skills', 'agentguard', 'scripts', 'checkup-report.js');
  if (!existsSync(scriptPath)) {
    throw new Error(`report generator not found at ${scriptPath}`);
  }
  return new Promise((resolvePromise, reject) => {
    execFile('node', [scriptPath, '--file', dataPath], { timeout: 6000 }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || error.message));
      else resolvePromise(stdout.trim().split(/\r?\n/).pop() || '');
    });
  });
}

function printHealthCheckupSummary(report: HealthCheckupReport, htmlPath?: string | null): void {
  const totalFindings = Object.values(report.dimensions).reduce((sum, dim) => sum + dim.findings.length, 0);
  console.log('AgentGuard Health Checkup');
  console.log(`Overall Health Score: ${report.composite_score}/100 (Tier ${report.tier})`);
  console.log(`Findings: ${totalFindings}`);
  console.log(`Skills scanned: ${report.skills_scanned}`);
  console.log(`DSH plugins scanned: ${report.dsh_plugins_scanned}`);
  for (const [name, dim] of Object.entries(report.dimensions)) {
    const score = dim.na || dim.score === null ? 'N/A' : `${dim.score}/100`;
    console.log(`- ${name}: ${score} - ${dim.details}`);
  }
  if (htmlPath) {
    console.log(`Full visual report: ${htmlPath}`);
  } else {
    console.log('Full visual report: unavailable (text summary shown above)');
  }
}

function appendCheckupAudit(auditPath: string, report: HealthCheckupReport): void {
  const totalFindings = Object.values(report.dimensions).reduce((sum, dim) => sum + dim.findings.length, 0);
  try {
    appendFileSync(auditPath, `${JSON.stringify({
      timestamp: report.timestamp,
      event: 'checkup',
      composite_score: report.composite_score,
      tier: report.tier,
      checks: 8,
      findings: totalFindings,
      skills_scanned: report.skills_scanned,
      dsh_plugins_scanned: report.dsh_plugins_scanned,
    })}\n`, { mode: 0o600 });
  } catch {
    // Checkup should still succeed if audit logging is unavailable.
  }
}

function buildHealthAnalysis(score: number, dimensions: HealthCheckupReport['dimensions']): string {
  const weak = Object.entries(dimensions)
    .filter(([, dim]) => !dim.na && dim.score !== null && dim.score < 70)
    .map(([name]) => name.replace(/_/g, ' '));
  if (weak.length === 0) {
    return `Overall posture is healthy at ${score}/100. AgentGuard did not find major weaknesses across the local skill, credential, network, and runtime checks.`;
  }
  return `Overall posture is ${score}/100. The areas needing attention are ${weak.join(', ')}; review the findings and fix the highest-severity items first.`;
}

function tierForScore(score: number): HealthCheckupReport['tier'] {
  if (score >= 90) return 'S';
  if (score >= 70) return 'A';
  if (score >= 50) return 'B';
  return 'F';
}

function clampScore(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function riskLevelToSeverity(risk: string): CheckupFinding['severity'] {
  if (risk === 'critical') return 'CRITICAL';
  if (risk === 'high') return 'HIGH';
  if (risk === 'medium') return 'MEDIUM';
  return 'LOW';
}

interface SubscribeSummary {
  supported: boolean;
  pulled: number;
  fresh: number;
  matched: number;
  shouldNotify: boolean;
  hardFailures: number;
  results: SelfCheckResult[];
  notification?: {
    title: string;
    body: string;
  };
  cron: {
    requested: boolean;
    installed: boolean;
    result?: OpenClawCronInstallResult;
    error?: string;
  };
}

function buildSubscribeSummary(options: {
  supported: boolean;
  pulled: number;
  fresh: number;
  freshAdvisories: Advisory[];
  results: SelfCheckResult[];
  hardFailures: number;
  quiet: boolean;
}): SubscribeSummary {
  const matched = options.results.reduce((acc, r) => acc + r.matchedArtifacts.length, 0);
  const shouldNotify = options.supported
    && options.hardFailures === 0
    && (options.quiet ? matched > 0 : options.fresh > 0);
  const summary: SubscribeSummary = {
    supported: options.supported,
    pulled: options.pulled,
    fresh: options.fresh,
    matched,
    shouldNotify,
    hardFailures: options.hardFailures,
    results: options.results,
    cron: {
      requested: false,
      installed: false,
    },
  };
  if (shouldNotify && options.quiet) {
    summary.notification = {
      title: `AgentGuard detected ${matched} threat-feed match${matched === 1 ? '' : 'es'}`,
      body: formatThreatFeedNotification(options.results),
    };
  } else if (shouldNotify) {
    summary.notification = {
      title: `AgentGuard found ${options.fresh} new threat-feed advisor${options.fresh === 1 ? 'y' : 'ies'}`,
      body: formatNewAdvisoryNotification(options.freshAdvisories),
    };
  }
  return summary;
}

function formatNewAdvisoryNotification(advisories: Advisory[]): string {
  const lines = ['AgentGuard found new threat-feed advisories that need manual review:'];
  for (const advisory of advisories.slice(0, 10)) {
    lines.push(`- ${advisory.id} [${advisory.severity}] ${advisory.summary}`);
    const remediation = formatAdvisoryRemediation(advisory);
    if (remediation) {
      lines.push('  Remediation guidance:');
      for (const line of remediation.split('\n')) {
        lines.push(`  ${line}`);
      }
    }
  }
  if (advisories.length > 10) {
    lines.push(`- ... ${advisories.length - 10} more`);
  }
  return lines.join('\n');
}

function formatAdvisoryRemediation(advisory: Advisory): string | null {
  const remediation = advisory.selfCheck?.remediationMd?.trim();
  if (!remediation) return null;
  const compact = remediation
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  const maxLen = 1200;
  return compact.length > maxLen ? `${compact.slice(0, maxLen).trimEnd()}\n...` : compact;
}

function formatThreatFeedNotification(results: SelfCheckResult[]): string {
  const lines = ['AgentGuard threat-feed self-check found local matches:'];
  for (const result of results) {
    if (result.matchedArtifacts.length === 0) continue;
    lines.push(`- ${result.advisoryId}: ${result.matchedArtifacts.length} match(es)`);
    for (const match of result.matchedArtifacts.slice(0, 5)) {
      lines.push(`  - ${match.path} [${match.matchedBy}]`);
    }
    if (result.matchedArtifacts.length > 5) {
      lines.push(`  - ... ${result.matchedArtifacts.length - 5} more`);
    }
  }
  lines.push('Review the local machine and remove or quarantine the matched artifact(s).');
  return lines.join('\n');
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
