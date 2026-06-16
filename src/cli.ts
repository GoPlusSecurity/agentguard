#!/usr/bin/env node

import { appendFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { join, resolve } from 'node:path';
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
import { formatProtectResult, protectAction, exitCodeForDecision } from './runtime/protect.js';
import { approvePendingApproval, listPendingApprovals } from './runtime/approvals.js';
import { getDefaultEffectiveRuntimePolicy, loadCachedPolicy, saveCachedPolicy } from './runtime/policy.js';
import type { RuntimeActionType, RuntimeAgentHost } from './runtime/types.js';
import { installAgentTemplates, type AgentInstaller, type InstallResult } from './installers.js';
import { packageVersion } from './version.js';
import { runSelfCheckForAdvisory } from './feed/selfcheck.js';
import { getSeenAdvisoryIds, loadFeedState, prependFeedStateEntry, saveFeedState } from './feed/state.js';
import type { Advisory, SelfCheckResult } from './feed/types.js';
import { CloudRequestError } from './cloud/client.js';
import { notifyOpenClawMessage, notifyOpenClawRegistrationLink } from './cloud/openclaw-notify.js';
import {
  installThreatFeedCron,
  removeThreatFeedCron,
  validateCronExpression,
  type OpenClawCronInstallResult,
  type CronBackend,
  type ThreatFeedCronRemovalResult,
  type OpenClawGatewayOptions,
} from './feed/cron.js';

const SUPPORTED_AGENT_INSTALLERS: AgentInstaller[] = ['claude-code', 'codex', 'openclaw', 'hermes', 'qclaw'];
const AUTO_AGENT_DETECTION: Array<{ agent: AgentInstaller; dir: string }> = [
  { agent: 'claude-code', dir: '.claude' },
  { agent: 'openclaw', dir: '.openclaw' },
  { agent: 'hermes', dir: '.hermes' },
  { agent: 'qclaw', dir: '.qclaw' },
  { agent: 'codex', dir: '.codex' },
];
const REQUIRED_INIT_COMMAND = 'agentguard init --agent auto';

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
    .option('--agent <agent>', 'Install hook/template for claude-code, codex, openclaw, hermes, or qclaw')
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
      if (options.agent) {
        const normalizedAgent = String(options.agent).trim().toLowerCase();
        if (normalizedAgent === 'auto') {
          const results = initAutoAgents(config, forceTemplates);
          if (results.detected.length === 0) {
            console.log('No supported agent directories found. Looked for .claude, .openclaw, .hermes, .qclaw, and .codex.');
          } else if (results.installed.length === 0) {
            console.log('No agent templates were installed; all detected agent initializers failed.');
          }
          for (const result of results.installed) {
            console.log(`Installed ${result.agent} template:`);
            for (const file of result.files) console.log(`- ${file}`);
            if (result.agent === 'hermes') printHermesNativePluginEnabled();
          }
          for (const failure of results.failed) {
            console.error(`! Failed to initialize ${failure.agent}: ${failure.error}`);
          }
          return;
        }
        if (!SUPPORTED_AGENT_INSTALLERS.includes(normalizedAgent as AgentInstaller)) {
          throw new Error('Invalid agent. Use auto, claude-code, codex, openclaw, hermes, or qclaw.');
        }
        const agent = normalizedAgent as AgentInstaller;
        config.agentHost = agent;
        config.agentHosts = appendAgentHost(config.agentHosts, agent);
        saveConfig(config);
        const shellHooks = Boolean(options.shellHooks);
        const result = installAgentTemplates(agent, { force: forceTemplates, shellHooks });
        console.log(`Installed ${result.agent} template:`);
        for (const file of result.files) console.log(`- ${file}`);
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
    .option('--url <url>', 'AgentGuard Cloud URL', 'https://agentguard.gopluslabs.io')
    .option('--cloud <url>', 'AgentGuard Cloud URL')
    .action(async (options) => {
      const apiKey = options.key || options.apiKey || process.env.AGENTGUARD_API_KEY;
      if (!apiKey) {
        let config = ensureConfig();
        if (!isAgentJwtHostConfigured(config)) {
          throw new Error('AgentGuard Cloud connect supports API-key auth or Agent JWT registration for OpenClaw and Hermes. No API key was provided, and no supported Agent JWT host has been initialized. Run `agentguard init --agent openclaw` or `agentguard init --agent hermes`, then rerun `agentguard connect`; or pass --key, --api-key, or AGENTGUARD_API_KEY for API-key auth.');
        }
        config = withDetectedAgentJwtHost(config);
        const cloudUrl = normalizeCloudUrl(options.cloud || options.url || config.cloudUrl || 'https://agentguard.gopluslabs.io');
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
    .option('--cron-target <target>', 'Cron backend: auto, openclaw, qclaw, hermes, or system', 'auto')
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
          const message = 'AgentGuard Cloud is not connected. Run `agentguard connect --key <key>` first, or run `agentguard init --agent openclaw` or `agentguard init --agent hermes` to use Agent JWT registration.';
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
        if (summary.cron.result.backend === 'system') {
          console.log(`System cron output: ${join(getAgentGuardPaths().home, 'feed-cron.log')}`);
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
  if (value === 'auto' || value === 'openclaw' || value === 'qclaw' || value === 'hermes' || value === 'system') return value;
  throw new Error('Invalid cron target. Use auto, openclaw, qclaw, hermes, or system.');
}

function initAutoAgents(config: AgentGuardConfig, force: boolean): {
  installed: InstallResult[];
  failed: Array<{ agent: AgentInstaller; error: string }>;
  detected: AgentInstaller[];
} {
  const installed: InstallResult[] = [];
  const failed: Array<{ agent: AgentInstaller; error: string }> = [];
  const detectedAgents = AUTO_AGENT_DETECTION
    .filter(({ dir }) => existsSync(join(process.cwd(), dir)))
    .map(({ agent }) => agent);

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
  protection_level: string;
  analysis: string;
  recommendations: CheckupFinding[];
}

async function runLocalHealthCheckup(config: AgentGuardConfig): Promise<HealthCheckupReport> {
  const skillRoots = [
    join(homedir(), '.claude', 'skills'),
    join(homedir(), '.openclaw', 'skills'),
    join(homedir(), '.openclaw', 'workspace', 'skills'),
    join(homedir(), '.qclaw', 'skills'),
    join(homedir(), '.qclaw', 'workspace', 'skills'),
    join(homedir(), '.hermes', 'skills'),
  ];
  const skillDirs = discoverSkillDirs(skillRoots);
  const scanner = new SkillScanner({ useExternalScanner: false });

  const codeFindings: CheckupFinding[] = [];
  let codeScore = skillDirs.length === 0 ? 70 : 100;
  if (skillDirs.length === 0) {
    codeFindings.push({ severity: 'LOW', text: 'No installed third-party skills were found to audit.' });
  }
  for (const dir of skillDirs) {
    const result = await scanner.quickScan(dir);
    const name = dir.split(/[\\/]/).pop() || dir;
    if (result.risk_level === 'critical') codeScore -= 15;
    if (result.risk_level === 'high') codeScore -= 8;
    if (result.risk_level === 'medium') codeScore -= 3;
    if (result.risk_level !== 'low') {
      codeFindings.push({
        severity: riskLevelToSeverity(result.risk_level),
        text: `${name}: ${result.summary}${result.risk_tags.length ? ` (${result.risk_tags.join(', ')})` : ''}`,
      });
    }
  }
  codeScore = clampScore(codeScore);

  const credential = checkCredentialSafety(skillDirs);
  const network = await checkNetworkExposure(config);
  const runtime = checkRuntimeProtection(config, skillDirs.length);
  const web3 = checkWeb3Safety(skillDirs);

  const dimensions = {
    code_safety: {
      score: codeScore,
      findings: codeFindings,
      details: `${skillDirs.length} installed skill(s) scanned with AgentGuard rules.`,
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
      if (!entry.isDirectory()) continue;
      const dir = join(root, entry.name);
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

function checkCredentialSafety(skillDirs: string[]): CheckupDimension {
  let score = 100;
  const findings: CheckupFinding[] = [];
  for (const [path, severity] of [
    [join(homedir(), '.ssh'), 'HIGH'],
    [join(homedir(), '.gnupg'), 'MEDIUM'],
  ] as const) {
    const mode = permissionMode(path);
    if (mode !== null && mode > 0o700) {
      score -= severity === 'HIGH' ? 25 : 15;
      findings.push({ severity, text: `${path} permissions are ${mode.toString(8)}; expected 700 or stricter.` });
    }
  }

  const secretPatterns = [
    { re: /0x[a-fA-F0-9]{64}|-----BEGIN [A-Z ]*PRIVATE KEY-----/, severity: 'CRITICAL' as const, label: 'Plaintext private key pattern' },
    { re: /\b(seed_phrase|mnemonic)\b/i, severity: 'CRITICAL' as const, label: 'Mnemonic or seed phrase marker' },
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
      score -= pattern.severity === 'CRITICAL' ? 25 : 15;
      findings.push({ severity: pattern.severity, text: `${pattern.label} found in ${manifest}.` });
    }
  }
  return {
    score: clampScore(score),
    findings,
    details: findings.length ? `${findings.length} credential hygiene issue(s) found.` : 'Credential permissions and scanned manifests look clean.',
  };
}

async function checkNetworkExposure(config: AgentGuardConfig): Promise<CheckupDimension> {
  let score = 100;
  const findings: CheckupFinding[] = [];
  const listeners = await runCommandText('lsof', ['-i', '-P', '-n']);
  for (const port of ['2375', '3306', '6379', '27017']) {
    const exposed = new RegExp(`(\\*|0\\.0\\.0\\.0):${port}\\b`).test(listeners);
    if (exposed) {
      score -= 25;
      findings.push({ severity: 'HIGH', text: `High-risk service appears exposed on 0.0.0.0:${port}.` });
    }
  }

  const cron = await runCommandText('crontab', ['-l']);
  if (/(curl\b.*\|\s*(bash|sh)|wget\b.*\|\s*(bash|sh)|\.ssh)/i.test(cron)) {
    score -= 30;
    findings.push({ severity: 'HIGH', text: 'Suspicious cron entry found that downloads shell code or accesses SSH material.' });
  }

  const sensitiveEnvNames = Object.keys(process.env).filter((name) => /PRIVATE_KEY|MNEMONIC|SECRET|PASSWORD/i.test(name));
  if (sensitiveEnvNames.length > 0) {
    score -= 20;
    findings.push({ severity: 'MEDIUM', text: `Sensitive environment variable names are present: ${sensitiveEnvNames.slice(0, 8).join(', ')}.` });
  }

  for (const path of [join(homedir(), '.openclaw', 'openclaw.json'), join(homedir(), '.openclaw', 'devices', 'paired.json')]) {
    const mode = permissionMode(path);
    if (mode !== null && mode > 0o600) {
      score -= 15;
      findings.push({ severity: 'MEDIUM', text: `${path} permissions are ${mode.toString(8)}; expected 600 or stricter.` });
    }
  }

  return {
    score: clampScore(score),
    findings,
    details: findings.length ? `${findings.length} network/system exposure issue(s) found.` : 'No dangerous ports, cron entries, or config permission issues found.',
  };
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
  else findings.push({ severity: 'HIGH', text: 'No AgentGuard runtime hook was detected in known agent configuration files.' });

  if (existsSync(config.auditPath)) score += 30;
  else findings.push({ severity: 'MEDIUM', text: 'No AgentGuard audit log exists yet, so runtime threat history is unavailable.' });

  if (skillsScanned > 0) score += 30;
  else findings.push({ severity: 'MEDIUM', text: 'No installed skills were scanned during this checkup.' });

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
    findings.push({ severity: 'MEDIUM', text: 'Web3 usage detected but GOPLUS_API_KEY is not configured for transaction checks.' });
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

function runCommandText(command: string, args: string[]): Promise<string> {
  return new Promise((resolvePromise) => {
    try {
      const child = execFile(command, args, { timeout: 2000 }, (error, stdout, stderr) => {
        if (error) resolvePromise('');
        else resolvePromise(`${stdout || ''}${stderr || ''}`);
      });
      child.on('error', () => resolvePromise(''));
    } catch {
      resolvePromise('');
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
  const cloudUrl = normalizeCloudUrl(options.cloudUrl || baseConfig.cloudUrl || 'https://agentguard.gopluslabs.io');
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

function isAgentJwtHostConfigured(config: AgentGuardConfig): boolean {
  return isOpenClawAgentConfigured(config) || isHermesAgentConfigured(config);
}

function withDetectedAgentJwtHost(config: AgentGuardConfig): AgentGuardConfig {
  if (hasSavedAgentHost(config)) return config;
  if (detectOpenClawRuntime()) return withDetectedAgentHost(config, 'openclaw');
  if (detectHermesRuntime()) return withDetectedAgentHost(config, 'hermes');
  return config;
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
      checks: 5,
      findings: totalFindings,
      skills_scanned: report.skills_scanned,
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
