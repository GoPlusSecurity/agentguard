# GoPlus AgentGuard

AI Agent Security Guard — protect your AI agents from dangerous commands, data leaks, and malicious skills.

## Features

- **Code Scanning** — 24 detection rules covering shell injection, credential leaks, prompt injection, Web3 exploits, and more
- **Action Evaluation** — Real-time allow/deny/confirm decisions for runtime actions (network, exec, file, Web3)
- **Trust Registry** — Manage skill trust levels with capability-based access control
- **Security Patrol** — Automated daily security checks for OpenClaw environments
- **Agent Health Checkup** — Full security posture assessment with visual HTML report and shareable lobster mascot
- **Audit Logging** — Full security event trail with reporting

## Usage

```
/agentguard scan <path>          — Scan code for security risks
/agentguard action <description> — Evaluate runtime action safety
/agentguard patrol [run|setup|status] — Daily security patrol
/agentguard trust <subcommand>   — Manage skill trust levels
/agentguard report               — View security event audit log
/agentguard config <level>       — Set protection level (strict/balanced/permissive)
/agentguard checkup              — Run agent health checkup with visual HTML report
```

## Agent Health Checkup 🦞

Run a full security health check on your AI agent and get a visual report in the browser:

```
/agentguard checkup
```

Evaluates 4 dimensions (5 if Web3 usage is detected):

| Dimension | What's checked |
|-----------|---------------|
| **Skill & Code Safety** | Scan all installed skills with 24 detection rules |
| **Credential & Secrets** | File permissions on `~/.ssh/`, `~/.gnupg/`, leaked keys and API tokens |
| **Network & System** | Dangerous open ports, suspicious cron jobs, sensitive env vars |
| **Runtime Protection** | Security hooks, audit log, whether skills have been scanned |
| **Web3 Safety** | Wallet-draining patterns, unlimited approvals, GoPlus API config (only if Web3 detected) |

Scores are combined into a composite 0–100 health score with a tier:

| Score | Tier | Lobster |
|-------|------|---------|
| 90–100 | **S** | 💪 Jacked — 5 random muscular variants |
| 70–89 | **A** | 🛡️ Healthy — 5 random armored variants |
| 50–69 | **B** | ☕ Tired — 5 random sleepy variants |
| 0–49 | **F** | 🚨 Critical — 5 random sick variants |

The report opens automatically in your browser. It includes a downloadable summary image with tier-specific copy in Chinese and English.

## Requirements

- Node.js 18+
- Optional: GoPlus API credentials for enhanced Web3 transaction simulation

## Author

Built by [GoPlus Security](https://gopluslabs.io) — the leading Web3 security infrastructure provider.
