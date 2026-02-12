# GoPlus AgentGuard Security Policy

Unified security policy reference for all platforms (Claude Code, OpenClaw, and future integrations).

---

## 1. Overview

### Design Principles

1. **Defense in Depth**: Multiple layers of protection (static scan, runtime evaluation, trust registry)
2. **Fail-Secure**: Unknown or ambiguous actions default to denial/confirmation
3. **Least Privilege**: Skills receive minimal capabilities by default
4. **User Sovereignty**: Users always retain final approval authority

### Three-Module Architecture

| Module | Purpose | When Invoked |
|--------|---------|--------------|
| **Static Scanner** | Detect malicious patterns in code/prompts | Before execution (`/agentguard scan`) |
| **Action Evaluator** | Runtime policy decisions on agent actions | On tool calls (hooks) |
| **Trust Registry** | Skill identity and capability attestation | Skill invocation & lookup |

---

## 2. Protection Levels

Configure via `/agentguard config <level>`:

| Level | Description | DENY Behavior | CONFIRM Behavior |
|-------|-------------|---------------|------------------|
| **strict** | Maximum security. All risk operations blocked. | Block | Block (treated as deny) |
| **balanced** (default) | Critical threats blocked, high-risk prompts user. | Block | Prompt user |
| **permissive** | Only critical threats blocked, others prompt. | Block if critical; else prompt | Prompt if high/critical |

### Decision Matrix

| Risk Level | strict | balanced | permissive |
|------------|--------|----------|------------|
| critical + DENY | Block | Block | Block |
| critical + CONFIRM | Block | Prompt | Prompt |
| high + DENY | Block | Block | Prompt |
| high + CONFIRM | Block | Prompt | Prompt |
| medium + DENY | Block | Block | Prompt |
| medium + CONFIRM | Block | Prompt | Allow |
| low | Allow | Allow | Allow |

---

## 3. Decision Framework

### Decision Types

| Decision | Meaning | Typical Outcome |
|----------|---------|-----------------|
| **ALLOW** | Safe to proceed | Action executes |
| **DENY** | Must not proceed | Action blocked (error to agent) |
| **CONFIRM** | Requires user approval | Prompt user for confirmation |

### Risk Levels

| Level | Priority Range | Description |
|-------|----------------|-------------|
| **critical** | 90-100 | Immediate block — private keys, destructive commands |
| **high** | 70-89 | Strong risk — API secrets, untrusted network exfil |
| **medium** | 50-69 | Moderate risk — system commands, network activity |
| **low** | 0-49 | Minimal risk — safe/read-only operations |

---

## 4. Runtime Action Rules (ActionScanner)

### 4.1 Command Execution (`exec_command`)

#### Safe Commands (Always ALLOW)

Commands matching the safe list are allowed without restriction, **unless** they contain shell metacharacters or access sensitive paths.

| Category | Commands |
|----------|----------|
| **Read-only** | `ls`, `echo`, `pwd`, `whoami`, `date`, `hostname`, `uname`, `tree`, `du`, `df`, `sort`, `uniq`, `diff`, `cd` |
| **File inspection** | `cat`, `head`, `tail`, `wc`, `grep`, `find`, `which`, `type` |
| **File operations** | `mkdir`, `cp`, `mv`, `touch` |
| **Git** | `git status`, `git log`, `git diff`, `git branch`, `git show`, `git remote`, `git clone`, `git checkout`, `git pull`, `git fetch`, `git merge`, `git add`, `git commit`, `git push` |
| **Package managers** | `npm install`, `npm run`, `npm test`, `npm ci`, `npm start`, `npx`, `yarn`, `pnpm`, `pip install`, `pip3 install` |
| **Version checks** | `node -v`, `npm -v`, `python --version`, `tsc --version`, `go version`, `rustc --version`, `java -version` |
| **Build & run** | `tsc`, `go build`, `go run`, `cargo build`, `cargo run`, `cargo test`, `make` |

**Shell metacharacters that disqualify safe commands**: `;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `{`, `}`

#### Dangerous Commands (Always DENY — Critical)

| Pattern | Description |
|---------|-------------|
| `rm -rf` / `rm -fr` | Recursive delete |
| `mkfs` | Format filesystem |
| `dd if=` | Raw disk write |
| `:(){:\|:&};:` | Fork bomb (with space variants) |
| `chmod 777` / `chmod -R 777` | World-writable permissions |
| `> /dev/sda` | Disk overwrite |
| `mv /* ` | Move root contents |
| `curl\|sh` / `wget\|bash` | Download and execute |

#### Sensitive Data Access (High Risk — CONFIRM)

| Pattern | Target |
|---------|--------|
| `cat /etc/passwd` | User database |
| `cat /etc/shadow` | Password hashes |
| `cat ~/.ssh` | SSH keys |
| `cat ~/.aws` | AWS credentials |
| `cat ~/.kube` | Kubernetes config |
| `cat ~/.npmrc` | npm auth tokens |
| `cat ~/.netrc` | Network credentials |
| `printenv` / `env` / `set` | All environment variables |

#### System Commands (Medium Risk — Audit)

`sudo`, `su`, `chown`, `chmod`, `chgrp`, `useradd`, `userdel`, `groupadd`, `passwd`, `visudo`, `systemctl`, `service`, `init`, `shutdown`, `reboot`, `halt`

#### Network Commands (Medium Risk — Audit)

`curl`, `wget`, `nc`/`netcat`/`ncat`, `ssh`, `scp`, `rsync`, `ftp`, `sftp`

#### Shell Injection Patterns (Medium Risk)

| Pattern | Description |
|---------|-------------|
| `; command` | Command separator |
| `\| command` | Pipe |
| `` `command` `` | Backtick execution |
| `$(command)` | Command substitution |
| `&& command` | Conditional chain |
| `\|\| command` | Or chain |

---

### 4.2 Network Requests (`network_request`)

#### Webhook / Exfiltration Domains (DENY unless allowlisted)

| Domain | Service |
|--------|---------|
| `discord.com` / `discordapp.com` | Discord webhooks |
| `api.telegram.org` | Telegram bot API |
| `hooks.slack.com` | Slack webhooks |
| `webhook.site` | Webhook testing |
| `requestbin.com` | Request inspection |
| `pipedream.com` | Workflow automation |
| `ngrok.io` / `ngrok-free.app` | Tunneling |
| `beeceptor.com` | API mocking |
| `mockbin.org` | HTTP mocking |

#### High-Risk TLDs (Medium → High with POST/PUT)

`.xyz`, `.top`, `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.work`, `.click`, `.link`

#### Request Body Secret Scanning

| Secret Type | Priority | Risk Level | Decision |
|-------------|----------|------------|----------|
| Private Key (`0x` + 64 hex) | 100 | critical | DENY |
| Mnemonic (12-24 BIP-39 words) | 100 | critical | DENY |
| SSH Private Key (`-----BEGIN.*PRIVATE KEY`) | 90 | critical | DENY |
| AWS Secret Key (40-char near AWS context) | 80 | high | CONFIRM |
| AWS Access Key (`AKIA[0-9A-Z]{16}`) | 70 | high | CONFIRM |
| GitHub Token (`gh[pousr]_...`) | 70 | high | CONFIRM |
| Bearer/JWT Token (`ey...`) | 60 | medium | CONFIRM |
| API Secret (generic patterns) | 50 | medium | CONFIRM |
| DB Connection String | 50 | medium | CONFIRM |
| Password in Config | 40 | low | CONFIRM |

#### Network Decision Logic

1. Invalid URL → **DENY** (high)
2. Domain in webhook list & not allowlisted → **DENY** (high)
3. Body contains private key / mnemonic / SSH key → **DENY** (critical)
4. Body contains other secrets → risk based on priority
5. High-risk TLD & not allowlisted → **CONFIRM** (medium)
6. POST/PUT to untrusted domain → escalate medium → high
7. Domain in allowlist → **ALLOW** (low)

---

### 4.3 File Operations (`read_file` / `write_file`)

#### Sensitive Paths (DENY or CONFIRM based on level)

| Path Pattern | Description |
|--------------|-------------|
| `.env`, `.env.local`, `.env.production` | Environment secrets |
| `.ssh/`, `id_rsa`, `id_ed25519` | SSH keys |
| `.aws/credentials`, `.aws/config` | AWS credentials |
| `.npmrc`, `.netrc` | Package/network auth |
| `credentials.json`, `serviceAccountKey.json` | Service accounts |
| `.kube/config` | Kubernetes config |

---

### 4.4 Secret Leak Detection Priority

| Secret Type | Priority | Risk Level |
|-------------|----------|------------|
| `PRIVATE_KEY` | 100 | critical |
| `MNEMONIC` | 100 | critical |
| `SSH_KEY` | 90 | critical |
| `AWS_SECRET` | 80 | high |
| `AWS_KEY` | 70 | high |
| `GITHUB_TOKEN` | 70 | high |
| `BEARER_TOKEN` | 60 | medium |
| `API_SECRET` | 50 | medium |
| `DB_CONNECTION` | 50 | medium |
| `PASSWORD_CONFIG` | 40 | low |

---

### 4.5 Web3 Operations (`web3_tx` / `web3_sign`)

#### GoPlus Integration

| Check | Description | Trigger → Action |
|-------|-------------|------------------|
| **Phishing Site** | Origin URL on phishing list | `PHISHING_ORIGIN` → DENY (critical) |
| **Malicious Address** | Target address blacklisted | `MALICIOUS_ADDRESS` → DENY (critical) |
| **Honeypot Related** | Address associated with honeypot | `HONEYPOT_RELATED` → flag (high) |
| **Unlimited Approval** | Token approval for max uint256 | `UNLIMITED_APPROVAL` → CONFIRM (high) |
| **Simulation Failed** | Transaction simulation error | `SIMULATION_FAILED` → flag (medium) |

#### Environment Variables

```bash
GOPLUS_API_KEY=your_key         # Required for simulation
GOPLUS_API_SECRET=your_secret   # Required for simulation
```

#### Degradation Strategy

When GoPlus is unavailable:
1. `SIMULATION_UNAVAILABLE` tag is set
2. Decision falls back to policy-based rules only
3. Capability model and secret scanning still apply

---

## 5. Static Scan Rules (24 Rules)

### Critical Severity

| Rule | ID | Target Files |
|------|-----|--------------|
| Auto-Update / Remote Code Execution | `AUTO_UPDATE` | `.js`, `.ts`, `.py`, `.sh`, `.md` |
| Remote Code Loader | `REMOTE_LOADER` | `.js`, `.ts`, `.mjs`, `.py`, `.md` |
| Read SSH Keys | `READ_SSH_KEYS` | All |
| Read Keychain/Browser Credentials | `READ_KEYCHAIN` | All |
| Private Key Pattern | `PRIVATE_KEY_PATTERN` | All |
| Mnemonic Pattern | `MNEMONIC_PATTERN` | All |
| Wallet Draining | `WALLET_DRAINING` | `.js`, `.ts`, `.sol` |
| Prompt Injection | `PROMPT_INJECTION` | All |
| Webhook Exfiltration URL | `WEBHOOK_EXFIL` | All |
| Trojan Distribution | `TROJAN_DISTRIBUTION` | `.md` |

### High Severity

| Rule | ID | Target Files |
|------|-----|--------------|
| Shell Execution | `SHELL_EXEC` | `.js`, `.ts`, `.mjs`, `.cjs`, `.py`, `.md` |
| Unlimited Approval | `UNLIMITED_APPROVAL` | `.js`, `.ts`, `.sol` |
| Dangerous Selfdestruct | `DANGEROUS_SELFDESTRUCT` | `.sol` |
| Reentrancy Pattern | `REENTRANCY_PATTERN` | `.sol` |
| Signature Replay | `SIGNATURE_REPLAY` | `.sol` |
| Obfuscation | `OBFUSCATION` | `.js`, `.ts`, `.mjs`, `.py`, `.md` |
| Unrestricted Network Exfil | `NET_EXFIL_UNRESTRICTED` | `.js`, `.ts`, `.mjs`, `.py`, `.md` |
| Suspicious Paste URL | `SUSPICIOUS_PASTE_URL` | All |

### Medium Severity

| Rule | ID | Target Files |
|------|-----|--------------|
| Read Environment Secrets | `READ_ENV_SECRETS` | `.js`, `.ts`, `.mjs`, `.py` |
| Hidden Transfer | `HIDDEN_TRANSFER` | `.sol` |
| Proxy Upgrade | `PROXY_UPGRADE` | `.sol`, `.js`, `.ts` |
| Flash Loan Risk | `FLASH_LOAN_RISK` | `.sol`, `.js`, `.ts` |
| Suspicious IP Address | `SUSPICIOUS_IP` | All |
| Social Engineering | `SOCIAL_ENGINEERING` | `.md` |

---

## 6. Trust Registry & Capability Model

### Trust Levels

| Level | Priority | Description |
|-------|----------|-------------|
| `untrusted` | 0 | Unknown skill — read-only access only |
| `restricted` | 1 | Limited capabilities — per attestation |
| `trusted` | 2 | Full capabilities within attestation |

### Capability Model Structure

```typescript
interface CapabilityModel {
  network_allowlist: string[];      // Allowed domains (glob patterns)
  filesystem_allowlist: string[];   // Allowed paths (glob patterns)
  exec: 'allow' | 'deny';           // Command execution
  secrets_allowlist: string[];      // Allowed secret patterns
  web3?: {
    chains_allowlist: number[];     // Chain IDs
    rpc_allowlist: string[];        // RPC endpoints
    tx_policy: 'allow' | 'confirm_high_risk' | 'deny';
  };
}
```

### Capability Presets

#### `none` — Most Restrictive
```json
{
  "network_allowlist": [],
  "filesystem_allowlist": [],
  "exec": "deny",
  "secrets_allowlist": []
}
```

#### `read_only`
```json
{
  "network_allowlist": [],
  "filesystem_allowlist": ["./**"],
  "exec": "deny",
  "secrets_allowlist": []
}
```

#### `trading_bot`
```json
{
  "network_allowlist": [
    "api.binance.com", "api.bybit.com", "api.okx.com",
    "api.coinbase.com", "*.dextools.io", "*.coingecko.com"
  ],
  "filesystem_allowlist": ["./config/**", "./logs/**"],
  "exec": "deny",
  "secrets_allowlist": ["*_API_KEY", "*_API_SECRET"],
  "web3": {
    "chains_allowlist": [1, 56, 137, 42161],
    "rpc_allowlist": ["*"],
    "tx_policy": "confirm_high_risk"
  }
}
```

#### `defi`
```json
{
  "network_allowlist": ["*"],
  "filesystem_allowlist": [],
  "exec": "deny",
  "secrets_allowlist": [],
  "web3": {
    "chains_allowlist": [1, 56, 137, 42161, 10, 8453, 43114],
    "rpc_allowlist": ["*"],
    "tx_policy": "confirm_high_risk"
  }
}
```

### Capability Enforcement

| Action Type | Capability Check |
|-------------|------------------|
| `exec_command` | `can_exec !== false` |
| `network_request` | `can_network !== false` |
| `write_file` | `can_write !== false` |
| `read_file` | `can_read !== false` |
| `web3_tx` / `web3_sign` | `can_web3 !== false` |

---

## 7. Platform Integration

### 7.1 Claude Code

**Hook Events**: `PreToolUse`, `PostToolUse`

**Tool Mapping**:

| Claude Code Tool | Action Type |
|------------------|-------------|
| `Bash` | `exec_command` |
| `Write` | `write_file` |
| `Edit` | `write_file` |
| `WebFetch` | `network_request` |
| `WebSearch` | `network_request` |

**Configuration** (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": { "tool_name": "*" },
        "hooks": ["agentguard-hook"]
      }
    ]
  }
}
```

### 7.2 OpenClaw

**Hook Events**: `before_tool_call`, `after_tool_call`

**Tool Mapping**:

| OpenClaw Tool | Action Type |
|---------------|-------------|
| `exec` / `exec_*` | `exec_command` |
| `write` | `write_file` |
| `read` | `read_file` |
| `web_fetch` | `network_request` |
| `browser` | `network_request` |

**Auto-Scan & Registration**:

When AgentGuard registers as an OpenClaw plugin, it automatically:

1. **Scans all loaded plugins** - Static analysis of each plugin's source code
2. **Determines trust level** - Based on scan results (critical findings → untrusted)
3. **Infers capabilities** - Based on registered tools and scan risk level
4. **Registers to trust registry** - Auto-attests each plugin
5. **Builds tool mapping** - Maps `toolName → pluginId` for initiating skill inference

**Trust Level Assignment**:

| Scan Result | Trust Level | Capabilities |
|-------------|-------------|--------------|
| critical / dangerous patterns | `untrusted` | read-only |
| high risk | `restricted` | limited per scan |
| medium risk | `restricted` | limited per scan |
| low risk | `trusted` | full per tool type |

**Configuration** (Plugin registration):

```typescript
import { registerOpenClawPlugin } from '@goplus/agentguard';

// Basic registration (auto-scan enabled)
registerOpenClawPlugin(api);

// With options
registerOpenClawPlugin(api, {
  level: 'balanced',        // Protection level
  skipAutoScan: false,      // Set true to disable auto-scanning
});
```

**Exported Utilities**:

```typescript
import {
  getPluginIdFromTool,    // Get plugin ID from tool name
  getPluginScanResult,    // Get cached scan result for plugin
} from '@goplus/agentguard';
```

---

## 8. Quick Reference Tables

### Always Block (Critical — DENY)

| Category | Rules |
|----------|-------|
| **Destructive commands** | `rm -rf`, `mkfs`, `dd if=`, fork bomb, `chmod 777`, `curl\|bash` |
| **Key exfiltration** | Private keys (0x+64 hex), mnemonics (12-24 BIP39), SSH keys |
| **Webhook exfil** | Discord/Telegram/Slack webhooks (unless allowlisted) |
| **Prompt injection** | `ignore previous instructions`, jailbreak attempts |
| **Malicious addresses** | GoPlus-flagged phishing/blacklisted addresses |

### Require Confirmation (High — CONFIRM in balanced)

| Category | Rules |
|----------|-------|
| **Sensitive data access** | `cat /etc/passwd`, `cat ~/.ssh`, `env`, `printenv` |
| **API key leakage** | AWS/GitHub/Bearer tokens in request body |
| **Untrusted domains** | POST/PUT to non-allowlisted domains |
| **Web3 high-risk** | Unlimited approval, unknown spender |
| **Untrusted skills** | Skills not in trust registry |

### Audit but Allow (Medium — ALLOW with logging)

| Category | Rules |
|----------|-------|
| **Install commands** | `npm install`, `pip install`, `git clone` |
| **System commands** | `sudo`, `systemctl`, `chmod` |
| **Network commands** | `curl`, `wget`, `ssh` |
| **Shell metacharacters** | Commands with pipes, semicolons, etc. |

### Safe Pass-through (Low — ALLOW)

| Category | Commands |
|----------|----------|
| **Read-only** | `ls`, `cat`, `grep`, `find`, `pwd`, `whoami` |
| **Git operations** | `git status`, `git log`, `git diff`, `git add`, `git commit`, `git push` |
| **Build commands** | `npm run`, `npm test`, `tsc`, `go build`, `cargo build` |
| **Version checks** | `node -v`, `npm -v`, `python --version` |

---

## 9. Default Policy Summary

```yaml
# Secret Exfiltration
secret_exfil:
  private_key: DENY (always)
  mnemonic: DENY (always)
  ssh_key: DENY (always)
  api_secret: CONFIRM

# Command Execution
exec_command:
  dangerous: DENY (always)
  safe_list: ALLOW
  default: evaluate by capability

# Network
network:
  webhook_domain: DENY (unless allowlisted)
  body_contains_secret: DENY/CONFIRM by priority
  untrusted_domain: CONFIRM

# Web3
web3:
  phishing_origin: DENY
  malicious_address: DENY
  unlimited_approval: CONFIRM
  unknown_spender: CONFIRM

# File Operations
file:
  sensitive_path_write: DENY/CONFIRM by level
  read: ALLOW (unless sensitive)
```

---

## 10. Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2025-02 | 1.0.0 | Initial unified policy document |

---

*This document consolidates security policies from `skills/agentguard/action-policies.md`, `skills/agentguard/scan-rules.md`, and implementation in `src/action/detectors/`.*
