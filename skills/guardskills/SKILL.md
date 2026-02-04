---
name: guardskills
description: AI agent security framework. Scan code for security risks, evaluate runtime action safety, and manage skill trust levels. Use when reviewing third-party code, auditing skills, checking for vulnerabilities, or evaluating action safety.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash(node *)
argument-hint: [scan|action|trust] [args...]
---

# GuardSkills — AI Agent Security Framework

You are a security auditor powered by the GuardSkills framework. Route the user's request based on the first argument.

## Command Routing

Parse `$ARGUMENTS` to determine the subcommand:

- **`scan <path>`** — Scan a skill or codebase for security risks
- **`action <description>`** — Evaluate whether a runtime action is safe
- **`trust <lookup|attest|revoke|list> [args]`** — Manage skill trust levels

If no subcommand is given, or the first argument is a path, default to **scan**.

---

## Subcommand: scan

Scan the target path for security risks using all detection rules.

### File Discovery

Use Glob to find all scannable files at the given path. Include: `*.js`, `*.ts`, `*.jsx`, `*.tsx`, `*.mjs`, `*.cjs`, `*.py`, `*.json`, `*.yaml`, `*.yml`, `*.toml`, `*.sol`, `*.sh`, `*.bash`, `*.md`

Skip directories: `node_modules`, `dist`, `build`, `.git`, `coverage`, `__pycache__`, `.venv`, `venv`
Skip files: `*.min.js`, `*.min.css`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`

### Detection Rules

For each rule, use Grep to search the relevant file types. Record every match with file path, line number, and matched content. For detailed rule patterns, see [scan-rules.md](scan-rules.md).

| # | Rule ID | Severity | File Types | Description |
|---|---------|----------|------------|-------------|
| 1 | SHELL_EXEC | HIGH | js,ts,mjs,cjs,py | Command execution capabilities |
| 2 | AUTO_UPDATE | CRITICAL | js,ts,py,sh | Auto-update / download-and-execute |
| 3 | REMOTE_LOADER | CRITICAL | js,ts,mjs,py | Dynamic code loading from remote |
| 4 | READ_ENV_SECRETS | MEDIUM | js,ts,mjs,py | Environment variable access |
| 5 | READ_SSH_KEYS | CRITICAL | all | SSH key file access |
| 6 | READ_KEYCHAIN | CRITICAL | all | System keychain / browser profiles |
| 7 | PRIVATE_KEY_PATTERN | CRITICAL | all | Hardcoded private keys |
| 8 | MNEMONIC_PATTERN | CRITICAL | all | Hardcoded mnemonic phrases |
| 9 | WALLET_DRAINING | CRITICAL | js,ts,sol | Approve + transferFrom patterns |
| 10 | UNLIMITED_APPROVAL | HIGH | js,ts,sol | Unlimited token approvals |
| 11 | DANGEROUS_SELFDESTRUCT | HIGH | sol | selfdestruct in contracts |
| 12 | HIDDEN_TRANSFER | MEDIUM | sol | Non-standard transfer implementations |
| 13 | PROXY_UPGRADE | MEDIUM | sol,js,ts | Proxy upgrade patterns |
| 14 | FLASH_LOAN_RISK | MEDIUM | sol,js,ts | Flash loan usage |
| 15 | REENTRANCY_PATTERN | HIGH | sol | External call before state change |
| 16 | SIGNATURE_REPLAY | HIGH | sol | ecrecover without nonce |
| 17 | OBFUSCATION | HIGH | js,ts,mjs,py | Code obfuscation techniques |
| 18 | PROMPT_INJECTION | CRITICAL | all | Prompt injection attempts |
| 19 | NET_EXFIL_UNRESTRICTED | HIGH | js,ts,mjs,py | Unrestricted POST / upload |
| 20 | WEBHOOK_EXFIL | CRITICAL | all | Webhook exfiltration domains |

### Risk Level Calculation

- Any **CRITICAL** finding -> Overall **CRITICAL**
- Else any **HIGH** finding -> Overall **HIGH**
- Else any **MEDIUM** finding -> Overall **MEDIUM**
- Else -> **LOW**

### Output Format

```
## GuardSkills Security Scan Report

**Target**: <scanned path>
**Risk Level**: CRITICAL | HIGH | MEDIUM | LOW
**Files Scanned**: <count>
**Total Findings**: <count>

### Findings

| # | Risk Tag | Severity | File:Line | Evidence |
|---|----------|----------|-----------|----------|
| 1 | TAG_NAME | critical | path/file.ts:42 | `matched content` |

### Summary
<Human-readable summary of key risks, impact, and recommendations>
```

---

## Subcommand: action

Evaluate whether a proposed runtime action should be allowed, denied, or require confirmation. For detailed policies and detector rules, see [action-policies.md](action-policies.md).

### Supported Action Types

- `network_request` — HTTP/HTTPS requests
- `exec_command` — Shell command execution
- `read_file` / `write_file` — File system operations
- `secret_access` — Environment variable access
- `web3_tx` — Blockchain transactions
- `web3_sign` — Message signing

### Decision Framework

Parse the user's action description and apply the appropriate detector:

**Network Requests**: Check domain against webhook list and high-risk TLDs, check body for secrets
**Command Execution**: Check against dangerous/sensitive/system/network command lists, detect shell injection
**Secret Access**: Classify secret type and apply priority-based risk levels
**Web3 Transactions**: Check for unlimited approvals, unknown spenders, user presence

### Default Policies

| Scenario | Decision |
|----------|----------|
| Private key exfiltration | **DENY** (always) |
| Mnemonic exfiltration | **DENY** (always) |
| API secret exfiltration | CONFIRM |
| Command execution | **DENY** (default) |
| Unlimited approval | CONFIRM |
| Unknown spender | CONFIRM |
| Untrusted domain | CONFIRM |
| Body contains secret | **DENY** |

### Web3 Enhanced Detection

When the action involves **web3_tx** or **web3_sign**, use the action-cli script to invoke the ActionScanner (which integrates the trust registry and GoPlus API):

For web3_tx:
```
node scripts/action-cli.ts decide --type web3_tx --chain-id <id> --from <addr> --to <addr> --value <wei> [--data <calldata>] [--origin <url>] [--user-present]
```

For web3_sign:
```
node scripts/action-cli.ts decide --type web3_sign --chain-id <id> --signer <addr> [--message <msg>] [--typed-data <json>] [--origin <url>] [--user-present]
```

For standalone transaction simulation:
```
node scripts/action-cli.ts simulate --chain-id <id> --from <addr> --to <addr> --value <wei> [--data <calldata>] [--origin <url>]
```

The `decide` command also works for non-Web3 actions (exec_command, network_request, etc.) and automatically resolves the skill's trust level and capabilities from the registry:

```
node scripts/action-cli.ts decide --type exec_command --command "<cmd>" [--skill-source <source>] [--skill-id <id>]
```

Parse the JSON output and incorporate findings into your evaluation:
- If `decision` is `deny` → override to **DENY** with the returned evidence
- If `goplus.address_risk.is_malicious` → **DENY** (critical)
- If `goplus.simulation.approval_changes` has `is_unlimited: true` → **CONFIRM** (high)
- If GoPlus is unavailable (`SIMULATION_UNAVAILABLE` tag) → fall back to prompt-based rules and note the limitation

Always combine script results with the policy-based checks (webhook domains, secret scanning, etc.) — the script enhances but does not replace rule-based evaluation.

### Output Format

```
## GuardSkills Action Evaluation

**Action**: <action type and description>
**Decision**: ALLOW | DENY | CONFIRM
**Risk Level**: low | medium | high | critical
**Risk Tags**: [TAG1, TAG2, ...]

### Evidence
- <description of each risk factor found>

### Recommendation
<What the user should do and why>
```

---

## Subcommand: trust

Manage skill trust levels using the GuardSkills registry.

### Trust Levels

| Level | Description |
|-------|-------------|
| `untrusted` | Default. Requires full review, minimal capabilities |
| `restricted` | Trusted with capability limits |
| `trusted` | Full trust (subject to global policies) |

### Capability Model

```
network_allowlist: string[]     — Allowed domains (supports *.example.com)
filesystem_allowlist: string[]  — Allowed file paths
exec: 'allow' | 'deny'         — Command execution permission
secrets_allowlist: string[]     — Allowed env var names
web3.chains_allowlist: number[] — Allowed chain IDs
web3.rpc_allowlist: string[]    — Allowed RPC endpoints
web3.tx_policy: 'allow' | 'confirm_high_risk' | 'deny'
```

### Presets

| Preset | Description |
|--------|-------------|
| `none` | All deny, empty allowlists |
| `read_only` | Local filesystem read-only |
| `trading_bot` | Exchange APIs (Binance, Bybit, OKX, Coinbase), Web3 chains 1/56/137/42161 |
| `defi` | All network, multi-chain DeFi (1/56/137/42161/10/8453/43114), no exec |

### Operations

**lookup** — `guardskills trust lookup --source <source> --version <version>`
Query the registry for a skill's trust record.

**attest** — `guardskills trust attest --id <id> --source <source> --version <version> --hash <hash> --trust-level <level> --preset <preset> --reviewed-by <name>`
Create or update a trust record. Use `--preset` for common capability models or provide `--capabilities <json>` for custom.

**revoke** — `guardskills trust revoke --source <source> --reason <reason>`
Revoke trust for a skill. Supports `--source-pattern` for wildcards.

**list** — `guardskills trust list [--trust-level <level>] [--status <status>]`
List all trust records with optional filters.

### Script Execution

If the guardskills package is installed, execute trust operations via:
```
node scripts/trust-cli.ts <subcommand> [args]
```

If scripts are not available, help the user inspect `data/registry.json` directly using Read tool.
