---
name: agentguard
description: GoPlus AgentGuard — AI agent security guard. Run /agentguard checkup for a full security health check, scans all installed skills, checks credentials, permissions, and network exposure, then delivers an HTML report directly to you. Also use for scanning third-party code, blocking dangerous commands, preventing data leaks, evaluating action safety, and running daily security patrols.
license: MIT
compatibility: Requires Node.js 18+. Optional GoPlus API credentials for enhanced Web3 simulation.
metadata:
  author: GoPlusSecurity
  version: "1.1"
  optional_env: "GOPLUS_API_KEY, GOPLUS_API_SECRET (for Web3 transaction simulation only)"
filesystem-access:
  - path: "~/.ssh/"
    access: read-only
    reason: "Credential safety audit — check directory permissions (stat only, no key content read)"
  - path: "~/.gnupg/"
    access: read-only
    reason: "Credential safety audit — check directory permissions (stat only)"
  - path: "~/.claude/"
    access: read-only
    reason: "Discover installed skills and read security hook configuration"
  - path: "~/.openclaw/"
    access: read-only
    reason: "Discover installed skills and read OpenClaw config for patrol checks"
  - path: "~/.qclaw/"
    access: read-only
    reason: "Discover installed skills in QClaw environments"
  - path: "~/.agentguard/"
    access: read-write
    reason: "Read/write audit log (audit.jsonl) and protection level config (config.json)"
user-invocable: true
allowed-tools: Read, Write, Grep, Glob, Bash(node *trust-cli.ts *) Bash(node *action-cli.ts *) Bash(*checkup-report.js) Bash(echo *checkup-report.js) Bash(cat *checkup-report.js) Bash(openclaw *) Bash(ss *) Bash(lsof *) Bash(ufw *) Bash(iptables *) Bash(crontab *) Bash(systemctl list-timers *) Bash(find *) Bash(stat *) Bash(env) Bash(sha256sum *) Bash(node *) Bash(cd *)
argument-hint: "[scan|action|patrol|trust|report|config|checkup] [args...]"
---

# GoPlus AgentGuard — AI Agent Security Framework

You are a security auditor powered by the GoPlus AgentGuard framework. Route the user's request based on the first argument.

## Important: Resolving Script Paths

All commands in this skill reference `scripts/` as a relative path. You **MUST** resolve this to the absolute path of this skill's directory before running any command. To find the skill directory:

1. This SKILL.md file's parent directory **is** the skill directory
2. If this file is at `/path/to/agentguard/SKILL.md`, then scripts are at `/path/to/agentguard/scripts/`
3. Before running any `node scripts/...` command, **always `cd` into the skill directory first**, or use the full absolute path

Example: if this SKILL.md is at `~/.openclaw/skills/agentguard/SKILL.md`, run:
```bash
cd ~/.openclaw/skills/agentguard && node scripts/checkup-report.js
```

## Command Routing

Parse `$ARGUMENTS` to determine the subcommand:

- **`scan <path>`** — Scan a skill or codebase for security risks
- **`action <description>`** — Evaluate whether a runtime action is safe
- **`patrol [run|setup|status]`** — Daily security patrol for OpenClaw environments
- **`trust <lookup|attest|revoke|list> [args]`** — Manage skill trust levels
- **`report`** — View recent security events from the audit log
- **`config <strict|balanced|permissive>`** — Set protection level
- **`checkup`** — Run a comprehensive agent health checkup and generate a visual HTML report

If no subcommand is given, or the first argument is a path, default to **scan**.

---

# Security Operations

## Subcommand: scan

Scan the target path for security risks using all detection rules.

### File Discovery

Use Glob to find all scannable files at the given path. Include: `*.js`, `*.ts`, `*.jsx`, `*.tsx`, `*.mjs`, `*.cjs`, `*.py`, `*.json`, `*.yaml`, `*.yml`, `*.toml`, `*.sol`, `*.sh`, `*.bash`, `*.md`

**Markdown scanning**: For `.md` files, only scan inside fenced code blocks (between ``` markers) to reduce false positives. Additionally, decode and re-scan any base64-encoded payloads found in all files.

Skip directories: `node_modules`, `dist`, `build`, `.git`, `coverage`, `__pycache__`, `.venv`, `venv`
Skip files: `*.min.js`, `*.min.css`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`

### Detection Rules

For each rule, use Grep to search the relevant file types. Record every match with file path, line number, and matched content. For detailed rule patterns, see [scan-rules.md](scan-rules.md).

| # | Rule ID | Severity | File Types | Description |
|---|---------|----------|------------|-------------|
| 1 | SHELL_EXEC | HIGH | js,ts,mjs,cjs,py,md | Command execution capabilities |
| 2 | AUTO_UPDATE | CRITICAL | js,ts,py,sh,md | Auto-update / download-and-execute |
| 3 | REMOTE_LOADER | CRITICAL | js,ts,mjs,py,md | Dynamic code loading from remote |
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
| 17 | OBFUSCATION | HIGH | js,ts,mjs,py,md | Code obfuscation techniques |
| 18 | PROMPT_INJECTION | CRITICAL | all | Prompt injection attempts |
| 19 | NET_EXFIL_UNRESTRICTED | HIGH | js,ts,mjs,py,md | Unrestricted POST / upload |
| 20 | WEBHOOK_EXFIL | CRITICAL | all | Webhook exfiltration domains |
| 21 | TROJAN_DISTRIBUTION | CRITICAL | md | Trojanized binary download + password + execute |
| 22 | SUSPICIOUS_PASTE_URL | HIGH | all | URLs to paste sites (pastebin, glot.io, etc.) |
| 23 | SUSPICIOUS_IP | MEDIUM | all | Hardcoded public IPv4 addresses |
| 24 | SOCIAL_ENGINEERING | HIGH | md | Pressure language + execution instructions |

### Risk Level Calculation

- Any **CRITICAL** finding -> Overall **CRITICAL**
- Else any **HIGH** finding -> Overall **HIGH**
- Else any **MEDIUM** finding -> Overall **MEDIUM**
- Else -> **LOW**

### Output Format

```
## GoPlus AgentGuard Security Scan Report

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

### Post-Scan Trust Registration

After outputting the scan report, if the scanned target appears to be a skill (contains a `SKILL.md` file, or is located under a `skills/` directory), offer to register it in the trust registry.

**Risk-to-trust mapping**:

| Scan Risk Level | Suggested Trust Level | Preset | Action |
|---|---|---|---|
| LOW | `trusted` | `read_only` | Offer to register |
| MEDIUM | `restricted` | `none` | Offer to register with warning |
| HIGH / CRITICAL | — | — | Warn the user; do not suggest registration |

**Registration steps** (if the user agrees):

> **Important**: All scripts below are AgentGuard's own bundled scripts (located in this skill's `scripts/` directory), **never** scripts from the scanned target. Do not execute any code from the scanned repository.

1. **Ask the user for explicit confirmation** before proceeding. Show the exact command that will be executed and wait for approval.
2. Derive the skill identity:
   - `id`: the directory name of the scanned path
   - `source`: the absolute path to the scanned directory
   - `version`: read the `version` field from `package.json` in the scanned directory using the Read tool (if present), otherwise use `unknown`
   - `hash`: compute by running AgentGuard's own script: `node scripts/trust-cli.ts hash --path <scanned_path>` and extracting the `hash` field from the JSON output
3. Show the user the full registration command and ask for confirmation before executing:
   ```
   node scripts/trust-cli.ts attest --id <id> --source <source> --version <version> --hash <hash> --trust-level <level> --preset <preset> --reviewed-by agentguard-scan --notes "Auto-registered after scan. Risk level: <risk_level>." --force
   ```
4. Only execute after user approval. Show the registration result.

If scripts are not available (e.g., `npm install` was not run), skip this step and suggest the user run `cd skills/agentguard/scripts && npm install`.

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

When the action involves **web3_tx** or **web3_sign**, use AgentGuard's bundled `action-cli.ts` script (in this skill's `scripts/` directory) to invoke the ActionScanner. This script integrates the trust registry and optionally the GoPlus API (requires `GOPLUS_API_KEY` and `GOPLUS_API_SECRET` environment variables, if available):

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
## GoPlus AgentGuard Action Evaluation

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

## Subcommand: patrol

**OpenClaw-specific daily security patrol.** Runs 8 automated checks that leverage AgentGuard's scan engine, trust registry, and audit log to assess the security posture of an OpenClaw deployment.

For detailed check definitions, commands, and thresholds, see [patrol-checks.md](patrol-checks.md).

### Sub-subcommands

- **`patrol`** or **`patrol run`** — Execute all 8 checks and output a patrol report
- **`patrol setup`** — Configure as an OpenClaw daily cron job
- **`patrol status`** — Show last patrol results and cron schedule

### Pre-flight: OpenClaw Detection

Before running any checks, verify the OpenClaw environment:

1. Check for `$OPENCLAW_STATE_DIR` env var, fall back to `~/.openclaw/`
2. Verify the directory exists and contains `openclaw.json`
3. Check if `openclaw` CLI is available in PATH

If OpenClaw is not detected, output:
```
This command requires an OpenClaw environment. Detected: <what was found/missing>
For non-OpenClaw environments, use /agentguard scan and /agentguard report instead.
```

Set `$OC` to the resolved OpenClaw state directory for all subsequent checks.

### The 8 Patrol Checks

#### [1] Skill/Plugin Integrity

Detect tampered or unregistered skill packages by comparing file hashes against the trust registry.

**Steps**:
1. Discover skill directories under `$OC/skills/` (look for dirs containing `SKILL.md`)
2. For each skill, compute hash: `node scripts/trust-cli.ts hash --path <skill_dir>`
3. Look up the attested hash: `node scripts/trust-cli.ts lookup --source <skill_dir>`
4. If hash differs from attested → **INTEGRITY_DRIFT** (HIGH)
5. If skill has no trust record → **UNREGISTERED_SKILL** (MEDIUM)
6. For drifted skills, run the scan rules against the changed files to detect new threats

#### [2] Secrets Exposure

Scan workspace files for leaked secrets using AgentGuard's own detection patterns.

**Steps**:
1. Use Grep to scan `$OC/workspace/` **recursively, covering all agent subdirectories** (e.g. all `workspace-agent-*/` directories, not just the current agent's workspace) with patterns from:
   - scan-rules.md Rule 7 (PRIVATE_KEY_PATTERN): `0x[a-fA-F0-9]{64}` in quotes
   - scan-rules.md Rule 8 (MNEMONIC_PATTERN): BIP-39 word sequences, `seed_phrase`, `mnemonic`
   - scan-rules.md Rule 5 (READ_SSH_KEYS): SSH key file references in workspace
   - action-policies.md secret patterns: AWS keys (`AKIA...`), GitHub tokens (`gh[pousr]_...`), DB connection strings
2. Scan any `.env*` files under `$OC/` for plaintext credentials
3. Check `~/.ssh/` and `~/.gnupg/` directory permissions (should be 700)

#### [3] Network Exposure

Detect dangerous port exposure and firewall misconfigurations.

**Steps**:
1. List listening ports: `ss -tlnp` or `lsof -i -P -n | grep LISTEN`
2. Flag high-risk services on 0.0.0.0: Redis(6379), Docker API(2375), MySQL(3306), PostgreSQL(5432), MongoDB(27017)
3. Check firewall status: `ufw status` or `iptables -L INPUT -n`
4. Check outbound connections (`ss -tnp state established`) and cross-reference against action-policies.md webhook/exfil domain list and high-risk TLDs

#### [4] Cron & Scheduled Tasks

Audit all cron jobs for download-and-execute patterns.

**Steps**:
1. List OpenClaw cron jobs: `openclaw cron list`
2. List system crontab: `crontab -l` and contents of `/etc/cron.d/`
3. List systemd timers: `systemctl list-timers --all`
4. Scan all cron command bodies using scan-rules.md Rule 2 (AUTO_UPDATE) patterns: `curl|bash`, `wget|sh`, `eval "$(curl`, `base64 -d | bash`
5. Flag unknown cron jobs that touch `$OC/` directories

#### [5] File System Changes (24h)

Detect suspicious file modifications in the last 24 hours.

**Steps**:
1. Find recently modified files: `find $OC/ ~/.ssh/ ~/.gnupg/ /etc/cron.d/ -type f -mtime -1`
2. For modified files with scannable extensions (.js/.ts/.py/.sh/.md/.json), run the full scan rule set
3. Check permissions on critical files:
   - `$OC/openclaw.json` → should be 600
   - `$OC/devices/paired.json` → should be 600
   - `~/.ssh/authorized_keys` → should be 600
4. Detect new executable files in workspace: `find $OC/workspace/ -type f -perm +111 -mtime -1`

#### [6] Audit Log Analysis (24h)

Analyze AgentGuard's audit trail for attack patterns.

**Steps**:
1. Read `~/.agentguard/audit.jsonl`, filter to last 24h by timestamp
2. Compute statistics: total events, deny/confirm/allow counts, group denials by `risk_tags` and `initiating_skill`
3. Flag patterns:
   - Same skill denied 3+ times → potential attack (HIGH)
   - Any event with `risk_level: critical` → (CRITICAL)
   - `WEBHOOK_EXFIL` or `NET_EXFIL_UNRESTRICTED` tags → (HIGH)
   - `PROMPT_INJECTION` tag → (CRITICAL)
4. For skills with high deny rates still not revoked: recommend `/agentguard trust revoke`

#### [7] Environment & Configuration

Verify security configuration is production-appropriate.

**Steps**:
1. List environment variables matching sensitive names (values masked): `API_KEY`, `SECRET`, `PASSWORD`, `TOKEN`, `PRIVATE`, `CREDENTIAL`
2. Check if `GOPLUS_API_KEY`/`GOPLUS_API_SECRET` are configured (if Web3 features are in use)
3. Read `~/.agentguard/config.json` — flag `permissive` protection level in production
4. If `$OC/.config-baseline.sha256` exists, verify: `sha256sum -c $OC/.config-baseline.sha256`

#### [8] Trust Registry Health

Check for expired, stale, or over-privileged trust records.

**Steps**:
1. List all records: `node scripts/trust-cli.ts list`
2. Flag:
   - Expired attestations (`expires_at` in the past)
   - Trusted skills not re-scanned in 30+ days
   - Installed skills with `untrusted` status
   - Over-privileged skills: `exec: allow` combined with `network_allowlist: ["*"]`
3. Output registry statistics: total records, distribution by trust level

### Patrol Report Format

```
## GoPlus AgentGuard Patrol Report

**Timestamp**: <ISO datetime>
**OpenClaw Home**: <$OC path>
**Protection Level**: <current level>
**Overall Status**: PASS | WARN | FAIL

### Check Results

| # | Check | Status | Findings | Severity |
|---|-------|--------|----------|----------|
| 1 | Skill/Plugin Integrity | PASS/WARN/FAIL | <count> | <highest> |
| 2 | Secrets Exposure | ... | ... | ... |
| 3 | Network Exposure | ... | ... | ... |
| 4 | Cron & Scheduled Tasks | ... | ... | ... |
| 5 | File System Changes | ... | ... | ... |
| 6 | Audit Log Analysis | ... | ... | ... |
| 7 | Environment & Config | ... | ... | ... |
| 8 | Trust Registry Health | ... | ... | ... |

### Findings Detail
(only checks with findings are shown)

#### [N] Check Name
- <finding with file path, evidence, and severity>

### Recommendations
1. [SEVERITY] <actionable recommendation>

### Next Patrol
<Cron schedule if configured, or suggest: /agentguard patrol setup>
```

**Overall status**: Any CRITICAL → **FAIL**, any HIGH → **WARN**, else **PASS**

After outputting the report, append a summary entry to `~/.agentguard/audit.jsonl`:
```json
{"timestamp":"...","event":"patrol","overall_status":"PASS|WARN|FAIL","checks":8,"findings":<count>,"critical":<count>,"high":<count>}
```

### patrol setup

Configure the patrol as an OpenClaw daily cron job.

**Steps**:

1. Verify OpenClaw environment (same pre-flight as `patrol run`)
2. Ask the user for:
   - **Timezone** (default: UTC). Examples: `Asia/Shanghai`, `America/New_York`, `Europe/London`
   - **Schedule** (default: `0 3 * * *` — daily at 03:00)
   - **Notification channel** (optional): `telegram`, `discord`, `signal`
   - **Chat ID / webhook** (required if channel is set)
3. Generate the cron registration command:

```bash
openclaw cron add \
  --name "agentguard-patrol" \
  --description "GoPlus AgentGuard daily security patrol" \
  --cron "<schedule>" \
  --tz "<timezone>" \
  --session "isolated" \
  --message "/agentguard patrol run" \
  --timeout-seconds 300 \
  --thinking off \
  # Only include these if notification is configured:
  --announce \
  --channel <channel> \
  --to <chat-id>
```

4. **Show the exact command to the user and wait for explicit confirmation** before executing
5. After execution, verify with `openclaw cron list`
6. Output confirmation with the cron schedule

> **Note**: `--timeout-seconds 300` is required because isolated sessions need cold-start time. The default 120s is not enough.

### patrol status

Show the current patrol state.

**Steps**:

1. Read `~/.agentguard/audit.jsonl`, find the most recent `event: "patrol"` entry
2. If found, display: timestamp, overall status, finding counts
3. Run `openclaw cron list` and look for `agentguard-patrol` job
4. If cron is configured, show: schedule, timezone, last run time, next run time
5. If cron is not configured, suggest: `/agentguard patrol setup`

---

# Trust & Configuration

## Subcommand: trust

Manage skill trust levels using the GoPlus AgentGuard registry.

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

**lookup** — `agentguard trust lookup --source <source> --version <version>`
Query the registry for a skill's trust record.

**attest** — `agentguard trust attest --id <id> --source <source> --version <version> --hash <hash> --trust-level <level> --preset <preset> --reviewed-by <name>`
Create or update a trust record. Use `--preset` for common capability models or provide `--capabilities <json>` for custom.

**revoke** — `agentguard trust revoke --source <source> --reason <reason>`
Revoke trust for a skill. Supports `--source-pattern` for wildcards.

**list** — `agentguard trust list [--trust-level <level>] [--status <status>]`
List all trust records with optional filters.

### Script Execution

If the agentguard package is installed, execute trust operations via AgentGuard's own bundled script:
```
node scripts/trust-cli.ts <subcommand> [args]
```

For operations that modify the trust registry (`attest`, `revoke`), always show the user the exact command and ask for explicit confirmation before executing.

If scripts are not available, help the user inspect `data/registry.json` directly using Read tool.

---

## Subcommand: config

Set the GoPlus AgentGuard protection level.

### Protection Levels

| Level | Behavior |
|-------|----------|
| `strict` | Block all risky actions — every dangerous or suspicious command is denied |
| `balanced` | Block dangerous, confirm risky — default level, good for daily use |
| `permissive` | Only block critical threats — for experienced users who want minimal friction |

### How to Set

1. Read `$ARGUMENTS` to get the desired level
2. Write the config to `~/.agentguard/config.json`:

```json
{"level": "balanced"}
```

3. Confirm the change to the user

If no level is specified, read and display the current config.

---

# Reporting

## Subcommand: report

Display recent security events from the GoPlus AgentGuard audit log.

### Log Location

The audit log is stored at `~/.agentguard/audit.jsonl`. Each line is a JSON object with:

```json
{"timestamp":"...","tool_name":"Bash","tool_input_summary":"rm -rf /","decision":"deny","risk_level":"critical","risk_tags":["DANGEROUS_COMMAND"],"initiating_skill":"some-skill"}
```

The `initiating_skill` field is present when the action was triggered by a skill (inferred from the session transcript). When absent, the action came from the user directly.

### How to Display

1. Read `~/.agentguard/audit.jsonl` using the Read tool
2. Parse each line as JSON
3. Format as a table showing recent events (last 50 by default)
4. If any events have `initiating_skill`, add a "Skill Activity" section grouping events by skill

### Output Format

```
## GoPlus AgentGuard Security Report

**Events**: <total count>
**Blocked**: <deny count>
**Confirmed**: <confirm count>

### Recent Events

| Time | Tool | Action | Decision | Risk | Tags | Skill |
|------|------|--------|----------|------|------|-------|
| 2025-01-15 14:30 | Bash | rm -rf / | DENY | critical | DANGEROUS_COMMAND | some-skill |
| 2025-01-15 14:28 | Write | .env | CONFIRM | high | SENSITIVE_PATH | — |

### Skill Activity

If any events were triggered by skills, group them here:

| Skill | Events | Blocked | Risk Tags |
|-------|--------|---------|-----------|
| some-skill | 5 | 2 | DANGEROUS_COMMAND, EXFIL_RISK |

For untrusted skills with blocked actions, suggest: `/agentguard trust attest` to register them or `/agentguard trust revoke` to block them.

### Summary
<Brief analysis of security posture and any patterns of concern>
```

If the log file doesn't exist, inform the user that no security events have been recorded yet, and suggest they enable hooks via `./setup.sh` or by adding the plugin.

---

# Health Checkup

## Subcommand: checkup

Run a comprehensive agent health checkup across 6 security dimensions. Generates a visual HTML report with a lobster mascot and opens it in the browser. The lobster's appearance reflects the agent's health: muscular bodybuilder (score 90+), healthy with shield (70–89), tired with coffee (50–69), or sick with bandages (0–49).

### Step 1: Data Collection

**IMPORTANT: You MUST run ALL 7 checks below — not just the skill scan. The checkup covers 5 security dimensions, not just code scanning. Do NOT skip checks 2–7.**

Run these checks in parallel where possible. These are **universal agent security checks** — they apply to any Claude Code or OpenClaw environment, regardless of whether AgentGuard is installed.

1. **[REQUIRED] Discover & scan installed skills** (→ feeds Dimension 1: Code Safety): Glob ALL of the following paths for `*/SKILL.md`:
   - `~/.claude/skills/*/SKILL.md`
   - `~/.openclaw/skills/*/SKILL.md`
   - `~/.openclaw/workspace/skills/*/SKILL.md`
   - `~/.qclaw/skills/*/SKILL.md`
   - `~/.qclaw/workspace/skills/*/SKILL.md`

   For **every** discovered skill, **run `/agentguard scan <skill_path>`** using the scan subcommand logic (24 detection rules). Do NOT skip any skill regardless of how many are found. Collect the scan results (risk level, findings count, risk tags) for each skill.
2. **[REQUIRED] Credential file permissions** (→ feeds Dimension 2: Credential Safety): Platform-aware check — behavior differs by OS:
   - **macOS/Linux**: Run `stat -f '%Lp' <path> 2>/dev/null || stat -c '%a' <path> 2>/dev/null` on `~/.ssh/`, `~/.gnupg/`, and if OpenClaw: on `$OC/openclaw.json`, `$OC/devices/paired.json`. **If the command returns empty output, the directory does not exist — treat as N/A (award full points), do NOT flag as a failure.**
   - **Windows**: `stat` is not available. Use `icacls <path>` to check ACLs instead. If the directory does not exist, treat as N/A (award full points). If it exists, check that the ACL grants access only to the current user (no `Everyone`, `Users`, or `Authenticated Users` with write/read access). Flag as FAIL only if the directory exists AND the ACL is overly permissive.
3. **[REQUIRED] Sensitive credential scan / DLP** (→ feeds Dimension 2: Credential Safety): Use Grep to scan **all** agent workspace directories for leaked secrets. This MUST cover the entire workspace root, not just the current agent's directory:
   - For OpenClaw / QClaw: scan `~/.openclaw/workspace/` and `~/.qclaw/workspace/` recursively — this includes **all** `workspace-agent-*/` subdirectories, not just the current agent's workspace
   - For Claude Code: scan `~/.claude/` recursively
   - Patterns to detect:
     - Private keys: `0x[a-fA-F0-9]{64}`, `-----BEGIN.*PRIVATE KEY-----`
     - Mnemonics: sequences of 12+ BIP-39 words, `seed_phrase`, `mnemonic`
     - API keys/tokens: `AKIA[0-9A-Z]{16}`, `gh[pousr]_[A-Za-z0-9_]{36}`, plaintext passwords
   - **Important**: Use the workspace *root* directory as the scan target (e.g. `~/.qclaw/workspace/`), not a specific agent subdirectory. All sibling `workspace-agent-*` directories must be included.
4. **[REQUIRED] Network exposure** (→ feeds Dimension 3: Network & System): Run `lsof -i -P -n 2>/dev/null | grep LISTEN` or `ss -tlnp 2>/dev/null` to check for dangerous open ports (Redis 6379, Docker API 2375, MySQL 3306, MongoDB 27017 on 0.0.0.0)
5. **[REQUIRED] Scheduled tasks audit** (→ feeds Dimension 3: Network & System): Check `crontab -l 2>/dev/null` for suspicious entries containing `curl|bash`, `wget|sh`, or accessing `~/.ssh/`
6. **[REQUIRED] Environment variable exposure** (→ feeds Dimension 3: Network & System): Run `env` and check for sensitive variable names (`PRIVATE_KEY`, `MNEMONIC`, `SECRET`, `PASSWORD`) — detect presence only, mask values
7. **[REQUIRED] Runtime protection check** (→ feeds Dimension 4: Runtime Protection): Check if security hooks exist in `~/.claude/settings.json` or `~/.openclaw/openclaw.json`, check for audit logs at `~/.agentguard/audit.jsonl`

### Step 2: Score Calculation

**Additive scoring**: Each dimension starts at **0**. For each check that **passes**, add the listed points. Maximum is 100 per dimension. **Every failed check = 1 finding with severity and description.**

#### Dimension 1: Skill & Code Safety (weight: 25%)

Uses AgentGuard's 24-rule scan engine (`/agentguard scan`) to audit each installed skill. Start at base 100 and **deduct** for findings:

- Base score: **100**
- Each CRITICAL finding: **−15**
- Each HIGH finding: **−8**
- Each MEDIUM finding: **−3**
- Floor at **0** (never negative)

For each finding, add: `"<rule_id> in <skill>:<file>:<line>"` with its severity.

**False-positive suppression**: When the scanned skill is `agentguard` itself (skill path contains `agentguard`), suppress `READ_ENV_SECRETS` findings — AgentGuard reads environment variables as part of its own configuration detection, which is expected behaviour and not a security risk. Do not deduct points or list these as findings in the report.

If no skills installed: score = **70**, add finding: "No third-party skills installed — no code to audit" (LOW).

#### Dimension 2: Credential & Secret Safety (weight: 25%)

Checks for leaked credentials and permission hygiene. Start at **0**, add points for each check that **passes** (total possible = 100):

| Check | Points if PASS | If FAIL → finding |
|-------|---------------|-------------------|
| `~/.ssh/` permissions are 700 or stricter | **+25** | "~/.ssh/ permissions too open (<actual>) — should be 700" (HIGH) |
| `~/.gnupg/` permissions are 700 or stricter | **+15** | "~/.gnupg/ permissions too open (<actual>) — should be 700" (MEDIUM) |

**Permission check rules (to avoid false positives):**
- **Directory does not exist** (stat/icacls returns empty or "file not found"): Treat as N/A — award the points. A missing `~/.ssh/` or `~/.gnupg/` is not a security risk.
- **Windows**: Use `icacls` instead of `stat`. Award full points if directory doesn't exist. Flag as FAIL only if directory exists AND ACL grants access to `Everyone`, `Users`, or `Authenticated Users`.
- **macOS/Linux**: Flag as FAIL only when the directory exists AND stat returns a numeric value AND that value is greater than 700.
| No private keys (hex 0x..64, PEM) found in skill code or workspace | **+25** | "Plaintext private key found in <location>" (CRITICAL) |
| No mnemonic phrases found in skill code or workspace | **+20** | "Plaintext mnemonic found in <location>" (CRITICAL) |
| No API keys/tokens (AWS AKIA.., GitHub gh*_) found in skill code | **+15** | "API key/token found in <location>" (HIGH) |

#### Dimension 3: Network & System Exposure (weight: 20%)

Checks for dangerous network exposure and system-level risks. Start at **0**, add points for each check that **passes** (total possible = 100):

| Check | Points if PASS | If FAIL → finding |
|-------|---------------|-------------------|
| No high-risk ports exposed on 0.0.0.0 (Redis/Docker/MySQL/MongoDB) | **+35** | "Dangerous port exposed: <service> on 0.0.0.0:<port>" (HIGH) |
| No suspicious cron jobs (curl\|bash, wget\|sh, accessing ~/.ssh/) | **+30** | "Suspicious cron job: <command>" (HIGH) |
| No sensitive env vars with dangerous names (PRIVATE_KEY, MNEMONIC) | **+20** | "Sensitive env var exposed: <name>" (MEDIUM) |
| OpenClaw config files have proper permissions (600) if applicable | **+15** | "OpenClaw config <file> permissions too open" (MEDIUM) |

**Example**: If no dangerous ports (+35), no suspicious cron (+30), but env var `PRIVATE_KEY` found (+0), and not OpenClaw (+15 skip, give points) → score = 35 + 30 + 0 + 15 = **80**.

#### Dimension 4: Runtime Protection (weight: 15%)

Checks whether the agent has active security monitoring. Start at **0**, add points for each check that **passes** (total possible = 100):

| Check | Points if PASS | If FAIL → finding |
|-------|---------------|-------------------|
| Security hooks/guards installed (AgentGuard, custom hooks, etc.) | **+40** | "No security hooks installed — actions are unmonitored" (HIGH) |
| Security audit log exists with recent events | **+30** | "No security audit log — no threat history available" (MEDIUM) |
| Skills have been security-scanned at least once | **+30** | "Installed skills have never been security-scanned" (MEDIUM) |

#### Dimension 5: Web3 Safety (weight: 15% if applicable)

Only if Web3 usage is detected (env vars like `GOPLUS_API_KEY`, `CHAIN_ID`, `RPC_URL`, or web3-related skills installed). Otherwise `{ "score": null, "na": true }`. Start at **0**, add points for each check that **passes** (total possible = 100):

| Check | Points if PASS | If FAIL → finding |
|-------|---------------|-------------------|
| No wallet-draining patterns (approve+transferFrom) in skill code | **+40** | "Wallet-draining pattern detected in <skill>" (CRITICAL) |
| No unlimited token approval patterns in skill code | **+30** | "Unlimited approval pattern detected in <skill>" (HIGH) |
| Transaction security API configured (GoPlus or equivalent) | **+30** | "No transaction security API — Web3 calls are unverified" (MEDIUM) |

#### Composite Score Calculation

Calculate the weighted average of all applicable dimensions:

```
composite_score = (code_safety × 0.25) + (credential_safety × 0.25) + (network_exposure × 0.20) + (runtime_protection × 0.15) + (web3_safety × 0.15)
```

If Web3 Safety is N/A, redistribute its 15% weight proportionally across the other 4 dimensions:
```
composite_score = (code_safety × 0.294) + (credential_safety × 0.294) + (network_exposure × 0.235) + (runtime_protection × 0.176)
```

Round to the nearest integer.

**Tier assignment (MUST use these exact thresholds):**

| Score Range | Tier | Label |
|-------------|------|-------|
| **90–100** | **S** | JACKED |
| **70–89** | **A** | Healthy |
| **50–69** | **B** | Tired |
| **0–49** | **F** | Critical |

**Example**: code_safety=100, credential_safety=80, network_exposure=85, runtime_protection=30, web3=N/A → composite = (100×0.294)+(80×0.294)+(85×0.235)+(30×0.176) = 29.4+23.5+20.0+5.3 = **78** → Tier **A** (Healthy).

### Step 3: Generate Analysis Report

Based on all collected data and findings, write a **comprehensive security analysis report** as a single text block. This is where you use your AI reasoning ability — don't just list facts, **analyze** them:

- Summarize the overall security posture in 2-3 sentences
- Highlight the most critical risks and explain **why** they matter (e.g. "Your ~/.ssh/ permissions allow any process running as your user to read your private keys, which means a malicious skill could silently exfiltrate them")
- For each major finding, provide a specific actionable fix (exact command to run)
- Note what's going well — acknowledge secure areas
- If applicable, explain attack scenarios that the current configuration is vulnerable to (e.g. "A malicious skill could install a cron job that phones home your credentials every hour")
- Keep the tone professional but direct, like a security consultant's report

This report goes into the `"analysis"` field of the JSON output.

Also generate a list of actionable recommendations as `{ "severity": "...", "text": "..." }` objects for the structured view.

### Pre-Step-4 Validation

**Before assembling the JSON, verify you have collected data for ALL 5 dimensions:**

- [ ] `code_safety` — from Step 1 check 1 (skill scanning)
- [ ] `credential_safety` — from Step 1 checks 2 + 3 (permissions + DLP)
- [ ] `network_exposure` — from Step 1 checks 4 + 5 + 6 (ports + cron + env vars)
- [ ] `runtime_protection` — from Step 1 check 7 (hooks + audit log)
- [ ] `web3_safety` — from Step 2 (only if Web3 detected, otherwise `{ "score": null, "na": true }`)

**If any dimension is missing data, go back and run the missing checks. Do NOT submit a report with only code_safety filled in.**

### Step 4: Generate Report

Assemble the results into a JSON object and pipe it to the report generator:

```json
{
  "timestamp": "<ISO 8601>",
  "composite_score": <0-100>,
  "tier": "<S|A|B|F>",
  "dimensions": {
    "code_safety": { "score": <n>, "findings": [...], "details": "<one-line summary>" },
    "credential_safety": { "score": <n>, "findings": [...], "details": "<one-line summary>" },
    "network_exposure": { "score": <n>, "findings": [...], "details": "<one-line summary>" },
    "runtime_protection": { "score": <n>, "findings": [...], "details": "<one-line summary>" },
    "web3_safety": { "score": <n|null>, "na": <bool>, "findings": [...], "details": "<one-line summary>" }
  },
  "skills_scanned": <count>,
  "protection_level": "<level>",
  "analysis": "<the comprehensive AI-written security analysis report>",
  "recommendations": [
    { "severity": "HIGH", "text": "..." }
  ]
}
```

Execute the report generator. **Use the `--file` method for cross-platform compatibility** (the `echo | pipe` method fails on Windows due to shell quoting differences):

1. First, write the JSON to a temporary file using the Write tool (e.g. `/tmp/agentguard-checkup-data.json`)
2. Then run (remember to `cd` into the skill directory first — see "Resolving Script Paths" above):
```bash
cd <skill_directory> && node scripts/checkup-report.js --file /tmp/agentguard-checkup-data.json
```

The script outputs the HTML file path to stdout (e.g. `/tmp/agentguard-checkup-1234567890.html`). Capture this path — you will need it for delivery in Step 6.

> **Note**: The script also supports stdin pipe (`echo '<json>' | node scripts/checkup-report.js`) but this may fail on Windows cmd.exe where single quotes are not string delimiters. Always prefer `--file`.

### Step 5: Terminal Summary (REQUIRED)

**You MUST output this summary after the report generates.** This is the primary output the user sees. Do NOT skip this step — always show the score, dimension table, and report path:

```
## 🦞 GoPlus AgentGuard Health Checkup

**Overall Health Score**: <score> / 100 (Tier <grade> — <label>)
**Quote**: "<lobster quote>"

| Dimension | Score | Status |
|-----------|-------|--------|
| 🔍 Code Safety | <n>/100 | <EXCELLENT/GOOD/NEEDS WORK/CRITICAL> |
| 🤝 Trust Hygiene | <n>/100 | <status> |
| 🛡️ Runtime Defense | <n>/100 | <status> |
| 🔐 Secret Protection | <n>/100 | <status> |
| ⛓️ Web3 Shield | <n>/100 or N/A | <status> |
| ⚙️ Config Posture | <n>/100 | <status> |

**Full visual report**: <path> (opened in browser)

💡 Top recommendation: <first recommendation text>

### Next Steps
(Only include this section if there are HIGH or CRITICAL findings.)

List each HIGH or CRITICAL finding as a plain-language suggestion — no commands, no JSON, no technical details. One sentence per item. Ask the user to confirm if they'd like help with any of them.

Format:
```
⚠️ A few things need your attention:
1. 🔴 <plain description of critical issue and why it matters>
2. 🟠 <plain description of high issue and why it matters>
...

Reply with the number(s) you'd like help with and I'll walk you through it.
```

Examples of plain-language descriptions:
- No hooks: "Security monitoring isn't active — AgentGuard can't block threats in real-time until hooks are configured."
- Unregistered skills: "10 installed skills haven't been security-reviewed — they're running with no trust level assigned."
- SSH permissions: "Your SSH key folder has loose permissions — other processes on this machine could potentially read your private keys."
- Plaintext credential: "A private key or API token was found in plain text in a file — it should be removed and rotated."

### Step 6: Deliver the Report to the User

After printing the terminal summary, deliver the HTML report file. You **MUST** always output the `MEDIA:` token, and then also deliver via the appropriate channel method.

#### 6a. MEDIA token (required — always do this)

Output the following line on its **own line** in your response:

```
MEDIA:<file_path>
```

For example: `MEDIA:/tmp/agentguard-checkup-1234567890.html`

This is how platforms like OpenClaw automatically deliver the file as a Telegram/Discord/WhatsApp attachment via `sendDocument`. The platform strips this line from visible text — the user won't see it. **Always output this regardless of what channel you think you're in.**

#### 6b. Channel-specific delivery (in addition to MEDIA token)

**Claude Code (local desktop)**
- The browser should already be open from Step 4.
- Also copy to Desktop: `cp <file_path> ~/Desktop/agentguard-checkup-$(date +%Y-%m-%d).html`
- Tell the user: "✅ Report saved to your Desktop and opened in browser."

**Claude.ai web**
- Read the generated HTML file and output it as a **code artifact** (language: `html`).
- Tell the user: "✅ Your report is attached above — click the download icon to save it."

**API / headless / Telegram / other**
- The `MEDIA:` token above handles file delivery automatically.
- Also print the file path for reference.

Regardless of channel, always end with:
```
🦞 Stay safe — run /agentguard checkup anytime to get a fresh report.
```

Append a summary entry to `~/.agentguard/audit.jsonl`:
```json
{"timestamp":"...","event":"checkup","composite_score":<n>,"tier":"<grade>","checks":6,"findings":<count>,"skills_scanned":<count>}
```

---

# Auto-Scan on Session Start (Opt-In)

AgentGuard can optionally scan installed skills at session startup. **This is disabled by default** and must be explicitly enabled:

- **Claude Code**: Set environment variable `AGENTGUARD_AUTO_SCAN=1`
- **OpenClaw**: Pass `{ skipAutoScan: false }` when registering the plugin

When enabled, auto-scan operates in **report-only mode**:

1. Discovers skill directories (containing `SKILL.md`) under `~/.claude/skills/` and `~/.openclaw/skills/`
2. Runs `quickScan()` on each skill
3. Reports results to stderr (skill name + risk level + risk tags)

Auto-scan **does NOT**:
- Modify the trust registry (no `forceAttest` calls)
- Write code snippets or evidence details to disk
- Execute any code from the scanned skills

The audit log (`~/.agentguard/audit.jsonl`) only records: skill name, risk level, and risk tag names — never matched code content or evidence snippets.

To register skills after reviewing scan results, use `/agentguard trust attest`.
