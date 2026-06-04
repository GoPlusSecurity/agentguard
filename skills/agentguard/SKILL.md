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
  - path: "~/.hermes/"
    access: read-write
    reason: "Discover installed Hermes skills and help configure AgentGuard shell hooks"
  - path: "~/.qclaw/"
    access: read-only
    reason: "Discover installed skills in QClaw environments"
  - path: "~/.agentguard/"
    access: read-write
    reason: "Read/write audit log (audit.jsonl) and protection level config (config.json)"
user-invocable: true
allowed-tools: Read, Write, Grep, Glob, Bash(node *trust-cli.js *) Bash(node *action-cli.js *) Bash(*checkup-report.js) Bash(*checkup-score.js) Bash(*scan-to-sarif.js) Bash(echo *checkup-report.js) Bash(cat *checkup-report.js) Bash(agentguard *) Bash(openclaw *) Bash(ss *) Bash(lsof *) Bash(ufw *) Bash(iptables *) Bash(crontab *) Bash(systemctl list-timers *) Bash(find *) Bash(stat *) Bash(env) Bash(sha256sum *) Bash(node *) Bash(cd *)
argument-hint: "[scan|action|patrol|subscribe|trust|report|config|checkup|cli] [args...] [--format sarif|json] [--output <file>]"
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

### Post-Install Guidance

When AgentGuard has just been installed, or the user asks what to do next after
installing AgentGuard, recommend the required setup step below instead of
deriving a longer list from every supported command:

```bash
agentguard init --agent auto
```

Use a specific agent such as `hermes`, `qclaw`, `openclaw`, `claude-code`, or
`codex` only when the current host is known and the user wants targeted setup.
Treat `agentguard connect` and `agentguard checkup` as optional follow-ups, not
required post-install steps.

Parse `$ARGUMENTS` to determine the subcommand:

- **`init [args...]`** — Run `agentguard init`, especially `agentguard init --agent <agent>` after installation
- **`connect [args...]`** — Run `agentguard connect` to connect optional Cloud policy, audit, and approvals. AgentGuard supports either API-key auth or Agent JWT auth; only one Cloud auth method is required.
- **`scan <path>`** — Scan a skill or codebase for security risks
- **`action <description>`** — Evaluate whether a runtime action is safe
- **`patrol [run|setup|status]`** — Daily security patrol for OpenClaw environments
- **`trust <lookup|attest|revoke|list|seed> [args]`** — Manage skill trust levels
- **`subscribe [args...]`** — Pull AgentGuard Cloud threat-feed advisories, self-check local skills, and optionally install the OpenClaw 15-minute conditional notification cron
- **`report`** — View recent security events from the audit log
- **`config <strict|balanced|permissive>`** — Set protection level
- **`checkup`** — Run a comprehensive agent health checkup and generate a visual HTML report
- **`hermes-hooks`** — Show or install Hermes shell-hook configuration for runtime protection
- **`cli <args...>`** — Run the installed `agentguard` CLI directly for supported commands not otherwise routed by this skill

If no subcommand is given, or the first argument is a path, default to **scan**.

### CLI Passthrough

This skill is allowed to run `agentguard *`, so CLI commands and flags are available even when the skill has a higher-level workflow for the same area.

The skill's routed subcommands take priority over similarly named CLI commands. Do not route these through the packaged CLI unless the user explicitly prefixes the request with `/agentguard cli`: `scan`, `action`, `patrol`, `trust`, `report`, `config`, `checkup`, `hermes-hooks`.

Use CLI passthrough for the CLI-only commands below, for `init` and `connect`, for explicit `/agentguard cli <args...>` requests, or for the targeted `checkup --against-advisory <id>` mode described below.

Supported CLI commands and options:

| CLI command | Options | Notes |
|---|---|---|
| `agentguard init` | `--level <level>`, `--agent <agent>`, `--cloud <url>`, `--force` | Creates local config, persists the selected agent host, and optionally installs templates for `claude-code`, `codex`, `openclaw`, `hermes`, or `qclaw` |
| `agentguard connect` | `--key <key>`, `--api-key <key>`, `--url <url>`, `--cloud <url>` | API-key auth and Agent JWT auth are alternatives; configure only one. Prefer `AGENTGUARD_API_KEY` over passing secrets in flags |
| `agentguard disconnect` | none | Removes local Cloud credentials, pending event spool, cached Cloud policy, and the managed `agentguard-threat-feed` subscribe cron job; keeps Cloud URL, audit log, and installed hooks/templates |
| `agentguard status` | none | Shows local config, active Cloud auth method, policy cache, audit path |
| `agentguard policy pull` | `--json` | Pulls Cloud effective runtime policy into the local cache |
| `agentguard policy show` | `--json` | Shows the cached effective runtime policy, or the bundled default policy when no cache exists |
| `agentguard approve` | `--action-id <id>` or `--last`, `--once`, `--json` | Approves one existing pending runtime action; never approve without explicit user confirmation |
| `agentguard approvals list` | `--json` | Lists unexpired pending runtime approvals |
| `agentguard doctor` | none | Checks local setup and Cloud reachability when connected |
| `agentguard protect` | `--agent <agent>`, `--action-type <type>`, `--tool-name <name>`, `--session-id <id>`, `--decision-mode <local-first|cloud>`, `--json` | Evaluates one runtime action from stdin or hook environment |
| `agentguard subscribe` | `--since <iso>`, `--json`, `--quiet`, `--no-report`, `--cron <expr>`, `--cron-target <auto|openclaw|qclaw|hermes|system>`, `--cron-name <name>`, `--force`, `--cron-run`, `--cron-notify-run` | Pulls Cloud threat advisories and optionally self-checks local skills |
| `agentguard checkup` | `--json` | Runs the local agent health checkup |
| `agentguard checkup --against-advisory <id>` | `--json` | CLI threat-feed self-check for one advisory; this is a targeted mode, not the default health-check workflow |

Connect behavior:

- Always execute `agentguard connect ...` directly when the user asks for it. Do not answer that an API key must be obtained before running the command.
- `agentguard connect` with no `--key`, `--api-key`, or `AGENTGUARD_API_KEY` is valid in OpenClaw environments: the CLI uses Agent JWT registration, prints an activation link, and may notify the latest OpenClaw channel.
- Only suggest `agentguard connect --key <key>` when the user explicitly wants API-key auth or when the CLI itself reports that Agent JWT registration is unavailable. If the CLI says OpenClaw is not initialized, suggest `agentguard init --agent openclaw` and then rerun `agentguard connect`.

If the user writes `/agentguard cli <args...>`, execute `agentguard <args...>` directly.

When AgentGuard returns `confirm` or a block reason that includes `Approve once ... agentguard approve --action-id ... --once`, do not retry the protected action until the user explicitly approves. Show the exact approval command to the user before running it. Never run an approval command proactively, and never infer approval from context or from the agent's own plan. Treat user replies such as "yes", "approve", "approved", "confirm", "confirmed", "continue", "go ahead", "execute", "run it", "同意", "确认", "批准", "继续", or "执行" as explicit approval for the most recent protected action only after the user has seen the command and understands which action is being approved. After approval, run exactly the provided `agentguard approve --action-id ... --once` command, then retry the original action once. If the action id is unavailable, use `agentguard approvals list --json`; only use `agentguard approve --last --once` when there is exactly one relevant unexpired pending approval. If multiple pending approvals exist, ask the user to choose a specific action id.

Do **not** route plain `/agentguard scan`, `/agentguard action`, `/agentguard patrol`, `/agentguard trust`, `/agentguard report`, `/agentguard config`, `/agentguard checkup`, `/agentguard checkup --json`, or natural-language requests like "run agentguard checkup" through the packaged CLI. Those are this skill's higher-level workflows. Only use the packaged CLI checkup path when the user includes `--against-advisory <id>` or explicitly writes `/agentguard cli checkup ...`.

If the user writes `/agentguard checkup --against-advisory <id>`, use the CLI command `agentguard checkup --against-advisory <id>` instead of the comprehensive HTML health-report workflow.

## Subcommand: hermes-hooks

Help the user configure AgentGuard runtime protection for Hermes Agent.

Hermes does **not** load hooks from `SKILL.md` automatically. Hermes shell hooks
must be present in `~/.hermes/config.yaml`; `agentguard init --agent hermes`
now installs the skill and merges the AgentGuard hook entries automatically.
This skill ships the hook runner at `scripts/hermes-hook.js` and a copyable
template at `hermes-hooks.yaml`.

### What the Hermes hook protects

| Hermes hook | Tools | AgentGuard action |
|---|---|---|
| `pre_tool_call` | `terminal`, `execute_code` | `exec_command` |
| `pre_tool_call` | `write_file`, `patch`, `skill_manage` | `write_file` |
| `pre_tool_call` | `read_file` | `read_file` |
| `pre_tool_call` | `web_search` | `web_search` |
| `pre_tool_call` | `web_extract`, `browser_navigate`, `browser_open`, `web_open`, `open_url`, `visit_url`, `open` | `network_request` |
| `post_tool_call` | Same tools | Audit-only |

Hermes `pre_tool_call` supports allow/block only. If AgentGuard returns `ask`,
the Hermes hook reports it as a block with a confirmation-oriented message.
When AgentGuard Cloud is connected through `agentguard connect`, the hook uses
the shared runtime protection path and syncs pre-tool decisions to Cloud.

### Procedure

1. Resolve the AgentGuard skill directory using the "Important: Resolving Script
   Paths" rules above.
2. Confirm that dependencies are available. If `node scripts/hermes-hook.js`
   cannot load `@goplus/agentguard`, tell the user to run:
   ```bash
   cd <agentguard-skill-dir> && npm install
   ```
   or install the published package globally:
   ```bash
   npm install -g @goplus/agentguard
   ```
3. Prefer `agentguard init --agent hermes --force` to install and merge the
   hook entries automatically.
4. For manual setup, read `hermes-hooks.yaml`, replace
   `AGENTGUARD_SKILL_DIR` with the absolute skill directory, and show the
   resulting YAML to the user.
5. Ask for explicit confirmation before manually editing
   `~/.hermes/config.yaml`.
6. Tell the user to restart Hermes or launch it with one of the first-use
   consent options:
   ```bash
   hermes --accept-hooks chat
   HERMES_ACCEPT_HOOKS=1 hermes chat
   ```
   They may also set `hooks_auto_accept: true` in `~/.hermes/config.yaml`.
7. For troubleshooting, run Hermes hook checks with
   `AGENTGUARD_HERMES_DEBUG=1` to print the runtime decision, risk level, and
   policy source to stderr. Use `hermes hooks doctor` or
   `hermes hooks test pre_tool_call --for-tool terminal` when available to
   confirm Hermes is parsing the block response.

### Verification

After configuration, suggest a harmless test:

```bash
printf '{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo hello"}}' \
  | node <agentguard-skill-dir>/scripts/hermes-hook.js
```

Expected output:

```json
{}
```

And a blocked-action test:

```bash
printf '{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"rm -rf /"}}' \
  | node <agentguard-skill-dir>/scripts/hermes-hook.js
```

Expected output contains:

```json
{"action":"block","decision":"block","block":true}
```

## Subcommand: subscribe

Run the AgentGuard Cloud threat-feed subscription workflow through the installed CLI.

Examples:

```bash
agentguard subscribe
agentguard subscribe --quiet
agentguard subscribe --json
agentguard subscribe --since 2026-05-01T00:00:00.000Z
agentguard subscribe --no-report
agentguard subscribe --cron "0 * * * *"
agentguard subscribe --cron "0 * * * *" --cron-target system
agentguard subscribe --cron "0 * * * *" --cron-target openclaw
agentguard subscribe --cron "0 * * * *" --cron-target qclaw
agentguard subscribe --cron "0 * * * *" --cron-target hermes
agentguard subscribe --cron "0 * * * *" --quiet
agentguard subscribe --cron "0 * * * *" --cron-name agentguard-threat-feed
agentguard subscribe --cron "0 * * * *" --force
```

Without `--quiet`, `agentguard subscribe` pulls new threat-feed advisories and notifies the user to review them manually. With `--quiet`, it runs the full automated flow: pull new advisories, self-check local skills, report local matches back to Cloud, and notify only when local matches are found.

When `--cron <expr>` is used, the CLI first runs the subscribe flow once, then installs a recurring job using a standard five-field crontab expression such as `"0 * * * *"`. `--cron-target auto` is the default and uses the agent host saved by `agentguard init --agent`: `openclaw` uses the native `openclaw cron add` command and falls back to the OpenClaw Gateway at `127.0.0.1:18789`, `qclaw` uses the QClaw Gateway at `127.0.0.1:28789`, `hermes` uses native `hermes cron create` with a no-agent script under `~/.hermes/scripts/`, while `claude-code` and `codex` install a user crontab entry. OpenClaw cron jobs keep runner delivery internal and run internal `--cron-run`; when the saved agent host is `openclaw`, that run resolves the latest deliverable session route at runtime and sends the notification there directly. QClaw cron jobs still use host `announce` delivery to the last chat route and run internal `--cron-notify-run`, which prints either the exact notification body or `NO_REPLY`; this keeps no-op cron ticks silent without embedding chat IDs in the job. If no agent host is saved, auto asks the user to run `agentguard init --agent <claude-code|codex|openclaw|hermes|qclaw>` first or pass `--cron-target openclaw`, `--cron-target qclaw`, `--cron-target hermes`, or `--cron-target system` explicitly. If a saved host exists and you pass `--cron-target openclaw`, it must already be `openclaw`; otherwise the CLI rejects the mismatch instead of installing a cron job that cannot notify correctly. Pass `--cron-name <name>` to choose the job name. If a job with the same name already exists, the CLI leaves it untouched unless `--force` is passed.

System cron writes output to `~/.agentguard/feed-cron.log`; it does not send OpenClaw agent-channel notifications.

`agentguard subscribe --json` always includes a stable `cron` object with `requested`, `installed`, and optional `result` fields. If cron installation fails, the command exits non-zero instead of printing a misleading success summary.

`--since <iso>` overrides the persisted feed cursor for one run. `--no-report` skips uploading local matches back to Cloud in quiet mode. `--cron-run` and `--cron-notify-run` are internal and should only be used by installed cron jobs unless the user explicitly asks to reproduce cron behavior.

---

# Security Operations

## Subcommand: scan

Scan the target path for security risks using all detection rules.

**Argument parsing**: Extract from `$ARGUMENTS`:
- The scan target path (first positional argument, or value after `scan`)
- `--format <fmt>` flag: supported values are `sarif` (SARIF 2.1.0 JSON) and `text` (default markdown)
- `--output <file>` flag: write output to this file instead of stdout

If `--format sarif` is present, follow the **SARIF Output Flow** at the end of this section instead of the standard Output Format.

### Suppression Rules (read first)

Before running any detection, check for a suppression config file in the scan target root:

1. Use the Read tool to read `<scan_target>/.agentguard-suppress.yaml`. If the file does not exist (Read returns an error or empty), skip suppression — no findings will be filtered.
2. Parse the `suppress:` list. Each entry has:
   - `rule` (required): rule ID to suppress (e.g. `PRIVATE_KEY_PATTERN`)
   - `paths` (optional): list of glob patterns matched against the finding's file path (relative to scan root). `*` matches within one directory level; `**` matches across directories.
   - `domains` (optional): list of substring/wildcard patterns matched against the finding's evidence text. `*` acts as a wildcard prefix or suffix.
   - `reason` (required): explanation shown in the suppression summary.
3. Keep this suppression list in memory — you will apply it after all detection rules have run.

**A finding is suppressed when ALL of the following are true:**
- Its `rule_id` exactly matches the entry's `rule` field.
- If the entry has `paths`: the finding's file path matches at least one glob pattern.
- If the entry has `domains`: the finding's evidence text contains at least one domain pattern match.
- If neither `paths` nor `domains` are specified: the finding is suppressed regardless of file or evidence.

Suppressed findings are **excluded from the findings table and risk level calculation**. At the end of the report, add a note: `> N finding(s) suppressed via .agentguard-suppress.yaml — run with details to review.`

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
| 7 | PRIVATE_KEY_PATTERN | CRITICAL* | all | Hardcoded private keys |
| 8 | MNEMONIC_PATTERN | CRITICAL* | all | Hardcoded mnemonic phrases |
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

### Git Context Check (Rules 7 & 8 only)

Rules marked **CRITICAL\*** start at CRITICAL but must be downgraded based on git context **before** being added to the findings list. For every file that matched Rule 7 (PRIVATE_KEY_PATTERN) or Rule 8 (MNEMONIC_PATTERN), run the following checks in order and assign the final severity:

1. **Not in a git repo** — if `git -C <file_dir> rev-parse --git-dir 2>/dev/null` returns nothing → keep **CRITICAL**. Stop.
2. **Ever committed** — run `git -C <file_dir> log --all --oneline -- <file_path>`. If output is non-empty → keep **CRITICAL**. Stop.
3. **Not gitignored** — run `git -C <file_dir> check-ignore -q <file_path>`. If exit code is non-zero (file is NOT ignored) → downgrade to **HIGH**. Stop.
4. **Gitignored** — exit code 0 → downgrade to **MEDIUM**.

Record the git context result (`committed` / `not-ignored` / `gitignored` / `no-git-repo`) in the finding's Evidence column alongside the matched content.

**Important**: these checks require `git` to be available. If `git` is not in PATH, skip the check and keep **CRITICAL**.

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
**Total Findings**: <count of non-suppressed findings>

### Findings

| # | Risk Tag | Severity | File:Line | Evidence |
|---|----------|----------|-----------|----------|
| 1 | TAG_NAME | critical | path/file.ts:42 | `matched content` |

### Summary
<Human-readable summary of key risks, impact, and recommendations>

> N finding(s) suppressed via .agentguard-suppress.yaml
```
(Omit the suppression note line if no suppression file was found or no findings were suppressed.)

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
   - `hash`: compute by running AgentGuard's own script: `node scripts/trust-cli.js hash --path <scanned_path>` and extracting the `hash` field from the JSON output
3. Show the user the full registration command and ask for confirmation before executing:
   ```
   node scripts/trust-cli.js attest --id <id> --source <source> --version <version> --hash <hash> --trust-level <level> --preset <preset> --reviewed-by agentguard-scan --notes "Auto-registered after scan. Risk level: <risk_level>." --force
   ```
4. Only execute after user approval. Show the registration result.

If scripts are not available (e.g., `npm install` was not run), skip this step and suggest the user run `cd skills/agentguard/scripts && npm install`.

### SARIF Output Flow (when `--format sarif` is present)

**Run Steps 1–3 (File Discovery, Detection Rules, Risk Level Calculation) exactly as above.** Then, instead of the standard markdown Output Format, do the following:

**Step A — Assemble findings as structured JSON** and write to `/tmp/agentguard-scan-findings.json`:

```json
{
  "target": "<scanned path>",
  "scanned_at": "<ISO 8601 timestamp>",
  "files_scanned": <number>,
  "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "findings": [
    {
      "rule_id": "<RULE_ID>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
      "file": "<relative/path/to/file.ext>",
      "line": <line number>,
      "evidence": "<matched content snippet>"
    }
  ]
}
```

Use relative paths for `file` (relative to the scan target root). If no findings, use `"findings": []`.

**Step B — Run the SARIF converter** (cd into the skill directory first):

```bash
cd <skill_directory> && node scripts/scan-to-sarif.js --file /tmp/agentguard-scan-findings.json
```

**Step C — Handle output**:
- If `--output <file>` was specified: write the SARIF JSON to that file using the Write tool, then tell the user the file path.
- Otherwise: print the SARIF JSON to stdout (the user will redirect it, e.g. `> findings.sarif`).

**Do NOT** output the standard markdown report when `--format sarif` is active. Skip the Post-Scan Trust Registration offer.

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

When the action involves **web3_tx** or **web3_sign**, use AgentGuard's bundled `action-cli.js` script (in this skill's `scripts/` directory) to invoke the ActionScanner. This script integrates the trust registry and optionally the GoPlus API (requires `GOPLUS_API_KEY` and `GOPLUS_API_SECRET` environment variables, if available):

For web3_tx:
```
node scripts/action-cli.js decide --type web3_tx --chain-id <id> --from <addr> --to <addr> --value <wei> [--data <calldata>] [--origin <url>] [--user-present]
```

For web3_sign:
```
node scripts/action-cli.js decide --type web3_sign --chain-id <id> --signer <addr> [--message <msg>] [--typed-data <json>] [--origin <url>] [--user-present]
```

For standalone transaction simulation:
```
node scripts/action-cli.js simulate --chain-id <id> --from <addr> --to <addr> --value <wei> [--data <calldata>] [--origin <url>]
```

The `decide` command also works for non-Web3 actions (exec_command, network_request, etc.) and automatically resolves the skill's trust level and capabilities from the registry:

```
node scripts/action-cli.js decide --type exec_command --command "<cmd>" [--skill-source <source>] [--skill-id <id>]
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

**Daily security patrol.** Runs 8 automated checks that leverage AgentGuard's scan engine, trust registry, and audit log to assess the security posture of your agent deployment. Works on OpenClaw and standard cron environments.

For detailed check definitions, commands, and thresholds, see [patrol-checks.md](patrol-checks.md).

### Sub-subcommands

- **`patrol`** or **`patrol run`** — Execute all 8 checks and output a patrol report
- **`patrol setup`** — Configure as a daily cron job (OpenClaw or system crontab)
- **`patrol status`** — Show last patrol results and cron schedule

### Platform Detection

Before running `patrol setup` or `patrol status`, detect the available scheduling platform:

1. **OpenClaw**: Check for `$OPENCLAW_STATE_DIR` env var (fall back to `~/.openclaw/`), verify the directory exists and contains `openclaw.json`, and check if `openclaw` CLI is in PATH. If all three pass → use OpenClaw path.
2. **System crontab**: Check if `crontab` command is available in PATH → use crontab path.
3. **Neither available**: Inform the user and output the manual cron entry for them to add themselves.

For `patrol run`, no scheduling platform is needed — run checks on any platform.

Set `$OC` to the resolved OpenClaw state directory for all subsequent checks.

### The 8 Patrol Checks

#### [1] Skill/Plugin Integrity

Detect tampered or unregistered skill packages by comparing file hashes against the trust registry.

**Steps**:
1. Discover skill directories under `$OC/skills/` (look for dirs containing `SKILL.md`)
2. For each skill, compute hash: `node scripts/trust-cli.js hash --path <skill_dir>`
3. Look up the attested hash: `node scripts/trust-cli.js lookup --source <skill_dir>`
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
1. Find recently modified files: use Glob with patterns `$OC/**/*`, `~/.ssh/**/*`, `~/.gnupg/**/*` and filter results by mtime within 24h using `stat -f '%m %N' <file>` (macOS) or `stat -c '%Y %n' <file>` (Linux) — do NOT use the `find` binary as it may be unavailable in hardened environments
2. For modified files with scannable extensions (.js/.ts/.py/.sh/.md/.json), run the full scan rule set
3. Check permissions on critical files:
   - `$OC/openclaw.json` → should be 600
   - `$OC/devices/paired.json` → should be 600
   - `~/.ssh/authorized_keys` → should be 600
4. Detect new executable files in workspace: use Glob `$OC/workspace/**/*` and check each file's executable bit with `stat` — do NOT use `find` with `-perm`

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
1. List all records: `node scripts/trust-cli.js list`
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

Configure the patrol as a daily cron job. Detects the available platform and uses the appropriate method.

**Steps**:

1. Run platform detection (see above).
2. Ask the user for:
   - **Schedule** (default: `0 3 * * *` — daily at 03:00)
   - **Timezone** (default: UTC). Examples: `Asia/Shanghai`, `America/New_York`, `Europe/London`
   - **Notification channel** (optional, OpenClaw only): `telegram`, `discord`, `signal`
   - **Chat ID / webhook** (required if channel is set)

#### Path A — OpenClaw available

Generate and show the OpenClaw cron registration command:

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

**Show the exact command and wait for explicit user confirmation before executing.**
After execution, verify with `openclaw cron list`.

> **Note**: `--timeout-seconds 300` is required because isolated sessions need cold-start time.

#### Path B — System crontab available (OpenClaw not available)

Resolve the absolute path to this skill's directory (parent of this SKILL.md file) as `<SKILL_DIR>`.

Validate before generating the entry:
- `<schedule>` must be a standard five-field cron expression. Reject values that contain newlines.
- `<SKILL_DIR>` must be an absolute path. Reject paths containing single quotes, double quotes, null bytes, or newlines.
- Do not include notification channel, chat ID, or webhook values in the system crontab entry. System cron writes only to the local patrol log.

Generate the crontab entry using a single-quoted skill directory. If `<SKILL_DIR>` contains spaces, keep it inside the quotes exactly as shown:
```
<schedule> cd '<SKILL_DIR>' && AGENTGUARD_AUTO_SCAN=1 node scripts/auto-scan.js >> "$HOME/.agentguard/patrol.log" 2>&1
```

**Show the exact entry and wait for explicit user confirmation before writing.**

After confirmation, add the entry to the user's crontab:
```bash
(crontab -l 2>/dev/null; printf '%s\n' "<schedule> cd '<SKILL_DIR>' && AGENTGUARD_AUTO_SCAN=1 node scripts/auto-scan.js >> \"\$HOME/.agentguard/patrol.log\" 2>&1") | crontab -
```

Verify with `crontab -l | grep agentguard`.

#### Path C — Neither available

Output the crontab entry for the user to add manually:
```
<schedule> cd '<SKILL_DIR>' && AGENTGUARD_AUTO_SCAN=1 node scripts/auto-scan.js >> "$HOME/.agentguard/patrol.log" 2>&1
```
Explain that neither `openclaw` nor `crontab` was found in PATH, so the entry must be added manually.

### patrol status

Show the current patrol state.

**Steps**:

1. Read `~/.agentguard/audit.jsonl`, find the most recent `event: "patrol"` or `event: "auto_scan"` entry. If found, display: timestamp, overall status, finding counts.
2. **OpenClaw available**: run `openclaw cron list` and look for `agentguard-patrol`. Show schedule, timezone, last/next run time if found.
3. **System crontab available**: run `crontab -l 2>/dev/null | grep agentguard`. Show the matching entry if found.
4. If no cron is configured on any platform, suggest: `/agentguard patrol setup`.

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

**lookup** — `node scripts/trust-cli.js lookup --source <source> --version <version>`
Query the registry for a skill's trust record.

**attest** — `node scripts/trust-cli.js attest --id <id> --source <source> --version <version> --hash <hash> --trust-level <level> --preset <preset> --reviewed-by <name>`
Create or update a trust record. Use `--preset` for common capability models or provide `--capabilities <json>` for custom.

**revoke** — `node scripts/trust-cli.js revoke --source <source> --reason <reason>`
Revoke trust for a skill. Supports `--source-pattern` for wildcards.

**list** — `node scripts/trust-cli.js list [--trust-level <level>] [--status <status>]`
List all trust records with optional filters.

**seed** — `agentguard trust seed [--auto-attest-low-risk] [--auto-attest-medium-risk] [--dry-run]`
Batch-scan all installed skills and auto-attest those meeting the risk threshold. Designed for initial baseline setup when many skills are already installed.

Flags:
- `--auto-attest-low-risk` (default when `seed` is invoked): attest LOW-risk skills as `trusted` with `read_only` preset.
- `--auto-attest-medium-risk`: also attest MEDIUM-risk skills as `restricted` with `none` preset.
- `--dry-run`: preview only — show the plan table without executing any attest commands.

**HIGH and CRITICAL risk skills are never auto-attested** regardless of flags. They must be reviewed and attested manually.

#### seed Flow

**Step 1 — Discover skills**

Glob all of the following paths for `*/SKILL.md` (same as checkup):
- `~/.claude/skills/*/SKILL.md`
- `~/.openclaw/skills/*/SKILL.md`
- `~/.openclaw/workspace/skills/*/SKILL.md`
- `~/.qclaw/skills/*/SKILL.md`
- `~/.qclaw/workspace/skills/*/SKILL.md`

Skip `agentguard` itself. Collect the parent directory of each found `SKILL.md` as the skill path.

**Step 2 — Filter unregistered skills**

For each discovered skill, run:
```
node scripts/trust-cli.js lookup --source <skill_path>
```
If the lookup returns a record with `status: active`, the skill is already registered — skip it and note "already registered" in the summary. Only proceed with skills that have no active trust record.

**Step 3 — Scan unregistered skills**

For each unregistered skill, run the full scan (24 detection rules, same as `/agentguard scan <skill_path>`). Record: skill name, skill path, risk level (LOW/MEDIUM/HIGH/CRITICAL), finding count.

**Step 4 — Build preview table**

Output a plan table before taking any action:

```
## AgentGuard Trust Seed — Plan

Scanned <N> unregistered skills. Proposed actions:

| Skill | Path | Risk | Findings | Proposed Action |
|-------|------|------|----------|-----------------|
| foo   | ~/.claude/skills/foo | LOW    | 0 | ✅ attest trusted/read_only |
| bar   | ~/.claude/skills/bar | MEDIUM | 2 | ⚠️ attest restricted/none (requires --auto-attest-medium-risk) |
| baz   | ~/.claude/skills/baz | HIGH   | 5 | 🚫 SKIP — manual review required |
| qux   | ~/.claude/skills/qux | CRITICAL | 8 | 🚫 SKIP — manual review required |

Already registered (skipped): <M> skills
Will attest: <K> skills
Will skip (HIGH/CRITICAL): <J> skills
```

If `--dry-run` is present: output this table and stop. Add: `Dry run complete — no changes made. Remove --dry-run to execute.`

**Step 5 — User confirmation (REQUIRED)**

After showing the plan table, **always ask for explicit user confirmation** before executing any attest commands:

> "Ready to attest <K> skill(s). Confirm? (yes/no)"

Do NOT proceed without a clear affirmative response. If the user declines, stop and suggest `--dry-run` for future previews.

**Step 6 — Batch attest**

For each skill approved for attestation, compute its hash and run attest:

```bash
# Compute hash
node scripts/trust-cli.js hash --path <skill_path>

# Attest
node scripts/trust-cli.js attest \
  --id <skill_dir_name> \
  --source <skill_path> \
  --version <version_from_package.json_or_unknown> \
  --hash <computed_hash> \
  --trust-level <trusted|restricted> \
  --preset <read_only|none> \
  --reviewed-by agentguard-seed \
  --notes "Auto-attested by trust seed. Scan risk: <risk_level>. Findings: <count>." \
  --force
```

Run these sequentially (not in parallel) to avoid registry write conflicts.

**Step 7 — Result summary**

```
## Trust Seed Complete

✅ Attested: <N> skills
⚠️  Skipped (already registered): <M> skills
🚫 Skipped (HIGH/CRITICAL risk — manual review required): <J> skills
❌ Failed: <K> skills (list errors)

Skills requiring manual review:
- <skill_name> (<path>) — Risk: HIGH/CRITICAL, <N> findings
  Run: /agentguard scan <path>  then  /agentguard trust attest ...
```

### Script Execution

If the agentguard package is installed, execute trust operations via AgentGuard's own bundled script:
```
node scripts/trust-cli.js <subcommand> [args]
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

Run a comprehensive agent health checkup across 5 security dimensions. Generates a visual HTML report with a lobster mascot and opens it in the browser. The lobster's appearance reflects the agent's health: muscular bodybuilder (score 90+), healthy with shield (70–89), tired with coffee (50–69), or sick with bandages (0–49).

**Scoring is handled by `checkup-score.js` — you MUST NOT calculate scores yourself. Your role is to collect raw facts, assemble them into structured JSON, and pass to the script.**

**Argument parsing**: Extract from `$ARGUMENTS`:
- `--format json` flag: skip HTML generation and write the checkup JSON to a file instead
- `--output <file>` flag: path for the JSON output file (required when `--format json` is used; defaults to `/tmp/agentguard-checkup-data.json` if omitted)

If `--format json` is present, follow the modified flow noted in Step 4 below.

Plain `checkup` must always run this comprehensive workflow, even if the user phrases it as `agentguard checkup`. Do not answer that an advisory ID is required. Advisory IDs are optional and only switch to the targeted threat-feed self-check mode described below.

If the arguments include `--against-advisory <id>`, do not run this comprehensive HTML workflow. Instead execute the CLI threat-feed self-check:

```bash
agentguard checkup --against-advisory <id>
agentguard checkup --against-advisory <id> --json
```

That CLI path fetches the current Cloud advisory feed and checks local skills against the single advisory. It is separate from the full health report below.

### Step 1: Data Collection

**IMPORTANT: You MUST run ALL 7 checks below — not just the skill scan. The checkup covers 5 security dimensions, not just code scanning. Do NOT skip checks 2–7.**

**EVIDENCE RULE: Every finding you report MUST be backed by actual tool output collected in this step. You MUST quote the exact command output (or "no output" if the command returned nothing) in the finding's evidence field. Findings without concrete evidence from tool execution are FORBIDDEN — do not infer, assume, or fabricate results.**

Run these checks in parallel where possible. These are **universal agent security checks** — they apply to any Claude Code or OpenClaw environment, regardless of whether AgentGuard is installed.

1. **[REQUIRED] Discover & scan installed skills** (→ feeds Dimension 1: Code Safety): Glob ALL of the following paths for `*/SKILL.md`:
   - `~/.claude/skills/*/SKILL.md`
   - `~/.openclaw/skills/*/SKILL.md`
   - `~/.openclaw/workspace/skills/*/SKILL.md`
   - `~/.qclaw/skills/*/SKILL.md`
   - `~/.qclaw/workspace/skills/*/SKILL.md`

   For **every** discovered skill, **run `/agentguard scan <skill_path>`** using the scan subcommand logic (24 detection rules). Do NOT skip any skill regardless of how many are found. Record for each skill: name, risk_level, and exact findings list (rule, severity, file, line).
2. **[REQUIRED] Credential file permissions** (→ feeds Dimension 2: Credential Safety): Platform-aware check — behavior differs by OS:
   - **macOS/Linux**: Run `stat -f '%Lp' <path> 2>/dev/null || stat -c '%a' <path> 2>/dev/null` on `~/.ssh/`, `~/.gnupg/`. **If the command returns empty output, the directory does not exist — record `exists: false`.**
   - **Windows**: `stat` is not available. Use `icacls <path>` to check ACLs instead. If directory doesn't exist, record `exists: false`. If it exists, record whether the ACL grants access to `Everyone`, `Users`, or `Authenticated Users`.
   - Also check OpenClaw config files if applicable (`$OC/openclaw.json`, `$OC/devices/paired.json`).
3. **[REQUIRED] Sensitive credential scan / DLP** (→ feeds Dimension 2: Credential Safety): Use Grep to scan **all** agent workspace directories for leaked secrets. This MUST cover the entire workspace root, not just the current agent's directory:
   - For OpenClaw / QClaw: scan `~/.openclaw/workspace/` and `~/.qclaw/workspace/` recursively
   - For Claude Code: scan `~/.claude/` recursively
   - For Hermes Agent: scan `~/.hermes/` recursively
   - Patterns to detect:
     - Private keys: `0x[a-fA-F0-9]{64}`, `-----BEGIN.*PRIVATE KEY-----`
     - Mnemonics: sequences of 12+ BIP-39 words, `seed_phrase`, `mnemonic`
     - API keys/tokens: `AKIA[0-9A-Z]{16}`, `gh[pousr]_[A-Za-z0-9_]{36}`, plaintext passwords
   - Record: `private_keys_found`, `mnemonics_found`, `api_keys_found` (boolean, with location if found).
   - **Important**: Use the workspace *root* directory as the scan target (e.g. `~/.qclaw/workspace/`), not a specific agent subdirectory. All sibling `workspace-agent-*` directories must be included.
4. **[REQUIRED] Network exposure** (→ feeds Dimension 3: Network & System): Run `lsof -i -P -n 2>/dev/null | grep LISTEN` or `ss -tlnp 2>/dev/null` to check for dangerous open ports (Redis 6379, Docker API 2375, MySQL 3306, MongoDB 27017 on 0.0.0.0). Record list of dangerous ports found (e.g. `["Redis on 0.0.0.0:6379"]`).
5. **[REQUIRED] Scheduled tasks audit** (→ feeds Dimension 3: Network & System): Check `crontab -l 2>/dev/null` for suspicious entries containing `curl|bash`, `wget|sh`, or accessing `~/.ssh/`. Record list of suspicious cron command strings found.
6. **[REQUIRED] Environment variable exposure** (→ feeds Dimension 3: Network & System): Run `env` and check for sensitive variable names (`PRIVATE_KEY`, `MNEMONIC`, `SECRET`, `PASSWORD`) — detect presence only, mask values. Record list of sensitive variable names found.
7. **[REQUIRED] Runtime protection check** (→ feeds Dimension 4: Runtime Protection): Check if security hooks exist in `~/.claude/settings.json`, `~/.openclaw/openclaw.json`, or `~/.hermes/config.yaml`. Check for audit logs at `~/.agentguard/audit.jsonl`. Check if installed skills have been previously scanned (audit log contains `scan` events). Record booleans: `hooks_installed`, `audit_log_exists`, `skills_ever_scanned`.

### Step 2: Assemble Raw Facts JSON

After completing all 7 checks, assemble the raw facts into a structured JSON and write it to a temporary file (e.g. `/tmp/agentguard-raw-facts.json`):

```json
{
  "skills": [
    {
      "name": "<skill-name>",
      "risk_level": "<low|medium|high|critical>",
      "findings": [
        { "rule": "<RULE_ID>", "severity": "<CRITICAL|HIGH|MEDIUM|LOW>", "file": "<filename>", "line": <number> }
      ]
    }
  ],
  "credential_files": {
    "ssh_dir":   { "exists": <bool>, "permissions": "<octal string, e.g. 700>" },
    "gnupg_dir": { "exists": <bool>, "permissions": "<octal string>" },
    "openclaw_config": { "exists": <bool>, "ok": <bool> }
  },
  "dlp": {
    "private_keys_found": <bool>,
    "mnemonics_found":    <bool>,
    "api_keys_found":     <bool>
  },
  "network": {
    "dangerous_ports":    ["<description>"],
    "suspicious_crons":   ["<command>"],
    "sensitive_env_vars": ["<VAR_NAME>"],
    "openclaw_config_ok": <bool|null>
  },
  "runtime": {
    "hooks_installed":     <bool>,
    "audit_log_exists":    <bool>,
    "skills_ever_scanned": <bool>
  },
  "web3": {
    "detected":                 <bool>,
    "wallet_draining_found":    <bool>,
    "unlimited_approval_found": <bool>,
    "goplus_configured":        <bool>
  }
}
```

**Web3 detection**: set `detected: true` if any of these are present: env vars `GOPLUS_API_KEY`, `CHAIN_ID`, or `RPC_URL`; or any skill with web3-related findings (WALLET_DRAINING, UNLIMITED_APPROVAL).

**Pre-Step-3 validation** — verify all fields are populated before proceeding:
- [ ] `skills` — from check 1
- [ ] `credential_files` — from check 2
- [ ] `dlp` — from check 3
- [ ] `network` — from checks 4, 5, 6
- [ ] `runtime` — from check 7
- [ ] `web3` — detected flag + fields

**If any field is missing, go back and run the missing check. Do NOT proceed with incomplete data.**

### Step 3: Compute Scores with checkup-score.js

Run the scoring script (it reads the raw facts and deterministically computes all dimension scores, composite score, and tier — do NOT calculate these yourself):

```bash
cd <skill_directory> && node scripts/checkup-score.js --file /tmp/agentguard-raw-facts.json
```

The script outputs a JSON object with:
- `composite_score` (0–100)
- `tier` (S/A/B/F) and `tier_label`
- `total_findings`
- `dimensions`: `code_safety`, `credential_safety`, `network_exposure`, `runtime_protection`, `web3_safety` — each with `score` and `findings[]`

Capture this JSON output — you will use it in Step 4.

### Step 4: Generate Analysis Report

Based on the scored output from Step 3 and the raw facts you collected, write a **comprehensive security analysis report** as a single text block. This is where you use your AI reasoning ability — don't just list facts, **analyze** them:

- Summarize the overall security posture in 2-3 sentences
- Highlight the most critical risks and explain **why** they matter (e.g. "Your ~/.ssh/ permissions allow any process running as your user to read your private keys, which means a malicious skill could silently exfiltrate them")
- For each major finding from the scored output, provide a specific actionable fix (exact command to run)
- Note what's going well — acknowledge secure areas
- If applicable, explain attack scenarios that the current configuration is vulnerable to
- Keep the tone professional but direct, like a security consultant's report

This report goes into the `"analysis"` field of the final JSON.

Also generate a list of actionable recommendations as `{ "severity": "...", "text": "..." }` objects for the structured view.

### Step 5: Generate HTML Report

Assemble the final JSON by merging the scored output from Step 3 with the analysis from Step 4, then pass it to the report generator:

```json
{
  "timestamp": "<ISO 8601>",
  "composite_score": <from checkup-score.js>,
  "tier": "<from checkup-score.js>",
  "dimensions": {
    "code_safety":        { "score": <from score>, "findings": [...], "details": "<one-line summary>" },
    "credential_safety":  { "score": <from score>, "findings": [...], "details": "<one-line summary>" },
    "network_exposure":   { "score": <from score>, "findings": [...], "details": "<one-line summary>" },
    "runtime_protection": { "score": <from score>, "findings": [...], "details": "<one-line summary>" },
    "web3_safety":        { "score": <from score|null>, "na": <bool>, "findings": [...], "details": "<one-line summary>" }
  },
  "skills_scanned": <count of skills from Step 1>,
  "protection_level": "<level>",
  "analysis": "<the comprehensive AI-written security analysis report>",
  "recommendations": [
    { "severity": "HIGH", "text": "..." }
  ]
}
```

**If `--format json` was specified**:
1. Write this JSON to the `--output <file>` path (or `/tmp/agentguard-checkup-data.json` if no `--output` given) using the Write tool.
2. Tell the user: "Checkup JSON written to `<file>`." — include the composite score and tier in the message.
3. **Stop here** — skip Steps 5 and 6 (HTML generation and MEDIA delivery). The terminal summary in Step 5 is also skipped since the user is consuming the raw JSON programmatically.

**Otherwise (default HTML flow)**:

Write the JSON to a temporary file using the Write tool (e.g. `/tmp/agentguard-checkup-data.json`), then run (remember to `cd` into the skill directory first — see "Resolving Script Paths" above):

```bash
cd <skill_directory> && node scripts/checkup-report.js --file /tmp/agentguard-checkup-data.json
```

The script outputs the HTML file path to stdout (e.g. `/tmp/agentguard-checkup-1234567890.html`). Capture this path — you will need it for delivery in Step 7.

> **Note**: The script also supports stdin pipe (`echo '<json>' | node scripts/checkup-report.js`) but this may fail on Windows cmd.exe. Always prefer `--file`.

### Step 6: Terminal Summary (REQUIRED)

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

### Step 7: Deliver the Report to the User

After printing the terminal summary, deliver the HTML report file. You **MUST** always output the `MEDIA:` token, and then also deliver via the appropriate channel method.

#### 7a. MEDIA token (required — always do this)

Output the following line on its **own line** in your response:

```
MEDIA:<file_path>
```

For example: `MEDIA:/tmp/agentguard-checkup-1234567890.html`

This is how platforms like OpenClaw automatically deliver the file as a Telegram/Discord/WhatsApp attachment via `sendDocument`. The platform strips this line from visible text — the user won't see it. **Always output this regardless of what channel you think you're in.**

#### 7b. Channel-specific delivery (in addition to MEDIA token)

**Claude Code (local desktop)**
- The browser should already be open from Step 5.
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
- **Hermes Agent**: Configure the `on_session_start` shell hook from `hermes-hooks.yaml`; the template sets `AGENTGUARD_AUTO_SCAN=1` for that hook.

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
