# Changelog

## Unreleased

### Changed
- MCPB release builds now publish the bundle as `agentguard.mcpb` so Anthropic's
  directory auto-pickup keeps matching the asset across version tags.
- Relaxed OpenClaw file read/write handling so ordinary paths are allowed by default, while sensitive paths still require approval and critical system mutations still block.
- Changed `curl/wget | bash/sh` handling to require approval by default and block only when hard indicators or multiple suspicious signals are present.

## [1.1.28] - 2026-06-16

### Added
- Added `SOCIAL_ACCOUNT_ACTION` detection for mutating X/Twitter and TweetClaw account requests, including tweets, DMs, media, profile updates, follows, monitors, webhooks, and draws. (#102)
- Added MCPB bundle assets and a reproducible MCP Desktop Extension build path, including the bundle manifest, AgentGuard directory icon, privacy policy metadata, production dependency staging, release workflow, build docs, and manifest tests. (#106)
- Added a native Hermes plugin that `agentguard init --agent hermes` installs and enables, with pre-tool blocking, post-tool audit handling, session-start skill scans, a `/agentguard` slash command, Hermes plugin docs, and Python plugin tests. (#107)

### Changed
- Web search actions now use a dedicated `web_search` runtime action across Claude Code, Hermes, OpenClaw, MCP, and the skill CLI, so query-only searches are handled separately from URL fetches and no longer trigger invalid-URL network approval flows.
- Direct web fetch and browser navigation GET requests keep the default `network.defaultOutbound: warn` behavior as audit-only, while mutating or high-risk network requests still require confirmation or blocking.
- Network request decisions now treat GET/HEAD/OPTIONS as low-risk reads, keep non-sensitive POST/PUT/PATCH requests at audit-level risk, require approval for DELETE, and warn when a cached policy uses an interruptive `network.defaultOutbound`.
- Runtime network evaluation now detects local behavior and response anomalies including request bursts, token domain sweeps, replayed requests, odd-hour bursts, large responses, malicious response bodies, MIME mismatches, and credential echo.
- `agentguard connect` and `agentguard subscribe` now support Hermes Agent JWT registration when Hermes is initialized or detected via `HERMES_HOME`/`~/.hermes`, while preserving the existing OpenClaw notification behavior.

### Fixed
- Runtime command protection now sends `rm -rf`/`rm -fr` on non-system paths through approval instead of hard-blocking, while root and protected system paths still block.
- Runtime protection now blocks shell and file-tool mutations of critical system paths such as `/bin`, `/usr/bin`, `/etc/passwd`, `/etc/shadow`, device paths, and kernel paths.
- Wrapped network commands inside command substitution, interpreter snippets, and simple variable expansion are now surfaced for approval instead of being treated as low-risk shell metacharacters.
- Runtime file protection now keeps `protectedPaths` as a sensitive-path approval list instead of treating it as the general file allowlist, so ordinary workspace file reads and writes are no longer surfaced as `PATH_NOT_ALLOWED` under the default policy.
- `agentguard init --agent hermes` now targets `HERMES_HOME` or `~/.hermes` for explicit installs instead of creating a nested `.hermes` directory under the current working directory, while only updating the root Hermes config and profile configs.
- Runtime network policies now enforce `network.defaultOutbound` and `network.blockedDomains` for direct network/browser tool calls instead of only checking shell commands.
- Runtime blocked-domain matching now compares structured URL hosts and paths instead of raw substrings, avoiding false positives such as `notexample.com` matching `example.com`; curl/wget download-and-execute commands are detected with real regex patterns.
- Hermes hook templates now split `web_search` from URL-bearing web/browser tools and recognize open-style URL tools consistently.
- MCPB release builds now harden staging and packaging so the generated bundle stamps the package version, includes only production server dependencies, preserves required bundle metadata, and validates manifest expectations before publishing. (#106)
- Native Hermes plugin packaging now excludes test cache artifacts, validates required mapped fields, preserves command arguments consistently, and only allows the unsafe `npx` fallback when explicitly enabled. (#107)

## [1.1.27] - 2026-05-29

### Changed
- Shell metacharacter-only runtime findings now stay below the approval threshold: benign commands with redirects or simple shell metacharacters are scored as low risk, auto-allowed locally, and no longer generate audit events, Cloud sync, or pending approvals on that signal alone.
- Runtime approval prompts and AgentGuard skill guidance now require agents to show the exact `agentguard approve --action-id ... --once` command and wait for explicit user approval for that exact action before approving and retrying.

### Fixed
- OpenClaw runtime protection now recognizes alternate tool name fields such as `tool_name`, `name`, and `id`, and classifies `exec`/`execute` tools as shell actions before policy evaluation.
- Repeated matching protected actions now reuse the existing pending approval id instead of creating duplicate pending approvals.
- AgentGuard approval/self commands wrapped through simple shell launchers such as `/bin/zsh -lc` are now treated as self-commands and skipped by runtime protection.

## [1.1.26] - 2026-05-28

### Added
- Added local one-time runtime approval grants: `agentguard approve --action-id <id> --once`, `agentguard approve --last --once`, and `agentguard approvals list` let agents retry a previously intercepted protected action after explicit user approval, with short-lived pending approvals and audited approved retries.

### Changed
- `agentguard subscribe` cron internals (`--cron-run` and `--cron-notify-run`) now only pull feed advisories instead of re-subscribing on every scheduled run, preserving Cloud-side unsubscribe choices.
- OpenClaw Cloud connect guidance now documents the Agent JWT flow explicitly: initialized OpenClaw installs can run `agentguard connect` without an API key, while API-key auth remains available for explicit API-key connections.
- `agentguard init --agent openclaw` now installs the AgentGuard skill alongside the runtime plugin so OpenClaw agents can learn the local approval/retry flow.

### Fixed
- Supported agent CLI commands such as `openclaw`, `qclaw`, `hermes`, `codex`, and `claude` are now treated like AgentGuard self-commands so normal agent management commands are not audited, reported, or blocked by AgentGuard hooks while compound shell commands remain protected.
- Empty safe runtime decisions (`riskScore: 0`, `riskLevel: safe`, and no reasons) no longer trigger local interception or Cloud event sync.
- Threat-feed self-checks for non-skill ecosystems now cover more local artifact shapes: plugin manifest/code file inspect paths and nested Codex plugin caches, MCP server names from JSON/TOML configs, and common supply-chain dependency coordinates from npm locks, `requirements.txt`, and `pyproject.toml`.

## [1.1.20] - 2026-05-27

### Changed
- `agentguard init --agent openclaw` now enables the AgentGuard plugin in both the main OpenClaw config and companion workspace state when either layout is detected.
- OpenClaw Gateway fallback requests now reuse configured bearer tokens from `AGENTGUARD_OPENCLAW_GATEWAY_TOKEN`, `OPENCLAW_GATEWAY_TOKEN`, or the local OpenClaw config for HTTP and WebSocket paths.
- `agentguard status` now refreshes Agent JWT account binding state and clears stale activation links once the saved Agent JWT is accepted by Cloud.

### Fixed
- Fixed Agent JWT activation messaging to describe account binding instead of email binding.
- Fixed subscribe cron runs so Agent JWT 401 responses prompt for a manual `agentguard connect` instead of automatically re-registering the local agent.
- Fixed native OpenClaw cron replacement and removal to delete existing jobs by job ID before reinstalling, avoiding reliance on unsupported `openclaw cron add --force` behavior.

## [1.1.18] - 2026-05-26

### Added
- Added Agent JWT registration and activation links for OpenClaw-backed Cloud connections.
- Added Cloud feed subscription support for the default advisory ecosystems.
- `agentguard status` now shows the active Cloud auth method, including API-key and Agent JWT connection details.

### Changed
- Cloud flows now prefer Agent JWT auth when available, with API key support preserved.
- Threat-feed notifications now include Cloud remediation guidance when available.
- Connect and disconnect flows now keep API key and Agent JWT credentials mutually clean.
- `agentguard disconnect` now removes the managed threat-feed subscribe cron job from the configured agent backend and clears saved cron metadata.
- `agentguard subscribe --cron` now installs OpenClaw jobs with `delivery.mode = none` / `--no-deliver`, then lets the normal internal `--cron-run` path auto-detect the saved OpenClaw host and send notifications directly to the latest deliverable session route instead of relying on `channel:last` announce fallback.
- `agentguard subscribe --cron --cron-target openclaw` now rejects saved-host mismatches, so an existing non-OpenClaw `agentHost` can no longer install an OpenClaw cron job that would run without any working notification route.
- `agentguard init --agent <agent>` now overwrites managed hook/template files by default so upgraded OpenClaw plugin templates are refreshed without requiring `--force`; use `--no-force` to preserve existing files.
- OpenClaw runtime approval-required decisions now hard-block tool calls instead of routing through the OpenClaw plugin approval channel, avoiding accidental auto-allow for sensitive local file access.
- OpenClaw Gateway WebSocket fallback now signs the connect handshake with the saved local device identity when available.

### Fixed
- Fixed Cloud runtime decisions that return `require_approve` instead of `require_approval`.
- Fixed OpenClaw Agent JWT connect so OpenClaw runtime detection can start registration without requiring an API key or prior AgentGuard init.
- Fixed AgentGuard runtime self-handling so direct `agentguard` and `agentguard-mcp` CLI commands are not audited, reported, or blocked by AgentGuard's own hooks while compound shell commands remain protected.
- Improved disconnected Cloud guidance and Agent JWT reauth handling.
- Fixed OpenClaw plugin registration after global npm installs by generating a package-root fallback loader in the local OpenClaw plugin template.
- Added OpenClaw plugin startup/hook activation metadata so AgentGuard loads as a runtime hook plugin during gateway startup.
- Fixed runtime protected-path matching so shell commands and file reads against `~/.ssh/**` also match absolute home paths such as `/Users/.../.ssh/id_ed25519.pub`.
- Fixed OpenClaw Gateway cron setup to fall back from CLI invocation to direct Gateway RPC when plugin protocol compatibility prevents CLI Gateway access.
- Fixed OpenClaw Gateway WebSocket fallback protocol negotiation for current v4 gateways and made invalid local device identity keys degrade to unsigned connect params instead of failing the fallback.

## [1.1.14] - 2026-05-22

### Changed
- Feed subscription state now stores newest-first pull records with per-run `newSeenIds` and `foundIds` instead of a single object snapshot.

### Fixed
- `agentguard checkup` now excludes the managed GoPlus AgentGuard skill from third-party skill scans so the guard does not report its own hook/checkup scripts as user risk.
- `agentguard init --agent hermes` now recursively enables AgentGuard hooks in Hermes profile `config.yaml` files, including configs with empty `hooks: {}` blocks or duplicate top-level `hooks` keys.
- Fixed OpenClaw/QClaw Gateway threat-feed cron installation to send only fields accepted by OpenClaw's `agentTurn` cron payload schema.

## [1.1.13] - 2026-05-21

### Added
- Added `agentguard init --agent auto` to detect installed agent directories and initialize each supported agent in order while continuing after per-agent failures.
- Added automatic Hermes hook configuration and QClaw plugin enablement during `agentguard init --agent` and `setup.sh` installs.

### Changed
- `agentguard init` now stores all initialized agent hosts in config while keeping the first detected host as the default for `--cron-target auto`.
- `agentguard init --agent codex` now writes `.codex/agentguard-hook.json` as the concrete AgentGuard hook configuration file instead of an example filename.
- Install guidance now treats `agentguard init --agent auto` as the only required next step; Cloud connect and checkup remain optional commands.
- Postinstall now writes persistent next-step guidance to `~/.agentguard/next-steps.txt` and the package directory so agent installers can discover it even when npm hides lifecycle output.

### Fixed
- `agentguard init --agent` now normalizes agent names before validation, so mixed-case values such as `Hermes` initialize correctly.
- Hermes hook runtime decisions now use the shared AgentGuard Cloud sync path and emit a more broadly compatible block response for `pre_tool_call`.
- `agentguard subscribe --cron` OpenClaw/QClaw jobs now use host `announce` delivery to the last chat route with an internal `--cron-notify-run` command that prints either the notification body or `NO_REPLY`, avoiding missing Telegram `chatId` errors while keeping no-op ticks silent.
- `agentguard subscribe --cron` Gateway installation now preserves legacy HTTP Gateway compatibility, falls back to OpenClaw-compatible WebSocket RPC when needed, sends QClaw the `cron.add` object payload expected by the Gateway schema, and handles fragmented WebSocket responses.
- `setup.sh` now falls back to the Claude Code skill directory when no supported agent platform is detected, while keeping `--target` available for custom layouts.
- AgentGuard skill system-crontab guidance now validates cron expressions and skill paths, quotes paths with spaces, and avoids embedding notification secrets in crontab entries.

## [1.1.10] - 2026-05-21

### Added
- Added `agentguard policy show` to inspect the cached effective runtime policy, with `--json` output and fallback to the bundled default policy when no cache exists.
- Added `agentguard subscribe --cron-target <auto|openclaw|qclaw|hermes|system>` so OpenClaw can use native cron with Gateway fallback, QClaw can use its Gateway at `127.0.0.1:28789`, Hermes can use native Hermes cron, while Claude Code and Codex use system crontab.
- `agentguard init --agent <agent>` now persists the selected agent host in local config for later cron backend selection.
- `agentguard init --agent` now supports `hermes` and `qclaw` in addition to `claude-code`, `codex`, and `openclaw`.

### Changed
- Threat-feed cron installation now fails fast when the OpenClaw Gateway preflight is unavailable instead of hiding `cron.list` errors until `cron.add`.
- `agentguard subscribe --cron` now requires a saved agent host when `--cron-target auto` is used; run `agentguard init --agent <agent>` first or pass an explicit cron target.
- `agentguard status` now shows the saved agent host when one is configured.
- Install and postinstall guidance now recommends `agentguard init --agent <agent>`, `agentguard connect`, and `agentguard checkup` as the focused next steps.
- System cron installation now writes and invokes a validated AgentGuard wrapper script instead of embedding config-derived paths directly in crontab.

## [1.1.9] - 2026-05-20

### Added
- Added `agentguard subscribe --quiet` for the full automated threat-feed flow: pull new advisories, run local self-checks, report matches, and notify on local matches.
- Added `agentguard subscribe --cron <expr>` to install OpenClaw cron jobs with standard five-field crontab expressions such as `"0 * * * *"`.
- Expanded threat-feed self-checks to cover all advisory ecosystems returned by AgentGuard Cloud: `skill`, `plugin`, `mcp_server`, `supply_chain`, `url`, and `prompt_injection`.

### Changed
- Restored plain `agentguard checkup` as the local health checkup workflow, while keeping `agentguard checkup --against-advisory <id>` as the targeted Cloud advisory self-check mode.
- Threat-feed subscribe now separates manual and automated handling: non-quiet runs notify users about new advisories for manual review, while quiet runs self-check and report matches automatically.
- OpenClaw threat-feed cron jobs now use `{ kind: "cron", expr, tz }` schedules and preserve the quiet/non-quiet mode used during installation.

### Fixed
- Fixed disconnected targeted checkup behavior so `agentguard checkup --against-advisory <id>` requires an active Cloud connection instead of falling back to local advisory cache.
- Fixed plain `agentguard checkup` so it falls back to the text summary when the optional visual report generator is unavailable in packaged installs.
- Fixed OpenClaw cron payloads to persist the installed manual/quiet mode and exact subscribe command.
- Fixed `domainExact` self-check matching so exact domains do not match substrings such as `evil.example.com` or `not-evil.example`.

### Removed
- Removed the old `agentguard subscribe --install-cron` and `--interval-minutes` options from CLI docs and command handling.

## [1.1.8] - 2026-05-19

### Added
- Added `agentguard disconnect` to remove local AgentGuard Cloud credentials, connection metadata, pending event spool, and cached Cloud policy while keeping local protection active.
- Expanded threat-feed advisory types for supply-chain, URL, domain, and prompt-injection use cases, including self-check remediation metadata.

### Changed
- Aligned the AgentGuard Cloud feed client with the current API contract, including single-advisory lookup, richer error envelopes, bare status responses, and improved status output handling.
- Runtime approval prompts now route through the connected agent host (`claude-code` or `codex`) instead of creating separate Cloud approval records, so confirm flows use the agent's native permission channel.

### Fixed
- Preserved AgentGuard skill command routing while adding Cloud disconnect support.
- Aligned the OpenClaw plugin entry contract and installer behavior so OpenClaw loads the runtime plugin through the expected package entry.
- Strengthened tests around Cloud feed calls, disconnect behavior, OpenClaw installation, runtime approval output, and integration flows.

## [1.1.7] - 2026-05-18

### Fixed
- Added the missing `agentguard policy pull` command used by AgentGuard Cloud policy refresh instructions.
- OpenClaw installs now enable the AgentGuard plugin when installing the skill through `setup.sh` or running `agentguard init --agent openclaw`.
- Added a dedicated OpenClaw package entry so OpenClaw loads the runtime plugin instead of the generic SDK entrypoint.

## [1.1.5] - 2026-05-18

### Added
- Added Hermes hook support, including installable hook metadata and docs.
- Added `agentguard subscribe --install-cron` for silent OpenClaw Gateway cron subscription checks.

### Changed
- Routed OpenClaw tool calls through runtime protection and AgentGuard Cloud policy decisions.
- Improved OpenClaw plugin config handling, registry discovery, and action classification.

### Fixed
- Hardened OpenClaw fallback behavior so security-sensitive actions fail closed when runtime protection is unavailable.
- Prevented audit log write failures from masking runtime policy decisions.

## [1.1.4] - 2026-05-14

### Added
- `agentguard subscribe` — pulls new threat-feed advisories from AgentGuard Cloud (`GET /api/v1/feed/advisories`), runs a self-check against locally installed skills, and reports matches back via `POST /api/v1/feed/self-check-report`. State persisted at `~/.agentguard/feed-state.json` so successive runs only process new entries.
- `agentguard checkup --against-advisory <id>` — on-demand self-check for a single advisory. Useful when you just want to know "am I affected by AGS-2026-…?" without subscribing.
- `src/feed/` module: `Advisory` / `AdvisoryAffected` / `FeedState` types modelled after OSV.dev, a self-check engine that matches by `namePattern` / `sha256` / `bodyRegex`, and a small state store.
- `CloudRequestError` exported from `src/cloud/client.ts` so feed callers can branch on HTTP status (notably 404, which lets the CLI fall back gracefully when running against an older AgentGuard Cloud that doesn't expose the feed yet).

### Changed
- `normalizeCloudUrl` now accepts `http://` for loopback hosts (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`) in addition to https-everywhere-else. Required for local dev and unit tests against a local Cloud build; production URLs are unaffected.

## [1.1.3] - 2026-05-12

### Added
- Added local-first AgentGuard CLI flow for init, connect, status, doctor, scan, and protect.
- Added optional AgentGuard Cloud policy, audit sync, and approval integration.

### Security
- Hardened Cloud API key validation, HTTPS-only Cloud URLs, config file permissions, and audit redaction.

## [1.1.1] - 2026-04-17

### Added
- Visual share feature: canvas image generation, GitHub/ClawHub links, viral copy
- Complete i18n support for checkup reports and share panel
- Guided onboarding with immediate checkup prompts

### Fixed
- Process hang on stuck exec operations (#31)
- HTML report path output on Windows/Linux
- Credential scan coverage across all workspace directories (#33)
- Cross-platform compatibility (SKILL.md, setup.sh, checkup-report.js)
- YAML parsing errors
- Upgrade SOCIAL_ENGINEERING severity to HIGH (#6)

### Changed
- Checkup feature now front and center in skill description
- Locked and updated dependency versions (1.0.13, 1.0.14)

## [1.1.0] - 2026-03-19

### Added
- `checkup` subcommand — comprehensive agent health checkup with visual HTML report
  - 6 security dimensions: Code Safety, Trust Hygiene, Runtime Defense, Secret Protection, Web3 Shield, Config Posture
  - Weighted scoring algorithm (0–100 composite score)
  - Self-contained HTML report with dark theme, animated score gauge, and expandable findings
  - Lobster mascot with 4 health tiers: Muscular (S), Healthy (A), Tired (B), Sick (F)
  - Premium upgrade CTA integration (agentguard.gopluslabs.io)
  - Cross-platform browser opening (macOS/Linux/Windows)
- `checkup-report.js` script for HTML report generation (zero external dependencies)
- Checkup results logged to `~/.agentguard/audit.jsonl`

## [1.0.5] - 2026-03-18

### Added
- `patrol` subcommand for OpenClaw daily security patrol
  - `patrol run` — Execute 8 comprehensive security checks
  - `patrol setup` — Configure as OpenClaw cron job (timezone, schedule, notifications)
  - `patrol status` — View last patrol results and cron schedule
- 8 patrol checks: skill integrity, secrets exposure, network exposure, cron/scheduled task audit, file system changes (24h), audit log analysis, environment & config validation, trust registry health
- Patrol report with overall status (PASS / WARN / FAIL) and actionable recommendations
- Patrol results logged to `~/.agentguard/audit.jsonl`
- Updated README with full patrol documentation and Layer 3 security description

## [1.0.4] - 2026-02-18

### Security
- Auto-scan is now **opt-in** (disabled by default) to address ClawHub security review
  - Claude Code: requires `AGENTGUARD_AUTO_SCAN=1` environment variable
  - OpenClaw: requires `{ skipAutoScan: false }` when registering the plugin
- Auto-scan now operates in **report-only mode** — scans skills and reports results to stderr, but no longer calls `forceAttest` or modifies the trust registry
- Audit log (`~/.agentguard/audit.jsonl`) no longer records code snippets, evidence details, or scan summaries — only skill name, risk level, and risk tag names

### Removed
- `forceAttest` calls from `auto-scan.js` and `openclaw-plugin.ts`
- `inferCapabilities`, `determineTrustLevel`, `riskToTrustLevel` helpers from OpenClaw plugin (no longer needed)

## [1.0.3] - 2026-02-18

### Fixed
- Narrowed `allowed-tools` in SKILL.md from `Bash(node *)` to `Bash(node scripts/trust-cli.ts *)` and `Bash(node scripts/action-cli.ts *)`
- Added `license`, `compatibility`, and `metadata` fields to SKILL.md
- Declared optional env vars (`GOPLUS_API_KEY`, `GOPLUS_API_SECRET`) in skill metadata
- Added explicit user confirmation requirement before trust registry mutations (`attest`, `revoke`)

### Added
- OpenClaw `session_start` hook for auto-scanning skill directories
- Auto-scan now covers both `~/.claude/skills/` and `~/.openclaw/skills/`

## [1.0.2] - 2026-02-17

### Fixed
- Harden security across 6 vulnerabilities (P0+P1)
- Use `~/.agentguard/registry.json` as default registry path
- Balanced mode prompts user instead of hard-blocking non-critical commands

### Added
- Integration tests and smoke tests for full-chain validation
- OpenClaw hook support with multi-platform adapter abstraction
- OpenClaw auto-scan and plugin registration

## [1.0.0] - 2026-02-16

### Added
- Initial release of GoPlus AgentGuard
- 24 detection rules covering execution, secrets, exfiltration, obfuscation, Web3, and social engineering
- Runtime action evaluation (allow/deny/confirm) for commands, network requests, file ops, and Web3 transactions
- Trust registry with capability-based access control per skill
- Claude Code hook integration (`PreToolUse` / `PostToolUse`)
- Audit logging to `~/.agentguard/audit.jsonl`
- Protection levels: strict, balanced, permissive
- GoPlus API integration for Web3 transaction simulation (optional)
