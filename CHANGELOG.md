# Changelog

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
