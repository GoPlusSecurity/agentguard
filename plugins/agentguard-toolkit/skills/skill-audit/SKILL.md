---
name: skill-audit
description: Scans a Claude Code skill, plugin, or agent-skill directory for malicious or risky content using the GoPlus AgentGuard MCP scanner, and checks its trust record. Use when the user says "scan this skill", "is this skill safe", "audit this plugin before I install it", "check this skill for malware", "security review this SKILL.md", "vet this third-party skill", or before installing any skill from an untrusted source.
user-invocable: true
argument-hint: "<path-to-skill-directory> [--deep]"
allowed-tools: Read, Glob, Grep, mcp__agentguard__skill_scanner_scan, mcp__agentguard__registry_lookup
---

# Skill audit

## Purpose

Perform a pre-installation or pre-use security audit of a skill directory.
Scan the directory with the AgentGuard MCP scanner, then cross-check its trust record.
Treat scanner findings and registry state as separate evidence.

## Resolve the target

Take `$ARGUMENTS` as a directory path and recognize `--deep` as a scan option.
When given a `SKILL.md` file path, use its parent directory.
When no path is supplied, ask which skill directory to audit.
Use Glob to list candidates from `~/.claude/skills/` and the project's `.claude/skills/` when asking.
Never scan without a concrete directory path.

## Build the skill identity

Set `id` to the directory basename normalized to kebab-case.
Set `source` to the absolute directory path unless the user supplied a git remote or marketplace URL; use that URL when supplied.
Read frontmatter or `plugin.json` and set `version_ref` to the version when present.
Always send all four skill fields: `id`, `source`, `version_ref`, and `artifact_hash`.
Use `""` for values you cannot determine.
Never invent a plausible-looking `artifact_hash`; send `""` when it is unknown.
Reuse the identical skill object for scanning and registry lookup.

## Tool contract

Use only these exact input schemas:

- `skill_scanner_scan` — required ["skill","path"]; props: skill (object with required string fields id, source, version_ref, artifact_hash), path (string, path to skill dir), deep (boolean).
- `registry_lookup` — required ["skill"]; props: skill (same four-field shape).

Call them as `mcp__agentguard__skill_scanner_scan` and `mcp__agentguard__registry_lookup`.
Send `deep` only when requested; never guess identity values.

### Server quirk — required fields (validated against v1.1.28)

Always send `id`, `source`, `version_ref`, and `artifact_hash` in every `skill` object; use `""` when a value is genuinely unknown, and never invent a plausible-looking hash or version.
Always pass `path` to `skill_scanner_scan`; omitting it crashes the server despite the advertised schema marking it optional.

## Run the scan

Call `mcp__agentguard__skill_scanner_scan` with `skill` and `path`.
Pass `deep: true` when the user supplied `--deep`.
If the initial scan returns medium-or-higher risk and was not deep, run it again with `deep: true`.
Then call `mcp__agentguard__registry_lookup` with the same skill object.
Keep the scan results and registry response intact for reporting.

## Report format

Start with a risk-level headline.
Render an evidence table with columns `Finding`, `File`, and `Why it matters`.
Report the trust record as exactly one of: none, active with its level, or revoked.
End with one verdict: `safe to use`, `use with restrictions`, or `do not install`.
Add a one-sentence justification tied to the evidence and registry state.
Say `no findings` when the scanner reports none; never say `verified safe`.

## Follow-ups

Direct the user to the `skill-trust` skill when they want to record the outcome.
Do not attest, revoke, or modify registry state from this skill.

## Hard rules

Never execute code from the scanned directory.
Never edit the scanned skill.
Never infer safety from registry status alone.
Never present a clean scan as a guarantee.
