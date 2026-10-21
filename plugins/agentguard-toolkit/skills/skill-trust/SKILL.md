---
name: skill-trust
description: Manages the GoPlus AgentGuard trust registry for skills — look up, attest, revoke, and list trust records with explicit capability grants. Use when the user says "trust this skill", "attest this skill", "mark this skill trusted or restricted or untrusted", "revoke trust", "untrust this skill", "list trusted skills", "show the trust registry", "what skills are revoked", or "look up the trust record for X".
user-invocable: true
argument-hint: "[lookup|attest|revoke|list] [skill-id-or-source] [--level trusted|restricted|untrusted]"
allowed-tools: mcp__agentguard__registry_lookup, mcp__agentguard__registry_attest, mcp__agentguard__registry_revoke, mcp__agentguard__registry_list, mcp__agentguard__skill_scanner_scan
---

# Skill trust

## Purpose

Manage registry records through the AgentGuard MCP tools.
Remember that the registry is shared state at `~/.agentguard/registry.json`.
Treat changes as immediately relevant to this plugin's Skill trust-gate hook and the upstream AgentGuard CLI.

## Routing

Parse the first argument as `lookup`, `attest`, `revoke`, or `list`.
When no operation is supplied, ask which operation to perform.
Use the remaining arguments only to resolve the skill identity, filters, trust level, and capability proposal.

## Tool contract

Use only these exact input schemas:

- `registry_lookup` — required ["skill"]; props: skill (object with required string fields id, source, version_ref, artifact_hash).
- `registry_attest` — required ["skill","trust_level","capabilities"]; skill (same four-field shape); trust_level enum untrusted|restricted|trusted; capabilities object whose OWN required list is ["network_allowlist","filesystem_allowlist","exec","secrets_allowlist"] with network_allowlist string[], filesystem_allowlist string[], exec enum allow|deny, secrets_allowlist string[]; optional expires_at (string), reviewed_by (string), notes (string), force (boolean).
- `registry_revoke` — no required; props record_key, source, version_ref, reason (all strings).
- `registry_list` — no required; props trust_level (enum), status (enum active|revoked), source_pattern (string), include_expired (boolean).

For a pre-attestation scan, use this exact schema:

- `skill_scanner_scan` — required ["skill","path"]; props: skill (same four-field shape), path (string, path to skill dir), deep (boolean).

Call the tools with their full names from `allowed-tools`.
For every attestation, include all four capability keys: `network_allowlist`, `filesystem_allowlist`, `exec`, and `secrets_allowlist`.
Treat an empty array as a valid deny-all allowlist.
Set `exec` to exactly `allow` or `deny`.

### Server quirk — required fields (validated against v1.1.28)

Always send `id`, `source`, `version_ref`, and `artifact_hash` in every `skill` object for lookup, attest, and scan; use `""` when a value is genuinely unknown, and never invent a plausible-looking hash or version.
Always pass `path` when calling `skill_scanner_scan`.
For attest, prefer real `source`, `version_ref`, and `artifact_hash` values: the server builds `record_key` as `<source>@<version_ref>#<artifact_hash>`, and later revoke-by-source matching depends on them. Empty strings are accepted but produce a weak, near-useless key.

## Attest workflow

If this skill has not been scanned in the current session, run `mcp__agentguard__skill_scanner_scan` first and show its result.
Propose least-privilege capabilities, defaulting to empty allowlists and `exec: "deny"`.
Use this complete default capability object:

```json
{"network_allowlist":[],"filesystem_allowlist":[],"exec":"deny","secrets_allowlist":[]}
```

Require the user to name `untrusted`, `restricted`, or `trusted`, or explicitly approve the proposed level.
Never assign `trusted` when the scan reported findings unless the user explicitly overrides after seeing them.
Ask for the reviewer's name or email unless the user already stated it, then set `reviewed_by`.
Put the scan summary in `notes`.
Pass `force: true` only after the tool itself asks for confirmation and the user confirms in chat.

## Revoke workflow

Always require a non-empty `reason`.
Prefer `record_key` when it is known; obtain it through lookup or list first.
Before using `source` or `version_ref`, warn that patterns can match multiple records and show what will match.
Do not call revoke until the target and reason are clear.
When reading a record back, check `status` before `trust_level`: revoke sets `status` to `"revoked"` but leaves `trust_level` unchanged, so `status` is authoritative.

## List workflow

Map user filters only to `trust_level`, `status`, `source_pattern`, and `include_expired`.
Render results as a table with `Record key`, `Skill id`, `Level`, `Status`, and `Expiry`.
Preserve missing expiry values as empty or `none` rather than inventing dates.

## Hard rules

Never invent capability values.
Never attest without a user-named trust level or explicit approval of the proposal.
Report the tool's response verbatim when a conflict occurs.
Never imply that registry operations install, execute, or delete a skill.
