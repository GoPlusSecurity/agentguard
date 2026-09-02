---
name: action-precheck
description: Evaluates whether a proposed runtime action is safe using the GoPlus AgentGuard policy engine before it is executed — shell commands, file reads/writes, network requests, secret access, or Web3 operations. Use when the user says "is this command safe", "check this action", "should I run this", "is it safe to fetch this URL", "precheck this", "would AgentGuard allow this", or before running a risky operation in a production context.
user-invocable: true
argument-hint: "<description of the command, request, or file operation> [--env prod|dev|test]"
allowed-tools: mcp__agentguard__action_scanner_decide, mcp__agentguard__registry_lookup
---

# Action precheck

## Purpose

Perform a pre-flight policy check that returns allow, deny, or confirm with reasons.
Analyze the proposed action only.
Do not execute the action.

## Classify the action

Map the description to exactly one `action.type`:

| Description | Action type |
|---|---|
| curl, fetch, or a URL request | `network_request` |
| searching the web | `web_search` |
| shell or CLI invocation | `exec_command` |
| reading a normal file | `read_file` |
| creating or modifying a file | `write_file` |
| reading environment variables, keychains, `.env`, or tokens | `secret_access` |
| transaction or transfer | `web3_tx` |
| signature, permit, or typed data | `web3_sign` |

Ask a clarifying question when the type is genuinely ambiguous.
Do not combine action types in one call.

## Build the call

### Tool contract

Use this exact input schema:

- `action_scanner_decide` — required ["actor","action","context"]; actor = { skill: {id,source,version_ref,artifact_hash} } with all four string fields required; action = { type, data } both required, type enum network_request|web_search|exec_command|read_file|write_file|secret_access|web3_tx|web3_sign, data free-form object; context requires env (enum prod|dev|test), session_id (string), and user_present (boolean).

Call it as `mcp__agentguard__action_scanner_decide`.
When the action originates from a named skill, set `actor.skill` to that identity.
Optionally call `mcp__agentguard__registry_lookup` with the same identity for context.
Otherwise set `actor.skill` to `{"id":"claude-code-session","source":"","version_ref":"","artifact_hash":""}`.
Keep `action.data` minimal and factual because it is free-form.
Use `{"command":"..."}` for exec, `{"url":"..."}` for network, and `{"path":"..."}` for file operations.
Default `context.env` to `dev`.
Use `prod` only when the user says production or the target is clearly a live system.
Set `user_present: true`.
Use the real `session_id` when known; otherwise set it to the stable placeholder `"claude-code-session"`.

### Server quirk — required fields (validated against v1.1.28)

Always send `id`, `source`, `version_ref`, and `artifact_hash` in `actor.skill`; use `""` when a value is genuinely unknown, and never invent a plausible-looking hash or version.
Always send all three context fields: `env`, `session_id`, and `user_present`. Use the real session ID when known, otherwise use `"claude-code-session"`; set `user_present` to `true` when the user is in the chat.

## Interpret the verdict

For `allow`, state that the policy allows the action and include any returned caveats.
For `confirm`, quote the exact policy reason and ask the user to confirm.
For `deny`, quote the exact policy reason and do not offer workarounds.
Keep the policy result distinct from any separate judgment about the action.

## Hard rules

Evaluate one action per call.
Split compound commands and evaluate each action separately.
Never soften a deny.
Quote the policy reason verbatim.
Never execute, sign, send, install, or delete anything as part of this skill.
