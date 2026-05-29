# Codex

Codex can use AgentGuard as a local skill/runtime template for command, file, and network review.

## Local commands

```bash
npm install -g @goplus/agentguard
agentguard init
agentguard scan ./skills/example
```

## Runtime template

To write Codex templates in the current project:

```bash
agentguard init --agent codex
```

This creates `.codex/skills/agentguard/SKILL.md` and `.codex/agentguard-hook.json`.

Pipe a tool event to `agentguard protect`:

```bash
printf '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | AGENTGUARD_AGENT_HOST=codex agentguard protect --json
```

Use these mappings for Codex-style hooks or skills:

- shell commands → `shell`
- file reads → `file_read`
- file writes/patches → `file_write`
- browser/network fetches → `network`
- MCP tool calls → `mcp_tool`

When Cloud is connected, Codex events are synced as redacted previews. Confirmation still happens through the local agent permission flow, not a Cloud approval page.

If a protected action returns `confirm`, AgentGuard stores a short-lived pending
approval and includes an approval command:

```bash
agentguard approve --action-id act_local_... --once
```

Show that command to the user before running it. Run it only after the user
explicitly approves that exact action; do not let the agent approve its own
blocked command proactively. Then retry the original action once. If the action id was not visible, inspect
`agentguard approvals list --json`; use `agentguard approve --last --once`
only when there is exactly one relevant unexpired pending approval.
