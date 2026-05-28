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
