# Claude Code

Claude Code can call AgentGuard before risky tool use.

## Minimal runtime hook

To write the template automatically in the current project:

```bash
agentguard init --agent claude-code
```

This creates `.claude/hooks/agentguard-protect.sh` and `.claude/settings.local.json`.

Configure a PreToolUse hook that pipes Claude Code hook JSON to `agentguard protect`:

```json
{
  "matcher": "Bash",
  "hooks": [
    {
      "type": "command",
      "command": "AGENTGUARD_AGENT_HOST=claude-code AGENTGUARD_ACTION_TYPE=shell AGENTGUARD_TOOL_NAME=Bash agentguard protect"
    }
  ]
}
```

Recommended matchers:

- `Bash` → `shell`
- `Read` → `file_read`
- `Write`, `Edit`, `MultiEdit` → `file_write`
- `WebFetch` → `network`
- `WebSearch` → `web_search`

## Decisions

- `allow` and `warn` exit `0`
- `require_approval` is returned as Claude Code's native `ask` response when available
- `block` exits `2`

Cloud-connected runs still enforce locally. AgentGuard does not require a Cloud approval page for runtime confirmation.
