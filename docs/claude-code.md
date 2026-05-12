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
- `WebFetch`, `WebSearch` → `network`

## Decisions

- `allow` and `warn` exit `0`
- `require_approval` and `block` exit `2`

Connected Cloud approvals print the approval id when creation succeeds.
