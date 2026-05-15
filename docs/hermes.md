# Hermes Agent

Hermes Agent can use AgentGuard through Hermes shell hooks. AgentGuard evaluates
`pre_tool_call` events before risky tools execute and returns Hermes-compatible
block decisions on stdout.

## Shell hook usage

Build AgentGuard first so the hook script can import `dist/index.js`:

```bash
npm run build
```

Copy the template from `skills/agentguard/hermes-hooks.yaml` into
`~/.hermes/config.yaml` and replace `AGENTGUARD_SKILL_DIR` with the absolute
path to the installed AgentGuard skill directory.

```yaml
hooks:
  on_session_start:
    - command: "AGENTGUARD_AUTO_SCAN=1 node \"/path/to/agentguard/skills/agentguard/scripts/auto-scan.js\""
      timeout: 30

  pre_tool_call:
    - matcher: "terminal|execute_code"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 10
    - matcher: "write_file|patch|skill_manage"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 10
    - matcher: "web_search|web_extract|browser_.*"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 10

  post_tool_call:
    - matcher: "terminal|execute_code|write_file|patch|skill_manage|read_file|web_search|web_extract|browser_.*"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 5
```

Hermes asks for first-use consent for shell hooks. Use one of:

```bash
hermes --accept-hooks chat
HERMES_ACCEPT_HOOKS=1 hermes chat
```

or set `hooks_auto_accept: true` in `~/.hermes/config.yaml`.

## Tool mapping

| Hermes tool | AgentGuard action |
|-------------|-------------------|
| `terminal`, `execute_code` | `exec_command` |
| `write_file`, `patch`, `skill_manage` | `write_file` |
| `read_file` | `read_file` |
| `web_search`, `web_extract`, `browser_*` | `network_request` |

## Decisions

Hermes `pre_tool_call` supports allow or block. AgentGuard `deny` decisions are
returned as:

```json
{"action":"block","message":"GoPlus AgentGuard: ..."}
```

AgentGuard `ask` decisions are also represented as blocks because Hermes shell
hooks do not have a native confirmation decision.
