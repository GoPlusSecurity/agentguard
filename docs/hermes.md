# Hermes Agent

AgentGuard integrates with [Hermes Agent](https://github.com/NousResearch/hermes-agent)
two ways: a **native plugin** (recommended) and **shell hooks** (fallback). Both
route tool calls through the same AgentGuard decision engine, so detection logic
is identical; they differ only in how they are installed and managed.

## Native plugin (recommended)

The plugin is managed the Hermes-native way (`hermes plugins
enable/disable/list`), runs before shell hooks, and adds a `/agentguard`
slash command. `agentguard init --agent hermes` installs the plugin and enables
it in `~/.hermes/config.yaml`.

```bash
# Build the engine so the plugin can reach it
npm run build

# Install the plugin into ~/.hermes/plugins/agentguard/
agentguard init --agent hermes

# Confirm it is enabled
hermes plugins list
```

The plugin shells out to the `agentguard` CLI (or a `hermes-hook.js` you point it
at). Make sure `agentguard` is on `PATH` (`npm i -g @goplus/agentguard`) or set
`AGENTGUARD_BIN`. See [`plugins/hermes/README.md`](../plugins/hermes/README.md)
for the full configuration reference (`AGENTGUARD_HERMES_*` env vars, fail policy,
autoscan).

| Hermes hook        | Behavior                                                        |
|--------------------|-----------------------------------------------------------------|
| `pre_tool_call`    | Blocks dangerous actions (`{"action":"block","message":...}`).  |
| `post_tool_call`   | Audit-only; never blocks.                                       |
| `on_session_start` | Best-effort skill scan (opt out: `AGENTGUARD_HERMES_AUTOSCAN=0`).|
| `/agentguard`      | Slash command: `status`, `report` (default), `checkup`.         |

## Shell hooks (fallback)

Use shell hooks when you prefer wiring AgentGuard directly into the Hermes config,
or on a Hermes build without the plugin system:

```bash
npm run build
agentguard init --agent hermes --shell-hooks
```

This merges the AgentGuard hook entries into `~/.hermes/config.yaml`. The bundled
template at `skills/agentguard/hermes-hooks.yaml` is also available for manual
setups:

```yaml
hooks:
  on_session_start:
    - command: "env AGENTGUARD_AUTO_SCAN=1 node \"/path/to/agentguard/skills/agentguard/scripts/auto-scan.js\""
      timeout: 30

  pre_tool_call:
    - matcher: "terminal|execute_code"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 10
    - matcher: "write_file|patch|skill_manage"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 10
    - matcher: "web_search|web_extract|browser_navigate"
      command: "node \"/path/to/agentguard/skills/agentguard/scripts/hermes-hook.js\""
      timeout: 10

  post_tool_call:
    - matcher: "terminal|execute_code|write_file|patch|skill_manage|read_file|web_search|web_extract|browser_navigate"
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
| `web_search` | `web_search` |
| `web_extract`, `browser_navigate`, `browser_open`, … | `network_request` |

## Decisions

Hermes `pre_tool_call` supports allow or block. AgentGuard `deny` decisions are
returned as:

```json
{"action":"block","message":"GoPlus AgentGuard: ..."}
```

AgentGuard `confirm` decisions are also represented as blocks because Hermes
`pre_tool_call` has no native confirmation decision.
