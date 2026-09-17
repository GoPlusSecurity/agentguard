# Hermes Agent

AgentGuard integrates with [Hermes Agent](https://github.com/NousResearch/hermes-agent)
two ways: a **native plugin** (recommended) and **shell hooks** (fallback). The
native plugin observes supported main-loop LLM traffic and protects tool calls;
the shell-hook fallback protects tool calls only. Both reuse the same local
AgentGuard evaluator and redacted audit pipeline.

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

The plugin starts one persistent local evaluator on demand and communicates over
current-user IPC, avoiding a Node startup for every large prompt. Make sure
`agentguard` is on `PATH` (`npm i -g @goplus/agentguard`) or set
`AGENTGUARD_BIN`. See [`plugins/hermes/README.md`](../plugins/hermes/README.md)
for IPC limits, environment variables, and failure policy.

| Hermes hook        | Behavior                                                        |
|--------------------|-----------------------------------------------------------------|
| `pre_llm_call`     | Non-mutating turn boundary; not a per-model-request gate.        |
| `pre_api_request`  | Main-loop request observer; emits redacted `llm_request` audit.  |
| `post_api_request` | Main-loop response observer; emits correlated `llm_response` audit. |
| `pre_tool_call`    | Blocks dangerous actions (`{"action":"block","message":...}`).  |
| `post_tool_call`   | Audit-only; never blocks.                                       |
| `on_session_start` | Best-effort skill scan (opt out: `AGENTGUARD_HERMES_AUTOSCAN=0`).|
| `/agentguard`      | Slash command: `status`, `report` (default), `checkup`.         |

### LLM lifecycle capability

| Capability | Effective coverage |
| --- | --- |
| Main-loop model request/response | `observe_only`; `canBlockCurrentAction=false` |
| Dangerous tool execution | `blocking` at `pre_tool_call` |
| Full system/tools and exact payload/response | incomplete |
| Final destination, credentials, exact bytes | unavailable |
| Retry/fallback and auxiliary model calls | unsupported |
| Title, compression, iteration summary, trajectory paths | unsupported |

`pre_api_request` exposes a base-URL hint, provider/model, and visible message
data. It is not a transport gate: even when local policy would block a T3/T4
endpoint or visible PII, AgentGuard records `policyDecision` plus
`enforcementStatus=would_block` and returns no blocking directive. Likewise,
`post_api_request` can correlate suspicious output but cannot stop it from
flowing through Hermes. The actual final interception is `pre_tool_call` if the
response attempts a dangerous local action.

On Unix, the evaluator uses a `0600` socket inside a `0700` directory; a
current-user POSIX advisory file lease serializes daemon ownership and stale-lock
recovery. Windows uses loopback IPC with a
current-user token and a mutual HMAC challenge: the
client authenticates the daemon before sending prompt or tool content, and the
token itself is never transmitted. Requests are capped at 1 MiB, responses at
256 KiB, and timeouts are bounded; a blocking tool gate fails closed when IPC
is unavailable unless explicitly configured fail-open.

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
