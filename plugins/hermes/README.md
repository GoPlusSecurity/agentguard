# GoPlus AgentGuard — Hermes plugin

A native [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that
observes supported main-loop model traffic and runs tool calls through the
[GoPlus AgentGuard](https://github.com/GoPlusSecurity/agentguard) decision engine.
It **blocks risky shell, file, and network actions** before they execute.

Unlike the shell-hook integration (which you wire into `~/.hermes/config.yaml` by
hand), this plugin is managed the Hermes-native way — `hermes plugins
enable/disable/list` — runs before shell hooks, and adds a `/agentguard` slash
command. It reuses the same AgentGuard engine, so detection logic stays in one
place.

## Requirements

- Hermes Agent (with the plugin system).
- The AgentGuard engine reachable as the `agentguard` CLI on `PATH`
  (`npm i -g @goplus/agentguard`), or pointed at via `AGENTGUARD_BIN`.

## Install

```bash
# Installs the plugin into ~/.hermes/plugins/agentguard/
agentguard init --agent hermes

# Confirm it is enabled:
hermes plugins list
```

Or copy this directory to `~/.hermes/plugins/agentguard/` manually.

## What it does

| Hermes hook        | Behavior                                                        |
|--------------------|-----------------------------------------------------------------|
| `pre_llm_call`     | Non-mutating turn boundary; it is not a per-request gate.       |
| `pre_api_request`  | Observes supported main-loop requests; never blocks them.       |
| `post_api_request` | Observes and correlates main-loop responses; never blocks them. |
| `pre_tool_call`    | Evaluates the call; returns `{"action":"block","message":...}` to veto a dangerous action. |
| `post_tool_call`   | Audit-only; never blocks.                                       |
| `on_session_start` | Best-effort background scan of installed skills (opt out: `AGENTGUARD_HERMES_AUTOSCAN=0`). |
| `/agentguard`      | Slash command — `status`, `report` (default), or `checkup`.     |

Tools evaluated (others pass through untouched): `terminal`, `execute_code`,
`write_file`, `patch`, `skill_manage`, `read_file`, `web_search`, `web_extract`,
`browser_navigate`, `browser_open`, `web_open`, `open_url`, `visit_url`, `open`.

Hermes `pre_tool_call` has no native "ask"/confirm decision, so AgentGuard's
*confirm* decisions are surfaced as blocks with a confirmation-oriented message.

## Configuration

| Env var | Default | Effect |
|---------|---------|--------|
| `AGENTGUARD_BIN` | — | Explicit path to the `agentguard` CLI. |
| `AGENTGUARD_HERMES_TIMEOUT` | `10` | IPC connect/read timeout (seconds). |
| `AGENTGUARD_HERMES_FAIL_OPEN` | `0` | `1` allows tool calls when the engine can't be reached (default fails closed). |
| `AGENTGUARD_HERMES_IPC_PORT` | per-user derived | Optional Windows authenticated-loopback port override. |
| `AGENTGUARD_HERMES_IPC_TOKEN` | generated locally | Optional Windows IPC token override; at least 32 UTF-8 bytes. |
| `AGENTGUARD_HERMES_AUTOSCAN` | `1` | `0` disables the session-start skill scan. |

**Activation:** `agentguard init --agent hermes` installs the plugin and enables
it in `~/.hermes/config.yaml`. It takes effect on the next Hermes session. If you
copy this directory manually, run `hermes plugins enable agentguard`.

**Fail policy:** for the security-sensitive tools above, the plugin fails
**closed** (blocks) on `pre_tool_call` when the engine cannot be reached, and also
when a mapped event arrives without its required field (e.g. `terminal` with no
`command`) — matching the shell-hook behavior. Out-of-scope tools pass through
without an engine call. Post-tool evaluation never blocks.

The plugin starts one persistent `agentguard hermes-daemon` on demand instead
of launching Node for each prompt. Unix uses a `0600` socket inside a `0700`
runtime directory plus a current-user POSIX advisory file lease that serializes
stale-lock recovery. Windows uses authenticated `127.0.0.1`
IPC with a token kept
under the current user's AgentGuard runtime directory. A mutual HMAC challenge
authenticates the daemon before the client sends prompt or tool content; the
token itself is never transmitted. Requests are capped at 1 MiB, responses at
256 KiB, and partial frames are bounded by the timeout.

## LLM traffic coverage

`pre_api_request` and `post_api_request` are Hermes observers. AgentGuard maps
their visible provider, model, base URL, messages/response, and request ID into
local `llm_request` and `llm_response` evaluations, always with
`canBlockCurrentAction=false`. A block-class policy result is recorded as
`would_block`; it does not mean the provider request was stopped. If suspicious
output induces a dangerous local action, `pre_tool_call` remains the final
blocking boundary.

Complete system/tool payloads, the final transport destination, credentials,
exact bytes, internal retry/fallback, title generation, compression, iteration
summaries, trajectory paths, and other auxiliary SDK calls remain incomplete or
unsupported. A T3 base URL observation is therefore not a pre-send block.

## Development / tests

```bash
cd plugins/hermes
python -m pytest        # no Node engine required — the bridge is stubbed
```

Tests inject the legacy runner or persistent IPC transport, so they exercise the
request/response observer, allow/block, post-audit, and fail-mode contracts
without requiring a real Hermes installation.
