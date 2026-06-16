# GoPlus AgentGuard — Hermes plugin

A native [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that
runs every tool call through the [GoPlus AgentGuard](https://github.com/GoPlusSecurity/agentguard)
decision engine and **blocks risky shell, file, and network actions** before they
execute.

Unlike the shell-hook integration (which you wire into `~/.hermes/config.yaml` by
hand), this plugin is managed the Hermes-native way — `hermes plugins
enable/disable/list` — runs before shell hooks, and adds a `/agentguard` slash
command. It reuses the same AgentGuard engine, so detection logic stays in one
place.

## Requirements

- Hermes Agent (with the plugin system).
- The AgentGuard engine reachable as the `agentguard` CLI on `PATH`
  (`npm i -g @goplus/agentguard`), or pointed at via `AGENTGUARD_BIN` /
  `AGENTGUARD_HERMES_HOOK`.

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
| `AGENTGUARD_HERMES_HOOK` | — | Explicit path to `hermes-hook.js` (used instead of the CLI). |
| `AGENTGUARD_HERMES_TIMEOUT` | `10` | Per-call engine timeout (seconds). |
| `AGENTGUARD_HERMES_FAIL_OPEN` | `0` | `1` allows tool calls when the engine can't be reached (default fails closed). |
| `AGENTGUARD_HERMES_ALLOW_NPX` | `0` | `1` permits the `npx -y @goplus/agentguard` fallback when no local binary is found. Off by default — `npx` fetches an unpinned package over the network, which is unsafe for a security gate. |
| `AGENTGUARD_HERMES_AUTOSCAN` | `1` | `0` disables the session-start skill scan. |

**Activation:** `agentguard init --agent hermes` installs the plugin and enables
it in `~/.hermes/config.yaml`. It takes effect on the next Hermes session. If you
copy this directory manually, run `hermes plugins enable agentguard`.

**Fail policy:** for the security-sensitive tools above, the plugin fails
**closed** (blocks) on `pre_tool_call` when the engine cannot be reached, and also
when a mapped event arrives without its required field (e.g. `terminal` with no
`command`) — matching the shell-hook behavior. Out-of-scope tools pass through
without an engine call. Post-tool evaluation never blocks.

## Development / tests

```bash
cd plugins/hermes
python -m pytest        # no Node engine required — the bridge is stubbed
```

Tests stub the engine via an injected runner, so they exercise the allow / block /
confirm→block / post-audit / fail-mode contract without spawning a subprocess.
