# GoPlus AgentGuard — Cline plugin

A native [Cline](https://github.com/cline/cline) plugin that runs every tool
call through the [GoPlus AgentGuard](https://github.com/GoPlusSecurity/agentguard)
decision engine and **blocks risky shell, file, and network actions** before
they execute.

Two install surfaces — pick one:

| Surface | Lives at | Best for |
|---|---|---|
| **Runtime plugin** (this package) | `.cline/plugins/agentguard/` | TS plugin with typed `beforeTool` / `afterTool` hooks, runs in-process |
| **File hook** (`PreToolUse`) | `.cline/hooks/PreToolUse.js` | Stdin/stdout JSON contract, language-agnostic, also installs alongside this plugin |

Both reuse the same `ClineAdapter` and AgentGuard engine — detection logic
stays in one place.

## Requirements

- Cline ≥ the version that ships the SDK plugin system (`@cline/core`'s
  `AgentPlugin` with `hooks.beforeTool`). See
  [Cline plugin examples](https://github.com/cline/cline/tree/main/sdk/examples/plugins).
- The AgentGuard engine reachable as the `agentguard` CLI on `PATH`
  (`npm i -g @goplus/agentguard`), or installed locally where the plugin can
  `import('@goplus/agentguard')`.

## Install

```bash
# Installs the plugin into ~/.cline/plugins/agentguard/ and a file-hook
# script into ~/.cline/hooks/PreToolUse.js (you can keep one or both).
agentguard init --agent cline

# Then enable it inside Cline:
cline plugin install ~/.cline/plugins/agentguard
cline plugin list
```

Or install the runtime plugin directly from GitHub:

```bash
cline plugin install https://github.com/GoPlusSecurity/agentguard/blob/main/plugins/cline/index.ts
```

## What it does

| Cline hook        | Behavior                                                              |
|-------------------|-----------------------------------------------------------------------|
| `beforeTool`      | Evaluates the call; returns `{ skip: true, reason }` to veto a dangerous action, `{ review: true }` to pause for user confirmation. |
| `afterTool`       | Audit-only; never blocks.                                             |

Tools evaluated (others pass through untouched):
`run_commands`, `execute_command`, `write_to_file`, `write_file`,
`replace_in_file`, `editor`, `read_files`, `read_file`, `web_fetch`,
`browser_action`, `web_search`.

Cline's `beforeTool` natively supports both `skip` (cancel) and `review` (pause
for user approval), so AgentGuard's `deny` decisions map to `skip` and `ask`
decisions map to `review` — no lossy translation needed.

## Configuration

| Env var | Default | Effect |
|---|---|---|
| `AGENTGUARD_CLINE_FAIL_OPEN` | `0` | `1` allows tool calls when the engine cannot be loaded or errors. Default is fail-closed — both the runtime plugin and the file-hook share this single env var so enforcement is consistent across surfaces. |
| `AGENTGUARD_LEVEL` | `balanced` | Override AgentGuard protection level (`strict` / `balanced` / `permissive`) when no on-disk config is present. |

**Activation:** `agentguard init --agent cline` only writes files. The plugin is
inactive until you run `cline plugin install ~/.cline/plugins/agentguard` (Cline
plugins are opt-in).

**Fail policy:** Out-of-scope tools always pass through without an engine call.
For the security-sensitive tools above, both the runtime plugin and the file
hook default to **fail-closed** (a security gate that quietly turns off isn't a
security gate). Set `AGENTGUARD_CLINE_FAIL_OPEN=1` for local development. This
matches the Hermes plugin's posture and is a single env var across both Cline
surfaces.

## Development

The runtime plugin is a single TypeScript file (`index.ts`) with no runtime
dependencies beyond `@goplus/agentguard` and the Cline SDK. There is no build
step — Cline transpiles plugin TypeScript on install. The shared `ClineAdapter`
that this plugin invokes lives in
[`src/adapters/cline.ts`](../../src/adapters/cline.ts) of the AgentGuard repo
and is exported from `@goplus/agentguard`.
