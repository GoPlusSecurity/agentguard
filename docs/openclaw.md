# OpenClaw

OpenClaw can use AgentGuard as a local runtime guard and optional Cloud-connected audit source.

## Plugin usage

To install and enable the AgentGuard OpenClaw plugin:

```bash
agentguard init --agent openclaw
```

This creates a local plugin under `~/.openclaw/plugins/agentguard`, installs the AgentGuard skill under `~/.openclaw/skills/agentguard`, and enables the plugin in `~/.openclaw/openclaw.json`.

```ts
import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',
    skipAutoScan: false,
  });
}
```

## Cloud connect

After OpenClaw initialization, run:

```bash
agentguard connect
```

No API key is required for the OpenClaw flow. AgentGuard registers a local Agent
JWT, prints an activation link, and may send the link to the latest OpenClaw
channel. Open that link to bind the local agent to your account.

## Runtime hook shape

For direct hook integration, send events to:

```bash
AGENTGUARD_AGENT_HOST=openclaw \
AGENTGUARD_ACTION_TYPE=shell \
AGENTGUARD_TOOL_NAME=exec \
agentguard protect
```

AgentGuard accepts OpenClaw-style JSON with `toolName` and `params`, plus Claude-style `tool_name` and `tool_input`.

OpenClaw cannot safely pause and resume a protected tool call, so AgentGuard
blocks `require_approval` actions locally and stores a short-lived pending
approval. The block reason includes:

```bash
agentguard approve --action-id act_local_... --once
```

Show that command to the user before running it. Run it only after the user
explicitly approves that exact action; do not let the agent approve its own
blocked command proactively. Then retry the original action once. If the action id was not visible in the OpenClaw message,
inspect pending approvals first:

```bash
agentguard approvals list --json
```

Use `agentguard approve --last --once` only when there is exactly one relevant
unexpired pending approval; otherwise approve the specific `actionId`.

## Docker demo

See `examples/openclaw-docker/` for a minimal Docker demo that installs `@goplus/agentguard`, runs `agentguard init --agent openclaw`, and provides a starter plugin.
