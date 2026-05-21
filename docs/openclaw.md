# OpenClaw

OpenClaw can use AgentGuard as a local runtime guard and optional Cloud-connected audit source.

## Plugin usage

To install and enable the AgentGuard OpenClaw plugin:

```bash
agentguard init --agent openclaw
```

This creates a local plugin under `~/.openclaw/plugins/agentguard` and enables it in `~/.openclaw/openclaw.json`.

```ts
import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',
    skipAutoScan: false,
  });
}
```

## Runtime hook shape

For direct hook integration, send events to:

```bash
AGENTGUARD_AGENT_HOST=openclaw \
AGENTGUARD_ACTION_TYPE=shell \
AGENTGUARD_TOOL_NAME=exec \
agentguard protect
```

AgentGuard accepts OpenClaw-style JSON with `toolName` and `params`, plus Claude-style `tool_name` and `tool_input`.

## Docker demo

See `examples/openclaw-docker/` for a minimal Docker demo that installs `@goplus/agentguard`, runs `agentguard init --agent openclaw`, and provides a starter plugin.
