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

AgentGuard uses OpenClaw conversation hooks. For a non-bundled plugin, allow
conversation access in the plugin entry:

```json
{
  "plugins": {
    "entries": {
      "agentguard": {
        "hooks": {
          "allowConversationAccess": true
        }
      }
    }
  }
}
```

## Lifecycle coverage

AgentGuard registers only OpenClaw's existing public plugin hooks:

| Hook | AgentGuard behavior | Boundary |
| --- | --- | --- |
| `before_agent_run` | Blocking gate over the initial prompt, loaded history, and system prompt | Runs once at the supported run boundary; it is not a gate for every model call |
| `llm_input` | Redacted semantic request audit | Observer only |
| `llm_output` | Redacted partial response audit | Observer only |
| `model_call_started` / `model_call_ended` | Correlates `runId` / `callId` and records provider, model, and supplied byte statistics | Observer only |
| `before_tool_call` | Blocks dangerous commands and sensitive actions or returns native OpenClaw approval | Blocking |
| `after_tool_call` | Audits tool outcomes and visible response-poisoning evidence | Observer only |

Observer records always use `canBlockCurrentAction=false`. A policy result that
would block is therefore audited as `would_block`; it does not claim that the
model request or response was stopped. Provider and model are recorded only
when the hook supplies them. Final endpoint, credential presence/kind,
retry/fallback status, and unobserved auxiliary-call facts remain `unknown` and
are reported as unsupported.

OpenClaw does not expose a public, universal pre-send gate for every model
request. A second tool-loop call can be correlated when the diagnostic hooks
emit its `callId`, but compaction, internal retry/fallback, and auxiliary model
calls that do not emit the registered public hooks are unsupported. AgentGuard
does not register provider-private `wrapStreamFn`, monkey-patch provider
runtimes, or modify OpenClaw source.

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

For `before_tool_call`, AgentGuard returns OpenClaw's native
`requireApproval` result. OpenClaw owns the approval prompt and resumes the
exact tool call after an allowed decision. OpenClaw 2026.9.4's public
[plugin permission documentation](https://docs.openclaw.ai/plugins/plugin-permission-requests)
specifies that unresolved decisions, unavailable approval routes, and timeouts
block the tool call, and that the legacy `timeoutBehavior` field is deprecated.
This is an upstream host specification, not an AgentGuard enforcement
guarantee. AgentGuard requests only `allow-once` or `deny`. The initial
`before_agent_run` gate has no approval result in OpenClaw, so AgentGuard
returns only `pass` or `block` there. AgentGuard-controlled normalization,
parsing, and evaluator failures at these registered gates deny by default
unless explicit fallback mode is configured.

The real-runtime contract test was verified against OpenClaw 2026.9.4
(3a9d69d). It discovers an optional installed package through
`OPENCLAW_PACKAGE_ROOT` or `PATH`, imports only the public
`plugin-sdk/hook-runtime` and `plugin-sdk/plugin-runtime` exports, and verifies
registration and host result merging for run gates, native approval, model
observers, a second tool loop, and absent unsupported hooks. The deterministic
repository fixture remains supplemental. The test does not exercise
channel-specific approval delivery, unresolved/no-route handling, or timeout
execution. Approval routing and timeouts, host termination/crash, and any path
that never invokes the registered hook are host-controlled, locally unverified
capability boundaries outside AgentGuard's control.

## Docker demo

See `examples/openclaw-docker/` for a minimal Docker demo that installs `@goplus/agentguard`, runs `agentguard init --agent openclaw`, and provides a starter plugin.
