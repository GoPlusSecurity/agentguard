# Codex

AgentGuard integrates with Codex through the official synchronous Hooks
protocol. The integration is a local guardrail for the user prompt and
supported local tool paths; it is not a model-traffic proxy and does not see the
final model request or response.

## Requirements and installation

The minimum supported version is `codex-cli 0.148.0-alpha.15`, with the `hooks`
feature enabled. Confirm it before relying on the integration:

```bash
codex --version
codex features list
agentguard init --agent codex
```

Initialization creates or safely merges these repository-local files:

- `.codex/hooks.json`
- `.codex/hooks/agentguard-user-prompt.sh`
- `.codex/hooks/agentguard-pre-tool.sh`
- `.codex/hooks/agentguard-post-tool.sh`
- `.codex/skills/agentguard/SKILL.md`

Existing hook groups and unknown JSON keys are preserved. Re-running init is
idempotent. The retired `.codex/agentguard-hook.json` file is not a Codex hook
configuration source; AgentGuard never deletes or overwrites an existing copy.

Open `/hooks` after installation and review and trust the new hooks. Codex skips
project hooks until the project layer and exact hook definitions are trusted.
The Skill is usage documentation only and is never an enforcement boundary.
See the [official Codex Hooks documentation](https://developers.openai.com/codex/hooks/)
for discovery, trust, protocol, and tool-coverage details.

## Hook behavior

All installed security hooks run synchronously; AgentGuard never sets
`async: true`. Commands use absolute installed wrapper paths, so starting Codex
from a repository subdirectory does not bypass them.

- `UserPromptSubmit` scans only the current `prompt` locally. Sensitive visible
  content is rejected before that prompt is sent, using the official top-level
  `decision: "block"` shape. Warnings return only a short `systemMessage`.
- `PreToolUse` maps Bash/unified exec to `shell`, reads to `file_read`,
  `apply_patch`/write tools to `file_write`, local network tools to `network`,
  and `mcp__*` tools to `mcp_tool`. Both AgentGuard `block` and
  `require_approval` return `permissionDecision: "deny"`.
- `PermissionRequest` evaluates only an approval Codex has already decided to
  request. It can return the official `allow` or `deny` behavior, but it cannot
  create an approval prompt for an ordinary action.
- `PostToolUse` scans the model-facing result of supported tools. A blocking
  result prevents the original result from continuing to the next model step.
  The tool has already run, so filesystem, network, and other side effects are
  not undone.
- `PreCompact` and `PostCompact` record only the trigger and redacted policy
  metadata. AgentGuard does not open or parse `transcript_path`, and compact
  metadata is not sent to AgentGuard Cloud.

Codex does not support `permissionDecision: "ask"` for `PreToolUse`; AgentGuard
never emits it for Codex. A `require_approval` decision therefore fails closed:
the current call is denied with an action id and redacted reason. The user may
approve that id from a separate terminal and then explicitly retry:

```bash
agentguard approve --action-id act_local_... --once
```

This approval workflow is best-effort and partial: the guidance tells the agent
never to approve directly or indirectly, and approval is a human action outside
the agent session. It does not authenticate user presence and is not a
fail-closed approval security boundary. Claude Code retains its own native
`ask` behavior.

Malformed hook JSON and catchable evaluator/process errors cause the installed
wrapper to exit `2` with a generic, non-sensitive reason. If Codex forcibly
terminates the hook or the process cannot return an exit code, Codex's host
behavior applies; this integration does not claim those timeouts fail closed.
Hook stdout, stderr, audit, and Cloud events contain only bounded rule ids,
risk, action ids, coverage facts, and redacted reasons—not prompt text, tool
output, credentials, or PII.

## Coverage and known gaps

The following labels describe rule coverage, not model API traffic coverage.

| Privacy rule | Codex coverage | Meaning |
| --- | --- | --- |
| 14 `UNTRUSTED_LLM_ENDPOINT` | `unsupported` | Hooks do not expose the final model destination. |
| 15 `PII_EGRESS` | `partial` | The current user prompt and supported local tool results are scanned; system instructions, history, attachments, compacted context, and the final payload are not visible. |
| 16 `LLM_ENDPOINT_HIJACK` | `partial` | Supported pre-tool paths can block endpoint configuration edits and explicit shell changes; changes outside hooked tools and the actual next destination are not revalidated. |
| 17 `RELAY_RESPONSE_TAMPERING` | `unsupported` | `PostToolUse` sees tool results, not the raw model response or its source. |
| 18 `LLM_KEY_TO_UNKNOWN_HOST` | `unsupported` | Hooks do not expose the final destination together with model credential facts. |
| 19 `WORKSPACE_BULK_EGRESS` | `partial` | Visible reads and tool arguments can be checked heuristically, but final request bytes, attachments, history, and complete file counts are unavailable. |

Untrusted project hooks, hosted `WebSearch`, specialized tools that bypass the
local function-tool path, Codex internal/auxiliary model calls, and future
unsupported tool paths are excluded from protected-path statistics. Native
hooks cannot reliably observe or block the final model endpoint, credential,
complete payload, raw response, retries, fallbacks, or auxiliary requests.
