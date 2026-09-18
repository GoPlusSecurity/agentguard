# Claude Code

AgentGuard installs synchronous, local `type: "command"` hooks in the current project. Run:

```bash
agentguard init --agent claude-code
```

This creates `.claude/hooks/agentguard-protect.sh` and structurally merges AgentGuard entries into `.claude/settings.local.json`. Existing settings, permissions, unknown keys, and other hooks on the same event are preserved. Re-running the initializer is idempotent; `--force` updates the managed script but never replaces the settings file wholesale.

Managed commands use `${CLAUDE_PROJECT_DIR}/.claude/hooks/agentguard-protect.sh`, so they continue to resolve after `/cd` or when Claude Code starts a hook from a nested directory. AgentGuard installs only local command hooks. It does not install `http`, `prompt`, `agent`, or external MCP hooks that could forward hook input.

## Version and installed capabilities

Initialization probes `claude --version` and prints the detected version, enabled events, gated events, and coverage summary. If the CLI is absent or its version cannot be parsed, base hooks are still installed and the host capability is reported as `unverified`. `PreModelSwitch` and `PostModelSwitch` are installed only for Claude Code 2.1.251 or newer; older versions report those events as `unsupported`.

The base installation registers:

- `UserPromptSubmit` and `UserPromptExpansion`
- `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, and `PostToolBatch`
- `ConfigChange`
- `MessageDisplay` and `Stop`
- `InstructionsLoaded`, `PreCompact`, and `PostCompact`

Hook execution is bounded to 30 seconds. Claude Code may continue the original action when a command hook times out or fails, including blocking hooks such as `UserPromptSubmit` and `PreToolUse`. This is a host fail-open gap, not a fail-closed guarantee. Catchable blocking-wrapper errors exit `2` with a fixed redacted message. Observer errors exit `0` and emit only `SECURITY_GATE_ERROR`.

## Lifecycle behavior

`UserPromptSubmit` scans the current prompt before Claude processes it. A block returns the native top-level `{ "decision": "block", "reason": "..." }` response. The reason contains only a bounded action ID, risk level, rule IDs, and a redacted explanation.

`UserPromptExpansion` evaluates `expansion_type`, `command_name`, `command_args`, and `command_source`. Project/custom commands, skills, and MCP prompts can be blocked from expanding. Coverage is `partial`: this event does not prove that AgentGuard saw the fully expanded prompt.

`PreToolUse` dynamically classifies Bash, PowerShell, Read, Write/Edit/MultiEdit, Web, MCP, image/file readers, and unknown tools from `tool_name` and `tool_input`. A block uses Claude Code's native `permissionDecision: "deny"`; `require_approval` uses `permissionDecision: "ask"`. Approval depends on Claude Code having an interactive approval UI. Non-interactive runs may not provide a usable approval path, so approval availability is not claimed as universal.

`PostToolUse` scans `tool_response`. AgentGuard uses `updatedToolOutput` only for verified response shapes: Read, Bash/PowerShell, WebFetch/WebSearch, and MCP content results. Redaction preserves the verified string/object/array shape. Unknown output schemas are not guessed or destructively rewritten; sensitive unknown output is marked `partial`/`would_block`, and `PostToolBatch` remains the continuation gate.

`PostToolUseFailure` records only redacted failure type/summary and coverage. It cannot replace or block a failed tool's output. Whether a particular Claude Code version includes failed results in a following `PostToolBatch.tool_calls[].tool_response` is `unverified` until tested on that version; if absent, the failure-output path is `unsupported`.

`PostToolBatch` scans each official `tool_calls[].tool_response` result Claude is about to use, records bounded file-path, byte, and redaction counts, and can stop the agentic loop before the next model call. Tool reads and side effects have already occurred. Existing transcript content is not removed, and a resumed session is not guaranteed to suppress retransmission.

`ConfigChange` reads the event source and, when `file_path` is present, at most the first 256 KiB of new local file content to detect endpoint changes, key forwarding, and dangerous permissions. Source-only events remain metadata-only partial coverage. A block prevents the current session from applying the change; it does not roll back the file on disk.

On Claude Code 2.1.251+, `PreModelSwitch` can deny or request approval for an explicit switch using `from_model`, `to_model`, `source`, and `context_tokens`. Explicit user/manual/API switches require approval, and any switch carrying 100,000 or more context tokens independently requires approval because it represents a material retransmission. Model IDs are labels, not endpoints, and are never treated as final transport destinations. `PostModelSwitch` audits automatic/session changes only. Automatic or one-shot fallbacks that do not emit the event remain `unsupported`.

`MessageDisplay` reads the official `delta` input and may return a masked top-level `displayContent`; it is always recorded as `display_only` with `canBlockCurrentAction=false`. It does not change the model response, transcript, or later `Stop` content. `Stop`, `InstructionsLoaded`, `PreCompact`, and `PostCompact` record redacted bounded metadata only; AgentGuard does not parse transcript files to invent payload, endpoint, credential, retry, or fallback facts.

## `@file` boundary

Claude Code does not emit `PreToolUse` for `@file` expansion. AgentGuard compensates only when the active cached policy explicitly contains a path that can be represented as one exact path. Initialization merges `Read(<exact-path>)` into `permissions.deny`. Relative exact paths are resolved against the project; glob patterns and unsafe matcher syntax are ignored. AgentGuard records only the exact denies it added in `.claude/agentguard-managed.json`, so a later initialization can replace or remove its own stale entries without removing user-owned deny rules. AgentGuard never expands defaults such as `**/.env*` into a workspace-wide deny.

An `@file` path without an explicit exact deny is `unsupported` and is not counted as PreToolUse coverage.

## Privacy and coverage

Raw prompts, command arguments, tool output, failure text, configuration content, credentials, and PII are evaluated locally. Native Claude hook audit and Cloud records replace hook content with `[LOCAL_ONLY_LLM_CONTENT]` and retain only bounded rule IDs, masks, counts, action IDs, coverage, and enforcement metadata. Hook stdout/stderr never echoes raw input.

Claude Code provides strong staged prompt/tool/context protection, but it does not expose the final model HTTP destination, Authorization credential, complete assembled payload, full response, all retries/fallbacks, or auxiliary model calls. Model-transport rules therefore remain `partial` or `unsupported`; AgentGuard does not claim complete model-traffic interception.
