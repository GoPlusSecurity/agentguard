# DSH runtime observation

AgentGuard Runtime Phase 2A connects to DSH's native `tools/pre-execute` waterfall. It translates each non-AgentGuard tool call into the shared `RuntimeAction` vocabulary, resolves the same effective runtime policy used by other AgentGuard hosts, runs the same OSS action evaluator, and writes the evaluated decision to the local audit log.

## Current behavior

The shipped mode is `observe`:

1. DSH supplies the immutable tool name, parsed arguments, call identity, root-call identity, optional parent token, and calling agent. AgentGuard uses the official session header for the workspace cwd and resolves a relative shell `workdir` against it.
2. AgentGuard maps recognized tools—including common command, patch, image, file-search, HTTP, browser, and MCP names—to `shell`, `file_read`, `file_write`, `web_search`, `network`, `deploy`, `skill_install`, or `mcp_tool`. Unknown tools remain `other` and are still audited.
3. AgentGuard preserves evaluator-relevant request context such as network method, headers, and body preview. `evaluateRuntimeAction()` then resolves Cloud, cached, or bundled-default policy and delegates to the existing `evaluateLocalAction()` / `ActionScanner` path.
4. AgentGuard records the policy decision, risk score, reasons, call tree metadata, and `sourceAttribution: "unknown"` in `~/.agentguard/audit.jsonl`.
5. The listener calls the next DSH policy unchanged. AgentGuard never returns its evaluated `deny` or `ask` in Phase 2A.

This means an audit event may contain `decision: "block"` while the action executed. The fields `runtimeMode: "observe"` and `enforcementApplied: false` make that distinction explicit.

AgentGuard's own `agentguard_*` tools are excluded to prevent recursive self-observation. Evaluation or audit failures are fail-open in Phase 2A and cannot change DSH behavior.

## Runtime summary tool

The installed bundle registers `agentguard_dsh_runtime_summary`. It reads only the bounded final 1 MiB of the configured local audit log and aggregates up to 1,000 recent DSH observation events. An optional exact `sessionId` filter can isolate one DSH call tree.

The result contains decision, action-type, risk-level, reason-code, and nested-call counts. It deliberately omits raw tool inputs, reason evidence, and command or file contents so asking DSH for a summary does not feed captured secrets back into the model context. Malformed audit lines are counted and ignored. AgentGuard's `agentguard_*` exclusion also prevents the summary request from observing itself.

## Configuration

The packaged Cordis row enables observation explicitly:

```yaml
- insert:
    - id: agentguard-dsh-plugin
      name: '@goplus/agentguard/dist/dsh/plugin.js'
      config:
        runtime:
          mode: observe
```

Set `runtime.mode` to `off` in a custom composition to omit the listener. No enforcement mode is accepted in Phase 2A.

## Security parity

DSH does not maintain a separate rule engine. The normalized action goes through AgentGuard's shared runtime policy and detector path, so dangerous commands, remote code execution, protected paths, credential access, exfiltration, outbound-network policy, and supported network anomalies retain the same scoring and decision semantics.

Direct Git package execution is part of the shared shell policy. Unpinned `npx`/`npm exec`/`pnpm dlx`/`yarn dlx`/`bunx` Git sources receive a high-risk `REMOTE_CODE_EXECUTION` decision. A Git source pinned to a full 40-character commit remains visible as a medium-risk warning. Ordinary registry package runners and quoted documentation examples are not classified as Git execution.

The host-parity regression matrix evaluates equivalent shell, file, and network actions with DSH, Codex, Claude Code, and OpenClaw host identities. It requires identical decision, risk score, risk level, and reason codes. This protects shared security semantics while allowing host-specific lifecycle behavior at the boundary.

Host behavior intentionally differs at the boundary:

- DSH supplies native call-tree identities rather than a shell-hook payload.
- Phase 2A uses local audit only; it may fetch an effective Cloud policy when AgentGuard is connected, but it does not upload DSH events.
- DSH currently supplies no reliable source-plugin ownership field. AgentGuard records `unknown` rather than guessing, so plugin-specific trust and capability enforcement is not yet equivalent.
- Post-response anomaly enforcement and native `ask`/`deny` translation are deferred to later phases.
- Phase 2A observes pre-execution request context only. Response status, headers, sizes, and content anomalies require a future `tools/post-execute` observer.

## Gate for enforcement

An enforcing mode must not be enabled until tests prove all of the following:

- `allow`, `warn`, `require_approval`, and `block` translate deterministically to DSH behavior.
- `require_approval` uses DSH's native approval service without creating a second AgentGuard CLI approval.
- Root calls and `run_code` sub-dispatches are covered without duplicate prompts or audit events.
- Cancellation, missing approval channels, headless policy, listener failure, and unload behavior are defined.
- Missing source attribution remains explicit and cannot silently grant plugin-specific trust.
