# DSH runtime observation

AgentGuard Runtime Phase 2A connects to DSH's native `tools/pre-execute` and `tools/post-execute` waterfalls. It translates each non-AgentGuard tool call into the shared `RuntimeAction` vocabulary, resolves the same effective runtime policy used by other AgentGuard hosts, runs the same OSS action evaluator, and writes the evaluated decision to the local audit log.

## Current behavior

The shipped mode is `observe`:

1. DSH supplies the immutable tool name, parsed arguments, call identity, root-call identity, optional parent token, and calling agent. AgentGuard uses the official session header for the workspace cwd and resolves a relative shell `workdir` against it.
2. AgentGuard maps recognized tools—including common command, patch, image, file-search, HTTP, browser, and MCP names—to `shell`, `file_read`, `file_write`, `web_search`, `network`, `deploy`, `skill_install`, or `mcp_tool`. Unknown tools remain `other` and are still audited.
3. AgentGuard preserves evaluator-relevant request context such as network method, headers, and body preview. `evaluateRuntimeAction()` then resolves Cloud, cached, or bundled-default policy and delegates to the existing `evaluateLocalAction()` / `ActionScanner` path.
4. AgentGuard records the policy decision, risk score, reasons, call tree metadata, and `sourceAttribution: "unknown"` in `~/.agentguard/audit.jsonl`.
5. The listener calls the next DSH policy unchanged. AgentGuard never returns its evaluated `deny` or `ask` in Phase 2A.
6. Network-tool results pass through a second audit-only observation. AgentGuard extracts a bounded response preview plus available status, content type, headers, and byte count, then evaluates response and network-volume anomalies without replacing or blocking the DSH result.
7. Each audit event includes a deterministic shadow enforcement plan. It records the DSH-native hook decision and disposition that the current AgentGuard policy would select, plus any integration gates that remain. This metadata is explanatory only and is never returned by the lifecycle listener.

This means an audit event may contain `decision: "block"` and `shadowHookDecision: "deny"` while the action executed. The fields `runtimeMode: "observe"` and `enforcementApplied: false` make that distinction explicit. `runtimePhase` distinguishes `pre` request observations from `post` response observations.

## Shadow enforcement mapping

The mapping is deliberately pure and deterministic so it can be tested before any mutation is enabled:

| AgentGuard decision | Pre-execute plan | Post-execute plan |
|---|---|---|
| `allow` | `allow` / proceed | `accept` / accept result |
| `warn` | `allow` / proceed with warning | `accept` / accept result with warning |
| `require_approval` | `ask` / request native approval | `block` / hold result for native approval |
| `block` | `deny` / deny execution | `block` / suppress result |

Approval plans carry explicit gates for DSH native approval, headless behavior, and approved-result resume. Post-result blocking also remains gated on suppression validation. The observer only writes this plan to audit metadata; both lifecycle listeners still return the downstream DSH decision unchanged.

AgentGuard also exports a protocol adapter for pre/post decision translation and monotonic composition tests. It is intentionally not registered by the packaged plugin and there is no `enforce` configuration value. The pre adapter returns DSH's native `{ kind: "ask", reason }` for `require_approval`; DSH—not AgentGuard—then owns the one-shot approval request, durable `approval/asked` + `approval/decided` pair, cancellation, and final allow/deny result. AgentGuard does not create a parallel CLI approval entry.

The reason passed into DSH contains only bounded policy metadata and up to five reason codes. Raw tool input, detector descriptions, and evidence are excluded. Composition helpers preserve a downstream `deny`, `ask`, or post-result `block`, so another DSH policy cannot be weakened.

AgentGuard's own `agentguard_*` tools are excluded to prevent recursive self-observation. Evaluation or audit failures are fail-open in Phase 2A and cannot change DSH behavior.

## Runtime summary tool

The installed bundle registers `agentguard_dsh_runtime_summary`. It reads only the bounded final 1 MiB of the configured local audit log and aggregates up to 1,000 recent DSH observation events. An optional exact `sessionId` filter can isolate one DSH call tree.

The result contains decision, action-type, risk-level, pre/post phase, shadow-disposition, gated-enforcement, reason-code, and nested-call counts. It deliberately omits raw tool inputs, reason evidence, and command or file contents so asking DSH for a summary does not feed captured secrets back into the model context. Malformed audit lines are counted and ignored. AgentGuard's `agentguard_*` exclusion also prevents the summary request from observing itself.

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
- Post-response anomaly enforcement and native `ask`/`deny` translation are deferred to later phases; response anomalies are currently recorded only.
- Pre/post network observations correlate by DSH call identity so one request is not counted twice by replay, rate, or volume behavior analysis.
- A bounded response fixture corpus locks detection for ordinary JSON, executable markup, obfuscated script staging, binary/HTML mismatch, stack disclosure, local-file disclosure markers, and credential echo.

## Gate for enforcement

An enforcing mode must not be enabled until tests prove all of the following:

- `allow`, `warn`, `require_approval`, and `block` translate deterministically to DSH behavior.
- `require_approval` uses DSH's native approval service without creating a second AgentGuard CLI approval.
- Root calls and `run_code` sub-dispatches are covered without duplicate prompts or audit events.
- Cancellation, missing approval channels, headless policy, listener failure, and unload behavior are defined.
- Missing source attribution remains explicit and cannot silently grant plugin-specific trust.

The shadow mapping satisfies the deterministic-translation design requirement, but it does not satisfy the native approval, cancellation, headless, or post-result-resume gates by itself.

The protocol contract test now proves that a translated `ask` reaches DSH's native tool pipeline and fails closed before tool dispatch when no approval service is composed. Interactive `allowed-once`, explicit rejection, cancellation during an open turn, and post-result resume remain required before an enforcing mode can ship.
