# DSH runtime guard

AgentGuard connects to DSH's native `tools/pre-execute` and `tools/post-execute` waterfalls. It translates each non-AgentGuard tool call into the shared `RuntimeAction` vocabulary, resolves the same effective policy used by the other AgentGuard hosts, runs the shared OSS evaluator, and writes a local audit event.

## Modes

The runtime integration accepts three explicit modes:

| Mode | Pre-execute | Post-execute | Intended use |
|---|---|---|---|
| `off` | no listener | no listener | scanner tools only |
| `observe` | evaluate and audit; preserve downstream decision | evaluate network responses and audit | packaged default and rollout baseline |
| `protect` | apply `allow`, `warn`, native `ask`, or `deny` | audit by default; optionally suppress block-class malicious results | explicit real-time protection |

The npm bundle continues to compose `observe` by default so installing an update does not silently change tool execution. Enable protection in a custom DSH composition:

```yaml
- insert:
    - id: agentguard-dsh-plugin
      name: '@goplus/agentguard/dist/dsh/plugin.js'
      config:
        runtime:
          mode: protect
          failureMode: deny
          postResponseMode: block-malicious
          attribution:
            toolOwners:
              find_dsh_plugin: dsh-find-plugin
          ownerPolicies:
            dsh-find-plugin:
              minimumDecision: require_approval
```

`failureMode` applies only to unexpected evaluator failures in `protect` mode. It defaults to `deny`. Set it to `allow` only for a deliberate compatibility rollout. Audit-file write failures do not erase a successfully evaluated policy decision and do not disable enforcement.

At plugin startup AgentGuard logs the configured mode and whether pre-execute enforcement is active. `agentguard_dsh_runtime_summary` also returns `configuredMode`, `preExecuteProtectionActive`, and `configuredPostResponseMode` even when the audit log is empty. Historical `runtimeModes` counts describe observed events; they are not a substitute for the current configured mode.

## Request processing

1. DSH supplies the immutable tool name, parsed arguments, call identity, root-call identity, optional parent token, and calling agent.
2. AgentGuard uses the official session header for the workspace cwd and resolves a relative shell workdir against it.
3. Common command, patch, image, file-search, HTTP, browser, deployment, skill-install, and MCP tools map to the shared action types. Unknown tools remain `other` and are still audited.
4. Network method, headers, and bounded body context are preserved for the shared evaluator.
5. AgentGuard resolves Cloud, cached, or bundled-default policy and evaluates locally. Cloud failure falls back to cached/default policy.
6. In `observe`, the downstream DSH policy is returned unchanged. In `protect`, the AgentGuard result is translated and monotonically merged with the downstream policy so a stronger third-party `ask` or `deny` is never weakened.
7. AgentGuard's own `agentguard_*` tools are excluded to prevent recursive protection.

## Decision mapping

| AgentGuard decision | DSH pre-execute result | Behavior |
|---|---|---|
| `allow` | `allow` | execute |
| `warn` | `allow` | execute and retain warning in audit |
| `require_approval` | `ask` | use DSH's native approval service |
| `block` | `deny` | do not dispatch the tool body |

DSH owns the one-shot approval interaction and its durable `approval/asked` plus `approval/decided` pair. AgentGuard does not create a parallel CLI approval entry. Only `allowed-once` resumes that tool call; rejection, cancellation, missing approval channels, headless `never`, a missing approval service, and agent-less calls fail closed in DSH.

The reason passed into DSH contains only a bounded risk score, normalized policy metadata, and up to five reason codes. Raw tool input, detector descriptions, evidence, and untrusted control text are excluded.

## Response containment boundary

Network results pass through `tools/post-execute`. AgentGuard extracts a bounded response preview plus available status, content type, headers, and byte count, then evaluates response and network-volume anomalies.

Post-execute remains audit-only in `observe` and in the default `protect` configuration. Set `postResponseMode: block-malicious` together with `mode: protect` to suppress only results whose final AgentGuard post-execute decision is `block`. The original result value and rendered content are not returned; DSH receives bounded AgentGuard feedback that excludes the untrusted preview and evidence. A stronger downstream block is preserved.

Approval-class post results remain audit-only because DSH has no native post-result `ask` or resumable held-result carrier. AgentGuard records the remaining `native-post-result-approval` and `approved-result-resume` gates rather than destroying a result that could not be resumed. Unexpected post evaluator errors fail open for the result path and remain available to downstream DSH policies; this avoids irrecoverable response loss caused by an internal guard failure.

## Audit and summary

Events are written to `~/.agentguard/audit.jsonl` with:

- native call/root identities and nested-call state;
- verified invocation context (`model-direct` or `nested-tool`), top-level/subagent origin, delegation depth, and agent preset when DSH supplies them;
- `sourceAttribution: "configured-tool-owner"` plus `sourceOwner` for exact operator-configured tool ownership bindings;
- shared decision, risk score, risk level, reason codes, and policy version;
- `runtimeMode`, `runtimePhase`, and `enforcementApplied`;
- the translated hook decision and disposition;
- `sourceAttribution: "unknown"` when no reliable owner binding exists.

`runtime.attribution.toolOwners` is an exact, case-sensitive map from a DSH tool name to a stable plugin or package id. It is operator-authored trust metadata, not a tool-name heuristic. Owner ids are bounded and validated, duplicate/ambiguous wildcard matching is not supported, and an unmapped tool remains `unknown`. Do not bind a name when another agent scope may shadow it with a different implementation.

`runtime.ownerPolicies` applies only after a call has a matching `configured-tool-owner`. Each owner declares a `minimumDecision` of `allow`, `warn`, `require_approval`, or `block`. This is a monotonic floor: it can strengthen the shared AgentGuard decision but can never weaken it. In particular, `minimumDecision: allow` means “no additional owner restriction”; it does not bypass a warning, approval, or block produced by the shared policy. An elevation adds the bounded `DSH_OWNER_POLICY` reason code to audit and native approval text.

In `protect`, pre-execute events set `enforcementApplied: true` and record the applied DSH hook decision. With `postResponseMode: block-malicious`, block-class post-execute events also set it to `true` and record `hookDecisionApplied: block`; approval-class post events remain `false`. DSH session events are the source of truth for the final human approval outcome.

`agentguard_dsh_runtime_summary` reads only the bounded final 1 MiB of the audit log and aggregates up to 1,000 recent DSH events. It reports decisions, action types, risks, phases, modes, applied-enforcement count, dispositions, gates, reason-code counts, nested calls, attribution coverage, invocation sources, session origins, and the top configured owners. Raw tool inputs and reason evidence are never returned to the model. An exact optional `sessionId` filter isolates one DSH call tree.

## Security parity

DSH does not maintain a separate detector. The normalized action goes through AgentGuard's shared policy and evaluator, so dangerous commands, protected paths, credential access, data exfiltration, outbound-network policy, response anomalies, and remote code execution retain the same semantics as other hosts.

Direct unpinned Git package execution through `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, or `bunx` requires approval. A full 40-character commit pin reduces this to a warning rather than treating remote code as trusted.

The host-parity matrix requires equivalent shell, file, and network actions to produce identical decisions, risk scores, risk levels, and reason codes across DSH, Codex, Claude Code, and OpenClaw. Host-specific lifecycle behavior is tested separately.

## Verified lifecycle behavior

The real DSH `ToolRuntime`, `ApprovalService`, and `Session` tests cover:

- concurrent safe calls;
- pre-execute allow, warn, native approval, rejection, and block;
- shell, file-write, and network actions;
- root and nested calls without duplicate approval;
- cancellation, unavailable/headless approval, missing services, and missing agents;
- stronger downstream policies;
- fail-closed and explicit fail-open evaluator errors;
- bounded audit output and explicit unknown attribution;
- audit-only approval-class response handling and optional block-class response suppression;
- plugin disposal removing the policy listener;
- install, update, uninstall, packaged assets, and live HTTP startup.

## Remaining host limitation

DSH currently supplies no reliable source-plugin ownership field on the lifecycle event. AgentGuard therefore supports exact operator-configured bindings and otherwise records explicit `unknown` attribution rather than guessing. Plugin-specific trust cannot silently bypass policy. When DSH exposes a stable tool-owner/provider identity, it can supersede configured bindings without changing the shared evaluator.
