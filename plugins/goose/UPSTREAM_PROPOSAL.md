# Goose upstream proposal — generic security webhook inspector

This document drafts a proposal to file against [block/goose](https://github.com/block/goose)
that would give third-party security tools (AgentGuard, but also others) a
real out-of-process hard gate on tool execution.

This is **not** a PR yet — it's the design that should accompany one.

## Problem

Goose currently has two ways to wire in security policy on tool calls:

1. **`ToolInspector` trait** (Rust, in-process, compile-time). The real
   `Allow / Deny / RequireApproval` decision surface, but there is no
   dynamic loader for it — third parties cannot ship one without forking
   and rebuilding Goose.
2. **MCP extensions**. Model-callable. The agent can skip your tools, so
   this is advisory only — it is not a security boundary.

This means there is no supported way today for an external security service
(static analyzer, runtime engine, anomaly detector) to gate Goose's tool
execution without forking the binary.

## Prior art inside Goose

Goose already accepts an external HTTP endpoint for one specific
classification job. From `crates/goose/src/security/classification_client.rs`
and the config:

```
SECURITY_PROMPT_CLASSIFIER_ENDPOINT
SECURITY_PROMPT_ENABLED
```

The classifier endpoint receives JSON, returns a classification, and Goose
honors the result. This is the pattern we're asking to generalize.

## Proposal

Add a new `WebhookToolInspector` that registers automatically when a
configured endpoint is set:

```yaml
# ~/.config/goose/config.yaml
SECURITY_INSPECTOR_ENABLED: true
SECURITY_INSPECTOR_ENDPOINT: "http://127.0.0.1:7777/inspect"
SECURITY_INSPECTOR_TIMEOUT_MS: 1500
SECURITY_INSPECTOR_FAIL_OPEN: false       # default: fail-closed
SECURITY_INSPECTOR_AUTH_HEADER: "X-Token: …"
```

At startup, `ToolInspectionManager::add_inspector` registers a built-in
`WebhookToolInspector` if `SECURITY_INSPECTOR_ENABLED == true`. It calls the
endpoint for every `ToolRequest`, with a JSON body like:

```json
{
  "session_id": "sess_…",
  "tool_requests": [
    { "tool": "developer__shell", "input": { "command": "rm -rf /" }, "call_id": "…" }
  ],
  "messages": [ /* optional, truncated */ ],
  "goose_mode": "auto"
}
```

And expects back:

```json
{
  "results": [
    { "call_id": "…",
      "action": "Deny",
      "reason": "destructive command",
      "policy_version": "…" }
  ]
}
```

`action` is one of `Allow`, `Deny`, `RequireApproval`. The webhook's response
maps 1:1 to `InspectionAction` — no impedance mismatch with the existing
trait.

## Why this is a small change

- It doesn't change the `ToolInspector` trait. The new inspector is just
  another implementer.
- It mirrors a pattern Goose already accepts (the classifier endpoint), so
  it should pass the "is this in scope for this project?" smell test.
- Fail-open vs fail-closed is configurable, with a security-safe default
  (fail-closed).
- No new permissions to plumb through the trust system; existing
  `ToolInspectionManager` handles aggregation.

## What we'd ship in the PR

1. `crates/goose/src/security/webhook_inspector.rs` — `WebhookToolInspector` impl
2. Config keys + parsing in `crates/goose/src/config/`
3. Registration in `crates/goose/src/agents/` startup
4. Tests (mocking the endpoint with `wiremock` or similar)
5. A docs page in `docs/security/` covering trade-offs and recommended deploys

## Open questions to confirm with maintainers before opening the PR

- Naming: `SECURITY_INSPECTOR_*` vs `TOOL_INSPECTOR_*` vs scoped to a single
  vendor key. We'd prefer the generic name so other security vendors can use
  the same surface.
- Should the webhook also see `PostToolUse` events for audit-only logging,
  or is pre-execution enough? (Our preference: pre-only, keep the surface
  minimal; audit lives elsewhere.)
- Should responses be allowed to mutate the tool input (`overrideInput`),
  as Cline and Continue hooks do? Probably no for v1 — keeps the threat
  model simple.

---

**Status:** draft. We (GoPlus) intend to file an issue first to gauge
maintainer interest before opening a PR. Anyone in this repo can take it on.
