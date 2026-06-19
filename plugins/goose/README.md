# GoPlus AgentGuard — Goose integration (advisory, MCP-based)

Goose ([block/goose](https://github.com/block/goose)) is **not** integrated
the same way as Cline, Hermes, or Continue. This README explains the
limitation honestly and documents the install paths that ship today.

## TL;DR

```bash
npm i -g @goplus/agentguard
agentguard init --agent goose
```

That writes `agentguard` as an MCP extension in `~/.config/goose/config.yaml`:

```yaml
extensions:
  agentguard:
    type: stdio
    command: agentguard-mcp
    args: []
    timeout: 300
    enabled: true
    description: GoPlus AgentGuard MCP — security scanner + action evaluator
```

Restart Goose. AgentGuard's scanner and action evaluator are now MCP-callable.

## Important: this is advisory, not a hard gate

Goose currently has **no out-of-process plugin API** for intercepting tool
calls. The only true `Allow / Deny / RequireApproval` surface is the in-process
Rust `ToolInspector` trait (`crates/goose/src/tool_inspection.rs`), which is
compile-time — there is no dynamic loader for it.

What an MCP extension can do:

- **Provide tools the model may choose to call** (`scan_skill`, `evaluate_action`, etc.)
- **Refuse to return data** when called

What an MCP extension **cannot** do:

- Sit on the execution path of every Goose tool call
- Block a `developer__shell` call the model never routed through AgentGuard

In other words, if the agent decides to call `shell` with `rm -rf /` and
never asks AgentGuard's MCP tools first, AgentGuard never gets a chance to
veto it. The model is free to skip you. **Treat this as defense-in-depth,
not a security boundary.**

For a real hard gate, see [UPSTREAM_PROPOSAL.md](./UPSTREAM_PROPOSAL.md) — a
draft proposal to add a `SECURITY_INSPECTOR_ENDPOINT` webhook to Goose,
mirroring its existing `SECURITY_PROMPT_CLASSIFIER_ENDPOINT`. That would
turn AgentGuard into a genuine pre-execution inspector with `block` /
`require_approval` returns.

## What the MCP integration is useful for

- **Pre-commit / pre-PR scanning** of skills the agent wants to install
- **Action evaluation** when the agent explicitly asks "is this dangerous?"
- **Audit logging** of evaluations the model did make through AgentGuard

These are real value-adds even without a hard gate, but be clear with users
about the boundary.

## Manual install

If you'd rather not run `agentguard init --agent goose`, copy the snippet
above into your existing `~/.config/goose/config.yaml` under `extensions:`
(or create the file if it doesn't exist). On Windows the path is
`%APPDATA%\Block\goose\config\config.yaml`.

The installer preserves any prior `extensions:` entries and is idempotent —
re-running won't duplicate the block.

## Reference

- Goose extensions / MCP: https://block.github.io/goose/docs/getting-started/installation
- ToolInspector trait (compile-time): `crates/goose/src/tool_inspection.rs`
- Existing classifier endpoint (the model we're proposing to copy):
  `crates/goose/src/security/classification_client.rs` +
  `SECURITY_PROMPT_CLASSIFIER_ENDPOINT`
