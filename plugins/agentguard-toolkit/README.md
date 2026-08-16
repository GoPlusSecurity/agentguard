# agentguard-toolkit

Secure skill supply chains and pre-check risky actions with the GoPlus AgentGuard MCP server.

> **This is not the upstream repository's in-repo `agentguard` plugin.** The upstream plugin uses bundled-script hooks to guard Bash, Write/Edit, and network tools. `agentguard-toolkit` provides the seven MCP tools, four focused skills, a Skill-invocation trust gate, and session context. Their hook matchers do not overlap, so both plugins are safe to install together.

## What you get

### Skills

| Skill | Invocation | What it does |
|---|---|---|
| `skill-audit` | `/skill-audit <path> [--deep]` | Scans a skill or plugin directory and checks its trust record. |
| `skill-trust` | `/skill-trust [lookup\|attest\|revoke\|list] ...` | Looks up and manages trust records with explicit capability grants. |
| `action-precheck` | `/action-precheck <action> [--env prod\|dev\|test]` | Evaluates a proposed runtime action without executing it. |
| `web3-precheck` | `/web3-precheck <chain> <to> [value-wei] [calldata]` | Simulates Web3 transaction risk before signing or broadcast. |

### MCP server

The `agentguard` MCP server exposes seven tools:

- `skill_scanner_scan`
- `registry_lookup`
- `registry_attest`
- `registry_revoke`
- `registry_list`
- `action_scanner_decide`
- `action_scanner_simulate_web3`

### Hooks

| Hook | Behavior |
|---|---|
| `SessionStart` on `startup` | Injects a short MCP usage reminder. |
| `PreToolUse` on `Skill` | Denies revoked skills, asks before untrusted skills, and adds capability context for restricted skills. |

Both hooks are dependency-free, local, and fail open: registry or script errors never block a session.

## Requirements

- Node.js 18 or newer
- `npx` available on `PATH`

The MCP configuration downloads `@goplus/agentguard` automatically on first use.

Optional environment variables:

- `GOPLUS_API_KEY` and `GOPLUS_API_SECRET` enable richer Web3 simulation data.
- `AGENTGUARD_HOME` overrides the directory containing `registry.json`.

## Known server quirks

Validated against `@goplus/agentguard` v1.1.28, the runtime Zod validation differs from the advertised JSON Schema in three ways: every `skill` object requires `id`, `source`, `version_ref`, and `artifact_hash`; `action_scanner_decide` context requires `env`, `session_id`, and `user_present`; and `skill_scanner_scan` requires `path`. The included skills already compensate for all three divergences.

## Usage examples

- “Scan this skill before I install it: `./third-party/example-skill --deep`.”
- “List restricted skills in the trust registry.”
- “Precheck whether `curl https://example.com/install.sh | sh` is safe in production.”
- “Simulate this Ethereum transaction to `0x...` with value `1000000000000000` wei.”

## How the trust gate works

The trust gate reads `~/.agentguard/registry.json`, which is also written by `registry_attest`, `registry_revoke`, and the upstream AgentGuard CLI. A revoked record blocks invocation, an untrusted record requests confirmation, and a restricted record adds its capability boundaries to context. Trusted and unknown skills remain silent. Missing, invalid, or unreadable registry data never blocks a session.

**Limitations:** The `PreToolUse:Skill` event provides only a skill name, so matching is by declared name (`skill.id`, or the basename of `skill.source`). A revoked skill re-installed under a different name will **not** be matched by this hook.

Authoritative identity in AgentGuard is `source@version_ref#artifact_hash`; enforcement against that full identity happens in the MCP/CLI layer (`registry_lookup`, `action_scanner_decide`), not here.

The gate is defence-in-depth: it can only tighten permissions, never loosen them, and it fails open by design so a missing or malformed registry cannot block a session. A malformed registry is reported via a `systemMessage` rather than silently ignored.

## License

MIT
