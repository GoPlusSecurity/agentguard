# Connect AgentGuard OSS to AgentGuard Cloud

AgentGuard is local-first. Cloud is optional and adds hosted policy, redacted audit sync, and session timelines.

## Install and initialize

```bash
npm install -g @goplus/agentguard
agentguard init
```

This creates `~/.agentguard/config.json`, `~/.agentguard/audit.jsonl`, and local cache paths.

## Connect Cloud

OpenClaw users can connect without an API key after initialization:

```bash
agentguard init --agent openclaw
agentguard connect
```

In this mode, `connect` registers a local Agent JWT, prints an activation link,
and may send that link to the latest OpenClaw channel. Open the link to bind the
local agent to your AgentGuard account.

API-key auth is also supported:

```bash
AGENTGUARD_API_KEY=ag_live_xxxxx \
  agentguard connect --url https://agentguard.gopluslabs.io
```

With API-key auth, `connect` stores the API key locally, fetches `/api/v1/policies/effective`, and caches the policy. With Agent JWT auth, `connect` stores the local agent credential instead of an API key. If Cloud is unavailable, AgentGuard keeps enforcing with cached policy or the bundled default policy.

Prefer `AGENTGUARD_API_KEY` or an ignored `.env.local` file over passing secrets as CLI flags, because shell history can persist command-line arguments.

## Runtime flow

1. Agent host sends tool metadata to `agentguard protect`.
2. AgentGuard evaluates locally by default.
3. Local audit is written to `~/.agentguard/audit.jsonl`.
4. Connected clients sync redacted audit events to `/api/v1/events/ingest`.
5. `require_approval` is handled by the agent host's native permission channel when one is available. If the host cannot safely resume an approved call, AgentGuard blocks locally and asks the user to retry only after intentionally changing local policy.

Use `AGENTGUARD_DECISION_MODE=cloud` or `agentguard protect --decision-mode cloud` only when Cloud should be authoritative for a specific hook.

## Commands

```bash
agentguard status
agentguard doctor
agentguard scan ./skills/example
agentguard protect --agent claude-code --action-type shell --tool-name Bash
```

For the full native API contract, see [AgentGuard Cloud Native API](cloud-native-api.md).

## Live Cloud smoke test

The normal test suite uses mocks and never touches Cloud. To verify a real test environment, build first and pass credentials through your shell:

```bash
npm run build
AGENTGUARD_CLOUD_URL=https://your-agentguard-cloud.example.com \
AGENTGUARD_API_KEY=ag_live_xxxxx \
  npm run test:cloud-live
```

You may also keep local-only credentials in an ignored `.env.local` file:

```bash
AGENTGUARD_CLOUD_URL=https://your-agentguard-cloud.example.com
AGENTGUARD_API_KEY=ag_live_xxxxx
```

Then run:

```bash
set -a
. ./.env.local
set +a
npm run test:cloud-live
```

Do not commit `.env.local`, `.env`, `~/.agentguard/config.json`, or any real API key.
