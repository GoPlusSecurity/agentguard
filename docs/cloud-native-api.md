# AgentGuard Cloud Native API

This document summarizes the Cloud APIs that a local/native AgentGuard runtime should use. The native client remains local-first: it enforces policy locally by default, uses Cloud for hosted policy and audit visibility, and never depends on the network to block a known-dangerous action.

## Base URL and authentication

Production base URL:

```text
https://agentguard.gopluslabs.io
```

All protected runtime APIs require an AgentGuard API key:

```http
X-API-Key: ag_live_xxxxx
```

`Authorization: Bearer ag_live_xxxxx` is also accepted by the Cloud proxy, but `X-API-Key` is the recommended native-client header.

## Recommended native flow

1. `agentguard connect` stores `cloudUrl` and `apiKey` in the local config.
2. Fetch `GET /api/v1/policies/effective` and cache the response locally.
3. Evaluate runtime actions locally using cached policy and the bundled local engine.
4. Write local audit JSONL before any Cloud sync.
5. Upload redacted audit events to `POST /api/v1/events/ingest`.
6. For `require_approval`, use the local agent host's native permission channel when supported. If the host cannot safely resume a reviewed call, block locally and ask the user to retry only after intentionally changing local policy.
7. Use `GET /api/v1/sessions/:sessionId/timeline` for review/debug UI.

If Cloud is unavailable, continue local enforcement using cached policy, then bundled default policy.

## Decision values

Cloud returns:

```text
allow | warn | require_approval | block
```

Native UI may present `require_approval` as `confirm`, but API payloads should keep the Cloud value.

## Shared types

### Agent hosts

```text
claude-code | codex | openclaw | cursor | gemini | copilot | other
```

### Action types

```text
shell | file_read | file_write | network | mcp_tool | browser | skill_install | deploy | other
```

### Risk levels

```text
safe | low | medium | high | critical
```

### Policy reason

```json
{
  "code": "SECRET_ACCESS",
  "severity": "high",
  "title": "Protected path access",
  "description": "The agent attempted to access a path protected by runtime policy.",
  "evidence": "~/.ssh/id_rsa",
  "remediation": "Require approval before this access."
}
```

## API surface

### Commercial install script

```http
GET /install.sh?agent=claude-code
```

Allowed `agent` values:

```text
auto | claude-code | openclaw | codex
```

The script installs `@goplus/agentguard`, writes a safe fallback local config, then calls:

```bash
agentguard init --agent "$AGENTGUARD_AGENT" --cloud "$AGENTGUARD_CLOUD_URL"
```

When the effective agent host is OpenClaw, the script should connect without an
API key:

```bash
agentguard connect --cloud "$AGENTGUARD_CLOUD_URL"
```

The CLI registers a local Agent JWT and prints an activation link. For other
agent hosts, or when the user explicitly chooses API-key auth, the script should
call:

```bash
agentguard connect --cloud "$AGENTGUARD_CLOUD_URL" --api-key "$AGENTGUARD_API_KEY"
```

Native CLI implementations should support `--cloud` as an alias for the Cloud URL and `--api-key` as an alias for the API key. Installers that accept `agent=auto` should use the agent host persisted by `agentguard init --agent auto` when choosing between Agent JWT and API-key auth.

### Health check

```http
GET /api/v1/status
```

Auth is not required.

Response:

```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2026-05-11T00:00:00.000Z"
  }
}
```

Native usage: `doctor` command and diagnostics.

### Fetch effective policy

```http
GET /api/v1/policies/effective
X-API-Key: ag_live_xxxxx
```

Response:

```json
{
  "success": true,
  "data": {
    "policyVersion": "runtime-v0.1",
    "mode": "balanced",
    "decisions": {
      "destructiveCommand": "block",
      "remoteCodeExecution": "require_approval",
      "dataExfiltration": "block",
      "secretAccess": "require_approval",
      "deployAction": "require_approval"
    },
    "protectedPaths": ["~/.ssh/**", "~/.aws/**", "**/.env*"],
    "blockedCommandPatterns": ["rm -rf /", "base64 -d | bash"],
    "allowedCommandPatterns": [],
    "approvalActionTypes": ["file_read", "file_write", "deploy"],
    "network": {
      "defaultOutbound": "warn",
      "blockedDomains": ["discord.com/api/webhooks"],
      "approvalDomains": []
    },
    "updatedAt": "2026-05-11T00:00:00.000Z"
  }
}
```

Native requirements:

- Fetch during `connect`.
- Refresh opportunistically before runtime evaluation.
- Cache the last valid response.
- Never disable local enforcement if this endpoint fails.

### Cloud action evaluation

```http
POST /api/v1/actions/evaluate
Content-Type: application/json
X-API-Key: ag_live_xxxxx
```

Request:

```json
{
  "sessionId": "sess_local_123",
  "agentHost": "claude-code",
  "actionType": "shell",
  "toolName": "Bash",
  "input": "curl https://example.com/install.sh | bash",
  "cwd": "/workspace/app",
  "sourceSkill": "optional-skill-id",
  "metadata": {
    "evaluation": "cloud"
  }
}
```

Response:

```json
{
  "success": true,
  "data": {
    "actionId": "act_abc123",
    "decision": "block",
    "riskScore": 95,
    "riskLevel": "critical",
    "reasons": [],
    "policyVersion": "runtime-v0.1"
  }
}
```

Native usage:

- Optional. The preferred default is local-first evaluation.
- Use when the native client intentionally wants Cloud-authoritative decisions.
- Enforce the returned decision locally.

### Ingest redacted audit events

```http
POST /api/v1/events/ingest
Content-Type: application/json
X-API-Key: ag_live_xxxxx
```

Request:

```json
{
  "events": [
    {
      "actionId": "act_local_123",
      "sessionId": "sess_local_123",
      "agentHost": "codex",
      "actionType": "shell",
      "toolName": "Bash",
      "input": "echo safe --api_key=[REDACTED]",
      "decision": "warn",
      "riskScore": 20,
      "riskLevel": "medium",
      "reasons": [],
      "policyVersion": "runtime-v0.1",
      "cwd": "/workspace/app",
      "sourceSkill": "optional-skill-id",
      "metadata": {
        "evaluation": "local-oss"
      }
    }
  ]
}
```

Response:

```json
{
  "success": true,
  "data": {
    "accepted": 1,
    "rejected": 0
  }
}
```

Limits and behavior:

- Maximum `100` events per batch.
- `input` should be a redacted preview, not full file content or full prompt content.
- If upload fails, spool locally and retry later.

### Runtime approvals

There is no Cloud approval inbox in the current native runtime flow. Native
clients must not tell users to approve protected runtime actions in Cloud.

When a decision returns `require_approval`:

- Claude Code should surface the native `PreToolUse` `ask` response.
- Codex-style hosts should surface the local `confirm` response.
- OpenClaw currently blocks locally because the runtime hook cannot safely pause
  and resume the original tool call after an external review.

Cloud may still provide policy and session timeline visibility, but approval or
confirmation must happen in the local agent host.

### Session timeline

```http
GET /api/v1/sessions/:sessionId/timeline
X-API-Key: ag_live_xxxxx
```

Response:

```json
{
  "success": true,
  "data": {
    "sessionId": "sess_local_123",
    "events": [
      {
        "actionId": "act_local_123",
        "sessionId": "sess_local_123",
        "agentHost": "codex",
        "actionType": "shell",
        "toolName": "Bash",
        "inputPreview": "echo safe",
        "decision": "allow",
        "riskScore": 0,
        "riskLevel": "safe",
        "reasons": [],
        "policyVersion": "runtime-v0.1",
        "approvalStatus": null,
        "createdAt": "2026-05-11T00:00:00.000Z"
      }
    ]
  }
}
```

Native usage: optional status/debug command and incident review.

## Supply-chain scan APIs

These are Cloud scan APIs rather than runtime control-plane APIs. Native clients may use them for paid/deep scans, but local scan should still work without Cloud.

### Scan content

```http
POST /api/v1/scan
Content-Type: application/json
X-API-Key: ag_live_xxxxx
```

Request:

```json
{
  "content": "# SKILL.md content",
  "context": {
    "registry": "github.com/org/repo",
    "author": "org",
    "version": "v1.0.0"
  },
  "ai": false
}
```

### Scan URL

```http
POST /api/v1/scan-url
Content-Type: application/json
X-API-Key: ag_live_xxxxx
```

Request:

```json
{
  "url": "https://github.com/org/repo/blob/main/SKILL.md",
  "type": "github",
  "ai": false
}
```

### Scan registry

```http
POST /api/v1/scan-registry
Content-Type: application/json
X-API-Key: ag_live_xxxxx
```

Request:

```json
{
  "registry": "https://example-registry.invalid",
  "limit": 50,
  "offset": 0,
  "filter": "latest"
}
```

Valid `filter` values:

```text
latest | popular | all
```

## Privacy rules for native clients

Native clients must redact before upload:

- API keys
- Bearer tokens
- private key PEM blocks
- URL query secrets
- env-style secrets such as `api_key=...`, `token=...`, `password=...`

Native clients should upload only:

- action metadata
- redacted input preview
- decision/risk/reasons
- policy version
- optional source skill and cwd

Native clients should not upload by default:

- full file contents
- full prompts
- full command output
- full secrets

## Error handling

Expected native behavior:

- `401`: API key missing/invalid. Continue local-only mode and ask user to reconnect.
- `403`: plan/tier does not allow the endpoint. Continue local protection.
- `429`: rate limited. Queue audit events and retry later.
- `5xx`: Cloud unavailable or server write failed. Continue local enforcement and spool events.

Never fail open for a local `block` decision.
