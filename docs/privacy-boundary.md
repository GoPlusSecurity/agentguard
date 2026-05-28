# OSS / Cloud Privacy Boundary

AgentGuard OSS protects your machine without requiring a Cloud account.

## Stays local by default

- Full prompts
- Full file contents
- Full command output
- Full secrets and private keys
- Local audit file at `~/.agentguard/audit.jsonl`
- Cached policy at `~/.agentguard/policy-cache.json`

## Sent to Cloud when connected

Only redacted runtime audit previews are uploaded by default:

- `sessionId`, `agentHost`, `actionType`, `toolName`
- Redacted `input` preview, capped at 2,000 characters
- Decision, risk score, risk level, reasons, and policy version

## Built-in redaction

AgentGuard redacts common sensitive values before Cloud sync:

- AgentGuard/OpenAI-style API keys
- `Bearer` tokens
- `token=`, `api_key=`, `secret=`, `password=`, and similar query/env values
- Private key PEM blocks
- URL credentials and sensitive query parameters

Cloud endpoints also apply server-side redaction, but clients should not rely on server redaction as the first line of defense.

## Offline behavior

If Cloud is unreachable, AgentGuard continues local enforcement and spools redacted audit events for later retry. It must never fail open for local `block` decisions.
