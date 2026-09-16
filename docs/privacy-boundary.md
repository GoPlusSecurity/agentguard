# OSS / Cloud Privacy Boundary

AgentGuard OSS protects your machine without requiring a Cloud account.

## Stays local by default

- Full prompts
- Full file contents
- Full command output
- Full secrets and private keys
- Local audit file at `~/.agentguard/audit.jsonl`
- Cached policy at `~/.agentguard/policy-cache.json`

LLM request and response content is evaluated only in local process memory. The
persisted and Cloud-facing form replaces that content with
`[LOCAL_ONLY_LLM_CONTENT]`; it retains only bounded lifecycle and coverage
facts.

## Sent to Cloud when connected

Only redacted runtime audit previews are uploaded by default:

- `sessionId`, `agentHost`, `actionType`, `toolName`
- Redacted `input` preview, capped at 2,000 characters
- Decision, risk score, risk level, reasons, and policy version
- Lifecycle stage, coverage level, enforcement status, missing-fact names, and
  request correlation IDs
- Provider/model and normalized endpoint classification only when the host
  actually exposes them
- Credential kind and presence only (`api_key`, `oauth`, `aws`, `ambient`,
  `none`, or `unknown`); never a credential value, Authorization header, or
  reversible digest
- PII category/count summaries and masked evidence; never raw matches

`payloadBytes`, when present, means the exact UTF-8 byte length of the
serialized request body. Character counts and previews are not substitutes;
adapters leave the field absent and report `exact_payload_bytes` as missing
when the host does not expose the serialized body.

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

Local policies are normalized when loaded, so caches written before the LLM
privacy fields existed inherit the bundled privacy defaults. Cloud availability
is not part of the local decision path.

## Approval and failure semantics

- An AgentGuard-controlled blocking gate treats an expired approval as absent.
- `require_approval` is denied when the host has no interactive approval
  protocol, the session is non-interactive, or an approval cannot be shown.
- JSON parsing and evaluator failures caught by a blocking wrapper deny the
  current action. Observer-only lifecycle failures record
  `SECURITY_GATE_ERROR` without claiming enforcement.
- A host may terminate or time out a hook before AgentGuard returns. When that
  host itself continues the action, the adapter reports a host fail-open
  capability gap; AgentGuard does not label the action as blocked.

## Coverage semantics

`canBlockCurrentAction` describes the current lifecycle event, independently of
the policy's desired decision. A blocking event records `enforced` when the
decision is applied. An observer that detects a block-class policy result
records `would_block`; it must not report that the model request was stopped.
Unavailable transport facts remain absent and are listed in `missingFacts`, so
missing visibility never becomes an implicit `allow`.
