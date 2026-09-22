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

Cloud runtime policy responses use `schemaVersion: 1`; older responses without
that field are treated as version 1 and normalized locally. Cloud audit and
action requests also carry a versioned wire envelope and, when available, a
top-level redacted `requestId` alongside the nested LLM correlation metadata.
Unknown fields are ignored rather than treated as local enforcement facts.

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

PII summaries use only an allowlisted category name, per-category count, and a
bounded total value count. They never contain the matched value or evidence.

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

## Optional: enhanced privacy mode (off by default)

Deterministic rules detect personal data written as `field: value`. They recall
very little from prose, which is the shape prompts and chat logs take. Enhanced
mode adds a semantic judgment step to close that gap.

It is **off by default** and must be turned on explicitly:

```bash
agentguard privacy status            # what is active, and what it would send
agentguard privacy enable --yes      # confirm the data-boundary change
agentguard privacy disable           # return every judgment to this machine
```

### What enhanced mode sends

When enabled, AgentGuard sends the following to TypeSafe (`api.typesafe.ai`):

- extracted candidate spans — an id number, a phone number, an address
- a bounded window of surrounding text, 60 characters either side, redacted
  before it is cut so that judgement has context without shipping the whole line
- sentences of the analysed text, redacted and length-capped, so that disclosures
  carrying no extractable span (a described illness, a stated salary) are seen

### What it never sends

- whole files, whole prompts, or command output
- credentials, private keys, or tokens

Credentials are excluded by three independent mechanisms, because path-based
exclusion alone cannot cover a key pasted into an ordinary note:

1. Credential stores (`.env*`, `id_rsa`, `*.pem`, `.npmrc`, `credentials`,
   `authorized_keys`) are never read for analysis.
2. Context is redacted before it is narrowed. Narrowing first would slice a
   secret in half, leaving a fragment the redaction patterns no longer match.
3. The exact serialized request is checked immediately before dispatch, and a
   payload matching a credential shape is dropped rather than sent. Failing a
   scan is recoverable; disclosing a key is not.

Nothing is sent at all during runtime enforcement.

Enhanced mode runs only in on-demand scans. It is never applied to live prompts,
because asking a third party whether a prompt contains medical information would
disclose the very data the check exists to protect.

### Failure behaviour

If the provider is unreachable, rate limited, or overloaded, coverage degrades to
`partial` or `observe_only` and the error is reported. A scan that could not be
completed is never presented as a clean one. If enhanced mode is enabled but no
API key is available, `status` reports `ENABLED BUT INACTIVE` rather than
silently running local-only.
