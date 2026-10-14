# OSS / Cloud Privacy Boundary

AgentGuard OSS protects your machine without requiring a Cloud account.

## Stays local by default

- Full prompts
- Full file contents
- Full command output
- Full secrets and private keys
- Local audit file at `~/.agentguard/audit.jsonl`
- Cached policy at `~/.agentguard/policy-cache.json`

LLM request and response content is evaluated only in local process memory.
Redacted request and response observations may be written to the local audit
file, but routine model-request records and all model-response records are not
uploaded to Cloud.

## Public web-search results

Bare card- or national-ID-shaped digits in a **verified, host-owned web-search
result** are treated as ambiguous public result metadata, not proof of user
data egress. Successful results remain local and are not uploaded to Cloud.
Search queries, user prompts, workspace files, web-fetch responses, unknown
tool names, and unrecognized result shapes retain the strict privacy rules.
Explicitly labeled personal data and credentials in search results remain
protected. Only an exact ambiguous numeric metadata *leaf* (`price`, `rank`,
`id`, etc.) in a verified search result is exempt; unrelated nested objects
and arrays are checked strictly. A numeric field name does not exempt a
number anywhere else in the application.

| Host | Verified result boundary | Limitation |
|---|---|---|
| Claude Code | Native `WebSearch` post-tool and post-tool batch | Only known rewriteable result shapes receive the numeric exception. |
| Codex | `PostToolUse` when the hook exposes an exact `web_search`/`WebSearch` result | Hosted searches that bypass native hooks cannot be observed. |
| OpenClaw / QClaw | Native `after_tool_call` result of `web_search` | Results cannot be rewritten; this is an observer boundary. |
| Hermes | `post_tool_call` result of `web_search` with a host-provided `result` and `status: ok` | Aliases such as `output` and `tool_result`, malformed/failed results, and older hooks that provide only arguments cannot establish result provenance. `pre_api_request` is observe-only. |
| DSH | Native `web_search`/`search_query` post-execute result | Result suppression requires `postResponseMode: block-malicious`; ordinary audit mode does not block. |

For supported model-request evaluations, only an exact previously observed
public-search result in the same agent session can suppress bare-number
heuristics in a tool-result message. This matching stores bounded SHA-256
digests in memory for ten minutes, never the raw result; it does not alter
the model request or suppress user messages. If provenance is unavailable or
the process restarts, evaluation stays strict.

Cloud runtime policy responses use `schemaVersion: 1`; older responses without
that field are treated as version 1 and normalized locally. Cloud audit and
action requests also carry a versioned wire envelope and, when available, a
top-level redacted `requestId` alongside the nested LLM correlation metadata.
Unknown fields are ignored rather than treated as local enforcement facts.

## Sent to Cloud when connected

Only redacted, Cloud-eligible runtime audit previews are uploaded by default:

- Clean events (`allow`, zero risk, `safe`, no findings, and no execution
  failure) remain in the local audit and are not uploaded, regardless of host.

- `sessionId`, `agentHost`, `actionType`, `toolName`
- Redacted `input` preview, capped at 2,000 characters
- Native shell hooks may retain a redacted command preview so operational
  context remains visible; recognized credential and PII values are masked.
  Protected-file access uses only a bounded, validated target summary such as
  `cat .env` or `cat .ssh/id_ed25519.pub`; absolute paths, additional
  arguments, redirects, substitutions, and command tails are omitted.
- Native web-fetch Pre events retain only a bounded `http`/`https` destination.
  URL credentials, fragments, query values, sensitive path segments, and
  opaque token-like path segments are removed; safe query names may remain.
- Native file reads and writes retain only a validated basename or bounded file
  count. Absolute paths, file contents, edit bodies, and patch bodies stay
  local. Configuration changes use the same boundary.
- Native model-switch events retain only validated model labels, a bounded
  source label, and the non-negative context-token count. Endpoint-like or
  credential-like labels are replaced with `unknown`.
- Native policy reasons use static titles selected by allowlisted rule ID;
  descriptions, evidence, and remediation text remain redacted.
- Native `PreToolUse` events are the primary Cloud action records. Routine
  successful `PostToolUse` observations stay in the local audit. A post-tool
  event is uploaded separately only when it adds a failure, elevated risk,
  anomalous result, PII summary, or another material security finding. A
  material Claude Code `PostToolBatch` event remains reportable when it blocks
  model continuation, using only a static finding summary and aggregate counts.
- Reportable native events use the original tool action for their safe summary,
  including post-tool shell commands and file basenames. If no raw value can be
  retained safely, the preview falls back to a bounded tool name plus static
  finding title rather than an opaque placeholder.
- Reportable DSH events use the same local-first boundary through a Cloud-only
  projection: command names, file basenames, sanitized network destinations,
  static finding titles, and bounded status fields may be sent; raw tool output,
  request/response previews, headers, absolute paths, and evaluator reason text
  remain local.
- Raw stdout and stderr are never uploaded from either lifecycle stage.
  Reportable post-tool events contain only the safe original-action summary,
  redacted risk summary, and bounded status metadata.
- Decision, risk score, risk level, reasons, and policy version
- Lifecycle stage, coverage level, enforcement status, missing-fact names, and
  request correlation IDs
- Provider/model and normalized endpoint classification only when the host
  actually exposes them
- Credential kind and presence only (`api_key`, `oauth`, `aws`, `ambient`,
  `none`, or `unknown`); never a credential value, Authorization header, or
  reversible digest
- For model traffic, only a confirmed PII-bearing request that was not stopped
  before egress; routine requests and every response stay local
- PII category/count summaries and masked evidence; never raw matches

PII summaries use only an allowlisted category name, per-category count, and a
bounded total value count. They never contain the matched value or evidence.

When a locally visible model payload contains a credential or personal-data
value, the existing audit `reasons` fields carry a human-readable exposure
summary and the actual enforcement outcome. Evidence uses fixed masks such as
`sk-****` and `***@***`; it never contains characters copied from the matched
value. Observer-only hooks explicitly say that the model call was not blocked.
This does not add fields or change the version-1 Cloud wire envelope.

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

If Cloud is unreachable, AgentGuard continues local enforcement and spools
Cloud-eligible redacted audit events for later retry. Clean tool events,
routine post-tool observations, routine model requests, and model responses
are filtered again at the Cloud client boundary, including when an older spool
is drained. It must never fail open for local `block` decisions.

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
