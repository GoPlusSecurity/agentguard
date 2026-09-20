# Task 10 — AgentGuard Cloud implementation requirements

This document is the handoff for the AgentGuard Cloud service and Dashboard.
The local client work is implemented in AgentGuard OSS; the items below still
require Cloud-side changes. Cloud must not become a prerequisite for local
blocking behavior.

## 1. Policy API

`GET /api/v1/policies/effective` must return the existing runtime policy plus:

```json
{
  "schemaVersion": 1,
  "policyVersion": "runtime-v0.1",
  "network": {
    "untrustedLlmEndpoint": "require_approval",
    "trustedLlmEndpoints": ["https://gateway.example.com/v1"]
  },
  "privacy": {
    "piiEgressTrusted": "warn",
    "piiEgressUntrusted": "require_approval",
    "enabledCategories": ["email_address", "phone_number"],
    "bulkEgressBytes": 1048576,
    "bulkAttachmentBytes": 5242880,
    "bulkFilePathCount": 20
  }
}
```

Requirements:

- `schemaVersion` is currently `1`. A missing field means version 1 for old
  clients. New fields must be additive; clients must continue to consume old
  policy responses.
- Decisions are only `allow`, `warn`, `require_approval`, or `block`.
- `enabledCategories` must be restricted to the documented PII category enum.
- Thresholds must be non-negative safe integers and have server-side maximums.
- Normalize trusted endpoints to canonical scheme/host/port/path forms. Reject
  invalid entries and never let a trusted endpoint override a global blocked
  domain or a literal-IP/high-risk endpoint classification.
- Return `policyVersion` and `updatedAt` on every successful response.
- Do not include prompt, tool output, credential values, or complete payloads in
  policy responses.

## 2. Action evaluation API

`POST /api/v1/actions/evaluate` accepts the local wire envelope:

- `schemaVersion`
- optional top-level `requestId`
- `sessionId`, `agentHost`, `actionType`, `toolName`
- redacted `input` or `[LOCAL_ONLY_LLM_CONTENT]`
- `lifecycleStage`, `canBlockCurrentAction`, `coverageLevel`,
  `enforcementStatus`, `missingFacts`
- redacted `llm` metadata and bounded metadata

The server may return a stronger decision than the local default, but the
client must enforce a returned `block` locally and must not downgrade a local
block because Cloud is unavailable.

## 3. Audit ingest API

`POST /api/v1/events/ingest` accepts at most 100 events per batch. Each event
may contain the following bounded facts:

| Field | Requirement |
| --- | --- |
| `schemaVersion` | Required for new clients; accept missing as v1 during migration |
| `requestId` / `llm.requestId` | Correlation identifier only; validate length and character set |
| `agentHost`, `actionType`, `lifecycleStage` | Enum-validated |
| `coverageLevel`, `enforcementStatus` | Preserve the distinction between enforced, observed, display-only, and unsupported |
| `canBlockCurrentAction` | Boolean; never infer from policy decision |
| `missingFacts` | Enum-validated, deduplicated, bounded |
| endpoint/provider/model/purpose | Accept only facts supplied by the host; no defaults for unknown values |
| payload/attachment/file counts | Non-negative bounded integers |
| PII rule summaries | Rule ID, detected flag, decision, coverage, and counts only; category names and counts are allowlisted |
| reason/decision/risk | Enum and length limits; no raw evidence required for Dashboard |

The server must reject or scrub before persistence, queues, analytics, and
responses:

- prompts, full tool output, transcript, model response, file contents;
- `Authorization`, API keys, bearer tokens, private keys, cookies and URL
  credentials;
- unmasked email/phone/national ID/health/location/contact data;
- arbitrary user-controlled metadata that is not in the allowlist.

Server-side redaction is defense in depth, not a replacement for the local
client's first-line redaction. Rejected events should return a bounded reason
code and request ID, never the rejected raw value.

## 4. Dashboard and query behavior

The session timeline and Dashboard must support filtering by:

- `agentHost`, `lifecycleStage`, `coverageLevel`, `enforcementStatus`;
- endpoint tier, provider, model, purpose;
- privacy rule/reason code, decision, policy version, and time range.

Display requirements:

- clearly distinguish `enforced`, `would_block`, `observed`, `display_only`, and
  `unsupported`;
- show `missingFacts` and host fail-open/observer limitations;
- show retry/fallback relationships only when the host supplied a verified
  correlation, never from inferred session ordering;
- do not show raw prompt, response, tool output, credentials, or complete PII;
- aggregate PII trends by category/count and apply tenant-level minimum counts
  or suppression to avoid reconstructing an individual's data.

## 5. Compatibility and failure tests

Cloud CI should include fixtures for:

1. legacy policy without privacy fields;
2. v1 policy with trusted and blocked endpoint overlap;
3. action and audit payloads containing redaction sentinels but no raw secrets;
4. malformed enum, oversized string, negative count, and unknown-field cases;
5. duplicate/replayed `requestId` events;
6. Cloud timeout/5xx and offline client behavior;
7. Dashboard rendering for full, partial, observe-only, display-only, and
   unsupported coverage.

Acceptance is met only when the local client continues enforcing known local
blocks with Cloud disconnected, and Cloud persistence/analytics contain no
raw prompt, response, key, credential, or complete PII.
