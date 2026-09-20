# AgentGuard LLM Egress Privacy Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modify only AgentGuard to implement personal privacy rules 1–19 and provide the strongest protection possible through the public lifecycle interfaces of OpenClaw, deepseek-harness (DSH), Hermes, Codex, and Claude Code. Model-traffic facts that a host does not expose must be explicitly marked `unknown`, `observe_only`, or `unsupported`; the product must not claim that it fully intercepts real model API traffic.

**Architecture:** AgentGuard provides shared endpoint classification, PII detection, runtime decisions, redacted audit, approval protocol, and a host capability model. Each adapter consumes only the lifecycle events publicly exposed by its Agent and normalizes the facts actually visible there. AgentGuard does not modify or patch host source code. Complete prompts and responses participate in decisions only in local memory. AgentGuard Cloud distributes policy and receives only redacted metadata and coverage status.

**Tech Stack:** TypeScript/Node.js (AgentGuard), Python (AgentGuard Hermes plugin), native Codex `hooks.json`, native Claude Code settings hooks, existing host plugin/Hook lifecycles, and the AgentGuard Cloud policy/audit API.

**Spec:** The original requirements are in `/Users/jeff/Downloads/AgentGuard 个人隐私保护规则集.md`. Existing integration documentation: [OpenClaw](./openclaw.md), [DSH](./dsh.md), [Hermes](./hermes.md), [Claude Code](./claude-code.md), and [Privacy Boundary](./privacy-boundary.md).

## Global Constraints

- Local rules must remain available without Cloud. Cloud must never be an availability dependency for a local `block`.
- Changes are limited to the AgentGuard repository and the plugins, Hooks, and configuration that AgentGuard installs into a target project or user directory. Do not modify, patch, fork, or require releases of OpenClaw, DSH, Hermes, Codex, or Claude Code source.
- Do not depend on host lifecycles that do not exist. Adapters must support currently public interfaces and explicitly degrade when capabilities are missing.
- Raw prompts, file contents, model responses, Authorization headers, and API keys must never be uploaded to Cloud.
- API keys may produce only facts such as `credentialKind` and `credentialPresent`. Key values must never enter hook payloads, logs, or approval copy.
- When a host exposes per-request events, every retry, fallback, provider switch, and endpoint switch must be checked again. When it does not, report `unsupported` rather than claiming a recheck occurred.
- Strong blocking for T3/T4 endpoints is valid only when the host exposes the final endpoint before sending. Run-level or tool-level events can provide only preventive configuration protection and audit.
- Rule evidence must be redacted before it is written to `~/.agentguard/audit.jsonl`. Cloud synchronization may process only already-redacted events.
- AgentGuard-controlled `require_approval` paths, parse errors, and evaluator errors should deny by default. If the host continues after a Hook timeout or crash, record and warn about that fail-open capability gap; do not claim AgentGuard can override host behavior.
- In-host hooks are defense in depth, not an isolation boundary against malicious plugins or arbitrary in-process code. High-threat deployments still require OS- or container-level network egress controls.
- The first release covers chat completions, responses, and messages to the extent exposed by each host. Embeddings, provider file uploads, and auxiliary model calls without a public lifecycle must be shown as `unsupported`.
- Do not introduce a local model proxy, transparent network proxy, or traffic interception as a compensating path.

---

## 1. Current Conclusions

### 1.1 The original requirements have three layers

1. **Static PII scanning (rules 1–10):** Detect hardcoded national IDs, bank accounts, biometric data, medical records, location traces, contact lists, phone numbers, email addresses, and bulk personal data in code, configuration, and data files.
2. **Static relay risk (rules 11–13):** Detect model endpoint overrides, forwarding of user keys, and install scripts that silently rewrite agent configuration.
3. **Runtime model-traffic protection (rules 14–19):** Before an actual model request is sent, inspect its endpoint, PII, credentials, and bulk workspace data; before a model response drives tool execution, inspect it for response poisoning.

AgentGuard can fully implement the first two layers. The ceiling for the third depends on the model-call lifecycle currently exposed by each host. This plan does not require hosts to add interfaces; missing capabilities are handled as `partial`, `observe_only`, or `unsupported`.

Complete rule list:

| # | Rule ID | Type | Primary objective |
| --- | --- | --- | --- |
| 1 | `PII_NATIONAL_ID` | Static | National ID, passport, SSN, and similar identifiers |
| 2 | `PII_BANK_ACCOUNT` | Static | Bank card, credit card, IBAN, and payment account |
| 3 | `PII_BIOMETRIC` | Static | Face, fingerprint, voiceprint, iris, and genetic data |
| 4 | `PII_MINOR_DATA` | Static | Data about children under 14 |
| 5 | `PII_HEALTH_RECORD` | Static | Medical records, diagnoses, prescriptions, and laboratory data |
| 6 | `PII_LOCATION_TRACE` | Static | Continuous precise location and movement traces |
| 7 | `PII_CONTACT_DUMP` | Static | Bulk contact lists or customer lists |
| 8 | `PII_PHONE_NUMBER` | Static | Chinese mobile and E.164 phone numbers |
| 9 | `PII_EMAIL_ADDRESS` | Static | Personal email addresses |
| 10 | `PII_HARDCODED_DATASET` | Static | Inline datasets containing multiple PII categories |
| 11 | `LLM_ENDPOINT_OVERRIDE` | Static | Model base URL points to a non-official domain |
| 12 | `RELAY_KEY_FORWARDING` | Static | A user's model key is forwarded to a third-party host |
| 13 | `RELAY_INSTALL_SCRIPT` | Static | An install script silently rewrites an agent endpoint |
| 14 | `UNTRUSTED_LLM_ENDPOINT` | Runtime | A model request is sent to a T3/T4 endpoint |
| 15 | `PII_EGRESS` | Runtime | A model payload carries personal data outbound |
| 16 | `LLM_ENDPOINT_HIJACK` | Runtime | A shell/file write hijacks the model endpoint |
| 17 | `RELAY_RESPONSE_TAMPERING` | Runtime | A relay response injects tool calls, commands, or unknown packages |
| 18 | `LLM_KEY_TO_UNKNOWN_HOST` | Runtime | Model credentials are sent to an unknown or high-risk host |
| 19 | `WORKSPACE_BULK_EGRESS` | Runtime | Large-volume, multi-file workspace data leaves the host |

### 1.2 Capabilities of the five hosts without upstream changes

| Host | Existing interfaces | What AgentGuard can implement | Primary gaps | Coverage |
| --- | --- | --- | --- | --- |
| DSH | `llm/stream` waterfall | Inspect and short-circuit semantic requests before `next()`; wrap streams to inspect responses and tool calls; cover auxiliary calls routed through the shared LLM service | No final adapter URL, authentication facts, or exact serialized byte count; calls bypassing the service are invisible | `partial`, the strongest of the five |
| Hermes | `pre_llm_call`, `pre_api_request`, `post_api_request`, `pre_tool_call` | Observe main-loop requests/responses; block dangerous tool execution through `pre_tool_call` | API hook return values do not control calls and exceptions are swallowed; incomplete system/tools; auxiliary SDK calls can bypass; model egress cannot be blocked | Model traffic `observe_only`; tool layer `partial` |
| OpenClaw | `before_agent_run`, `before_model_resolve`, `before_prompt_build`, `llm_input/output`, `model_call_started/ended`, tool hooks | Block initial input at run level; observe model semantics and call statistics; block dangerous tools and endpoint configuration changes | No public per-model-request decision gate; incomplete retry, fallback, auxiliary-call, and final transport facts | Model traffic `observe_only/partial`; run/tool layers can block |
| Codex | `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, compact hooks | Reject user prompts and supported local tool calls; filter tool results; protect endpoint configuration | No per-model-request/response Hook; no final endpoint, credential, or complete payload; hosted tools may bypass | Prompt/tool `partial`; model traffic `unsupported` |
| Claude Code | `UserPromptSubmit`, `UserPromptExpansion`, `PreToolUse`, `PostToolUse`/`PostToolUseFailure`, `PostToolBatch`, `ConfigChange`, `PreModelSwitch`, `MessageDisplay`, `Stop`, and others | Reject user prompts, command expansion, and tools; replace successful tool output in place; inspect a batch of tool results before the next model call; block some configuration/model changes | No per-model HTTP request gate; failed tool output cannot be replaced in place; `@file` bypasses `PreToolUse`; no final endpoint/credential/complete payload; incomplete automatic fallback coverage; display Hooks do not change transcripts | Prompt/tool/context `partial`; model transport `unsupported` |

Recommended delivery order: **shared AgentGuard capabilities and capability model → DSH adapter → Claude Code adapter → Hermes adapter → OpenClaw adapter → Codex adapter → Cloud control plane**. First validate the blockable semantic-request protocol with DSH, then use Claude Code's richer tool/context Hooks to validate phased protection. Other adapters must degrade according to their real lifecycle rather than inventing missing facts for superficial consistency.

### 1.3 Why runtime rules cannot see the real model API traffic

Existing AgentGuard integrations mainly intercept shell, file, browser, and network tools. Model-provider SDK calls are usually made directly inside the host and do not pass through those tool hooks. Checking only user input, session start, shell `curl`, or tool calls cannot prove that the final payload, endpoint, and credential combination sent to the model is safe.

A true security gate must sit after provider, endpoint, credential, and final request resolution but before the socket or SDK request is sent.

### 1.4 Codex native Hook findings

The assessment covered local `codex-cli 0.148.0-alpha.15`, the App Server schema generated by the CLI, and the [official Codex Hooks documentation](https://learn.chatgpt.com/zh-Hans/docs/hooks). The local installation contains only the executable, not full Codex source, so these conclusions are based on the public contract and locally observable behavior.

Codex currently exposes session events (`SessionStart`, `SessionEnd`, `Interrupt`), user/turn events (`UserPromptSubmit`, `Stop`), tool events (`PreToolUse`, `PermissionRequest`, `PostToolUse`), compaction events (`PreCompact`, `PostCompact`), and subagent events (`SubagentStart`, `SubagentStop`).

It does not expose `before_model_request`, `after_model_response`, provider retry/fallback, or final HTTP transport events. App Server notifications such as `turn/started`, `item/started`, and `item/completed` are observational/control-plane events, not synchronous pre-send security gates.

#### 1.4.1 Available capabilities

| Hook | AgentGuard use | Synchronous blocking | Key limitation |
| --- | --- | --- | --- |
| `UserPromptSubmit` | Inspect the prompt directly submitted for this turn; reject or warn on PII/API keys | Yes, with `decision: "block"` or exit code 2 | Only the raw user prompt; excludes system/developer messages, history, tool results, attachments, compacted context, and retry requests |
| `PreToolUse` | Inspect shell, `apply_patch`, MCP, and most local function tools; block sensitive reads, endpoint changes, and dangerous egress | Yes, with `permissionDecision: "deny"`; supported inputs may also be rewritten | Hosted tools such as WebSearch do not use this path; some specialized tools can bypass; not a model transport gate |
| `PermissionRequest` | Allow or deny a shell, file, or managed-network approval Codex already intends to request | Yes | Fires only when Codex would already ask; cannot create approval for an ordinary action |
| `PostToolUse` | Scan tool results and stop raw results from continuing to the model | Can block subsequent consumption | Side effects have already occurred and cannot be rolled back; the final model request remains invisible |
| `PreCompact` / `PostCompact` | Record compaction and audit or supplement context policy | Not suitable as a model-traffic gate | Does not expose the complete semantic payload after compaction |
| `Stop` | Audit or validate at turn completion | Cannot block model calls that already occurred | Can affect continuation only; cannot reject or revoke an existing response |

Security Hooks must be synchronous. A background Hook with `async: true` cannot block, approve, or rewrite the triggering action. Hook output must not echo raw PII, API keys, or full tool results because oversized output may spill into local temporary files.

#### 1.4.2 Coverage of rules 14–19

| Rule | What native Codex Hooks can do | What they cannot do | Conclusion |
| --- | --- | --- | --- |
| `UNTRUSTED_LLM_ENDPOINT` | `PreToolUse` can stop shell/file tools from changing configuration to an unknown endpoint | Cannot read the endpoint finally resolved for each model call or inspect internal fallback | Partial |
| `PII_EGRESS` | `UserPromptSubmit` can inspect directly pasted PII; `PostToolUse` can stop sensitive tool output entering context | Cannot inspect system, history, attachments, compacted context, or internally generated content in the final request | Partial |
| `LLM_ENDPOINT_HIJACK` | `PreToolUse` can stop supported tools from modifying `.codex/config.toml`, environment variables, or shell launch configuration | Non-Hook changes and the actual endpoint of the next request cannot be revalidated | Partial; the runtime rule best suited to native Hooks |
| `RELAY_RESPONSE_TAMPERING` | `PreToolUse` can provide a last gate when a malicious response produces a supported local tool call | No Hook before the model response reaches the Agent; incomplete control of prose and hosted tools | Partial |
| `LLM_KEY_TO_UNKNOWN_HOST` | Can stop obvious tool behavior that reads a key then invokes `curl`/MCP | Cannot see the destination and Authorization combination of Codex's internal model request | Does not meet the model-traffic requirement |
| `WORKSPACE_BULK_EGRESS` | Can apply path/size heuristics per file read, command, or MCP argument | Cannot calculate total bytes, files, and attachments in the final assembled request | Does not meet the model-traffic requirement |

Therefore, native Codex Hooks protect direct user input and local tool boundaries, reducing endpoint hijacking, sensitive-file reads, and response-induced tool execution. They do not provide complete visibility into or blocking of real model API traffic.

### 1.5 Claude Code native Hook findings

This assessment uses the [Claude Code Hooks reference](https://code.claude.com/docs/en/hooks) and [Permissions documentation](https://code.claude.com/docs/en/permissions) retrieved on 2026-09-16, plus AgentGuard's existing Claude Code installer/adapter. The local machine did not have the `claude` CLI installed, so fixtures must be run against the declared minimum supported version before release. Some newer events have explicit version requirements; for example, `PreModelSwitch`/`PostModelSwitch` require Claude Code `2.1.251+`.

Claude Code has no `before_model_request`, `after_model_response`, or Hook exposing the final HTTP destination/Authorization, but its tool and context lifecycle is richer than Codex:

| Hook | AgentGuard capability | Synchronous block/rewrite | Key limitation |
| --- | --- | --- | --- |
| `UserPromptSubmit` | Scan PII, API keys, and large data before Claude processes user input | Block with `decision: "block"` or exit code 2 | Sees only the current user prompt, not system/history/tool results/final payload; cannot rewrite the prompt in place |
| `UserPromptExpansion` | Apply allow/block policy to slash/custom commands, skills, or MCP prompt expansion using invocation metadata | Can block the expansion | Input is the raw invocation and command metadata, not guaranteed complete expanded text |
| `PreToolUse` | Inspect Bash/PowerShell, Read/Write/Edit, Web, MCP, and other tool inputs | `allow/deny/ask/defer` and `updatedInput` | Not a model transport gate; `@file` injection bypasses it; parallel Hooks cannot aggregate totals before reads; command Hook timeout is fail-open |
| `PermissionRequest` | Proxy an approval Claude Code is already preparing to show | Allow or deny | Only fires for tools that already require approval |
| `PostToolUse` | Scan and redact tool results before the next model context | Replace output with `updatedToolOutput` | Side effects already occurred; `decision: "block"` alone does not hide the original output; replacement must match tool schema |
| `PostToolUseFailure` | Scan failure type/visible error and record sensitive failure paths | Cannot replace or block the failed result; can only add context | stderr/exception text may contain PII; coverage by `PostToolBatch` must be verified per target version |
| `PostToolBatch` | Inspect all tool calls and serialized `tool_response` values before the next model request; count files, bytes, and PII | Can stop the agentic loop before the next model call | Covers only the current tool batch, not complete system/history/user payload; cannot guarantee resumed sessions will not resend old results |
| `ConfigChange` | Audit and prevent Claude settings/skill configuration from taking effect in the current session | Block except for `policy_settings` | Fires after the file change and does not roll back disk content; server-managed settings do not trigger it |
| `PreModelSwitch` | Inspect requested target model and use `context_tokens` to recognize large-context resend | `allow/deny/ask` | No endpoint/credential; does not cover automatic fallback; a custom gateway model is still only a model ID |
| `PostModelSwitch` | Observe session model changes and some automatic fallbacks | Cannot block | Misses temporary fallback serving one turn without changing the session model |
| `MessageDisplay` | Scan or replace assistant text shown in the UI | Display replacement only | Does not change transcript/internal content; timeout/failure shows original; tool-call-only responses do not trigger it |
| `Stop` / `SubagentStop` | Inspect final assistant text and require further work | Can prevent stopping | Response is already generated and may be displayed; not a pre-tool-loop response gate |
| `InstructionsLoaded` / compact Hooks | Observe instruction loading and control some compaction | Instruction load cannot block; `PreCompact` can block compaction | Does not expose the complete context of each final request |

Use only local synchronous `type: "command"` Hooks. `type: "http"` sends Hook input to a network endpoint; `type: "prompt"` and `type: "agent"` invoke another model. None is an appropriate default boundary for raw private data, and `async: true` cannot enforce synchronous blocking.

#### 1.5.1 Coverage of rules 14–19

| Rule | What native Claude Code Hooks can do | What they cannot do | Conclusion |
| --- | --- | --- | --- |
| `UNTRUSTED_LLM_ENDPOINT` | `PreToolUse` can stop endpoint changes; `ConfigChange` can inspect new settings and prevent them taking effect in the current session | No final endpoint per request; environment variables, automatic fallback, gateway routing, and next-session destination are unknown | Model transport `unsupported`; configuration protection `partial` |
| `PII_EGRESS` | Block direct input with `UserPromptSubmit`; block untrusted command/skill/MCP prompt with `UserPromptExpansion`; prevent ordinary sensitive reads with `PreToolUse`; redact results with `PostToolUse.updatedToolOutput`; inspect a full tool batch with `PostToolBatch` | No system, complete history, cache, all attachments, or final payload; `@file` bypasses `PreToolUse` except for exact preconfigured Read deny paths | `partial`, with stronger tool-result coverage than pre-tool-only hosts |
| `LLM_ENDPOINT_HIJACK` | `PreToolUse` blocks Bash/Write/Edit changes; `ConfigChange` blocks some settings; `PreModelSwitch` controls explicit switches | Policy/server-managed settings, external persistent changes, automatic fallback, and final endpoint remain uncontrolled | `partial` |
| `RELAY_RESPONSE_TAMPERING` | `PreToolUse` denies or approves dangerous tool calls; `Stop`/`MessageDisplay` observe text risk | No Hook before the raw model response reaches the Agent; display replacement does not affect transcript; relay origin/signature cannot be verified | Tool execution protection `partial`; response integrity `unsupported` |
| `LLM_KEY_TO_UNKNOWN_HOST` | Can stop explicit Bash/Web/MCP tools from sending a visible key to an unknown host | Cannot see Claude Code's internal model HTTP destination and Authorization combination | Model transport `unsupported` |
| `WORKSPACE_BULK_EGRESS` | `PreToolUse` controls ordinary reads; `PostToolBatch` aggregates batch file paths and serialized results; `PostToolUse` can replace large results | Cannot calculate final request bytes including history/system/cache/attachments; parallel reads cannot be aggregated before execution; `@file` creates no tool batch | `partial` |

Conclusion: modifying only AgentGuard gives Claude Code strong phased prompt/tool/context protection, especially for keeping sensitive tool output out of the next model call, but cannot provide transport-level guarantees for the final endpoint, credential, and complete payload.

#### 1.5.2 Gaps in the previous AgentGuard implementation

The earlier `agentguard init --agent claude-code` generated only `PreToolUse` matchers for Bash, Read, Write/Edit/MultiEdit, and WebFetch/WebSearch. Its `require_approval → permissionDecision: "ask"` mapping was protocol-compatible, but it still lacked:

- `UserPromptSubmit`, `UserPromptExpansion`, `PostToolUse`, `PostToolUseFailure`, `PostToolBatch`, `ConfigChange`, `PreModelSwitch`, `PostModelSwitch`, and `Stop` installation.
- A generic MCP matcher and coverage for PowerShell and other new/platform-specific tools.
- Handling for `@file` bypass. Exact Claude Code `Read` deny rules can compensate only for sensitive paths explicitly configured by an organization.
- `updatedToolOutput`, so PII in tool results could not be redacted in place before reaching the model.
- Structured merging when `.claude/settings.local.json` already existed; the old default skipped it, while `--force` replaced the whole file.
- Stable Hook paths. `./.claude/hooks/...` could fail after a cwd change; use `${CLAUDE_PROJECT_DIR}` or a stable path resolved at installation.
- A lifecycle model capable of expressing prompt, expansion, batch, config, model-switch, display, and stop stages, plus coverage/enforcement status.

---

## 2. Unified Runtime Protocol

All five adapters map into one local AgentGuard protocol to avoid duplicating privacy rules. The protocol unifies event and capability descriptions; it does not pretend all hosts have the same lifecycle.

### 2.1 Capabilities and events

Add host capability descriptions plus optional `llm_request` and `llm_response` action types in `src/runtime/types.ts`:

```ts
type CoverageLevel = 'full' | 'partial' | 'observe_only' | 'unsupported';
type EnforcementStatus = 'enforced' | 'would_block' | 'observed' | 'unsupported';

interface AgentLifecycleCapabilities {
  userPrompt: 'blocking' | 'observe_only' | 'none';
  promptExpansion: 'blocking' | 'observe_only' | 'none';
  modelRequest: 'blocking' | 'observe_only' | 'none';
  modelResponse: 'blocking' | 'observe_only' | 'none';
  preTool: 'blocking' | 'observe_only' | 'none';
  postTool: 'blocking' | 'observe_only' | 'none';
  toolOutputRewrite: boolean;
  postToolBatch: 'blocking' | 'observe_only' | 'none';
  configChange: 'blocking' | 'observe_only' | 'none';
  modelSwitch: 'blocking' | 'observe_only' | 'none';
  assistantDisplay: 'rewrite_display_only' | 'observe_only' | 'none';
  finalDestination: boolean;
  credentialFacts: boolean;
  exactPayloadBytes: boolean;
  retryAndFallback: boolean;
  auxiliaryModelCalls: boolean;
}

interface LlmEgressRequestMetadata {
  requestId: string;
  parentRequestId?: string;
  sessionId: string;
  purpose: 'conversation' | 'compaction' | 'title' | 'vision' |
    'embedding' | 'file_upload' | 'plugin' | 'other';
  lifecycleStage: 'user_prompt' | 'prompt_expansion' | 'run_start' | 'model_request' |
    'model_response' | 'pre_tool' | 'post_tool' | 'post_tool_batch' |
    'config_change' | 'model_switch' | 'assistant_display' | 'stop';
  canBlockCurrentAction: boolean;
  provider?: string;
  model?: string;
  apiMode?: string;
  attempt?: number;
  isRetry?: boolean;
  isFallback?: boolean;
  destination?: {
    scheme?: string;
    host?: string;
    port?: number;
    path?: string;
    service?: string;
    region?: string;
  };
  credentialKind: 'api_key' | 'oauth' | 'aws' | 'ambient' | 'none' | 'unknown';
  credentialPresent: boolean | 'unknown';
  payloadBytes?: number;
  attachmentBytes?: number;
  messageCount?: number;
  filePathCount?: number;
}
```

Each adapter statically declares `AgentLifecycleCapabilities`. Every event also carries whether the current action can actually be blocked. Invisible fields stay `undefined` or `unknown` and must not be inferred as real network facts from a default provider, environment-variable name, or historical event.

Semantic payloads supplied by a host Hook are passed to the evaluator as local, read-only, short-lived input and must not enter persistent metadata. Audit events retain only redacted summaries, counts, coverage level, and missing facts.

### 2.2 Lifecycle semantics

```text
The host emits an existing lifecycle event
        ↓
The AgentGuard adapter normalizes visible facts, missing facts, and blockability
        ↓
The local evaluator evaluates rules decidable for this event
        ↓
blocking hook: allow / warn / require_approval / block
observe_only hook: audit / warn (must not claim the model call was blocked)
        ↓
pre-tool hook provides the final gate for dangerous execution
```

Requirements:

- Only events with `canBlockCurrentAction=true` may return `require_approval` or `block` with enforcement semantics. Otherwise mark the outcome `observe_only` and use a later `pre_tool` gate where possible.
- Preserve the evaluator's policy decision separately from the adapter's actual `enforcementStatus`. For example, an observer hit records `policyDecision=block` and `enforcementStatus=would_block` rather than “blocked.”
- `warn` does not block, but must produce a redacted audit record.
- Only an existing blocking seam such as DSH `llm/stream` can short-circuit a semantic request before it is sent. Other hosts must not rename run-start, observer, or tool Hooks to `before_model_request`.
- If a response Hook cannot stop propagation, AgentGuard records only response risk. A blocking `pre_tool` may later stop a dangerous local tool call caused by that response.
- Associate retries/fallbacks only if the host emits a distinguishable event for every attempt; otherwise set the capability to `false`.
- All adapters share one evaluator, while every audit retains `agentHost`, `lifecycleStage`, `coverageLevel`, and `missingFacts`.

### 2.3 Endpoint tiers

Implement the single classifier in `src/runtime/llm-endpoints.ts`:

| Tier | Meaning | Default treatment |
| --- | --- | --- |
| T0 | localhost, loopback, `.local`, Ollama, LM Studio | endpoint `allow`; PII `allow` |
| T1 | Official model-provider endpoints | endpoint `allow`; PII `warn` |
| T2 | Auditable clouds/aggregators such as Azure OpenAI, Bedrock, Vertex AI, and OpenRouter | endpoint `allow`; PII `warn` |
| T3 | Unknown, self-hosted, or relay endpoint | endpoint/PII `require_approval` |
| T4 | Blocked domain, high-risk TLD, IP literal, URL shortener, and similar | `block` |

User-configured `trustedLlmEndpoints` may promote a private deployment into the trusted range but cannot override `blockedDomains`.

### 2.4 Standard inputs, decisions, and degradation for rules 14–19

| Rule | Facts required for a complete judgment | Default with complete facts | Handling when facts are missing |
| --- | --- | --- | --- |
| `UNTRUSTED_LLM_ENDPOINT` | Final destination, API path/service, and tier | T3 `require_approval`; T4 `block` | `unsupported`; endpoint hijacking can still be prevented through configuration writes and explicit network tools |
| `PII_EGRESS` | Complete semantic payload about to be sent plus tier | T0 `allow`; T1/T2 `warn`; T3 `require_approval`; T4 `block` | Scan only Hook-visible portions and mark `partial`; never report “no PII in this request” |
| `LLM_ENDPOINT_HIJACK` | Shell/file-write changes to endpoint configuration | T3 `require_approval`; T4 `block` | Enforce whenever a blocking pre-tool exists; internal or external changes remain invisible |
| `RELAY_RESPONSE_TAMPERING` | Complete response, source tier, tool calls/commands/package names | T3/T4 `require_approval` | Response observer audits only; blocking pre-tool stops the final dangerous action and coverage is `partial` |
| `LLM_KEY_TO_UNKNOWN_HOST` | `credentialPresent`/`credentialKind` and final destination | T3/T4 `block` | If either credential presence or destination is unknown, return `unsupported` rather than inferring allow |
| `WORKSPACE_BULK_EGRESS` | Final payload bytes, attachment bytes, multi-file path features, and tier | T0–T2 `warn`; T3 `require_approval`; T4 `block` | Apply heuristics to visible reads/tool arguments and mark `partial`; do not produce a complete conclusion without final totals |

---

## 3. Phased Implementation

### Task 1: Freeze policy semantics and data boundaries

**Files:**

- Modify: `src/runtime/types.ts`
- Modify: `src/runtime/policy.ts`
- Modify: `docs/privacy-boundary.md`
- Test: `src/tests/runtime-cloud.test.ts`

**Produces:** Versioned local request/response events, host capabilities, endpoint tiers, approval semantics, and a redacted Cloud contract.

- [x] Add `llm_request` and `llm_response` to `RuntimeActionType` and audit every action-type switch and serialization path.
- [x] Add `AgentLifecycleCapabilities`, `CoverageLevel`, `EnforcementStatus`, `canBlockCurrentAction`, and `missingFacts`, explicitly declared by every adapter.
- [x] Add `untrustedLlmEndpoint` and `trustedLlmEndpoints` to `EffectiveRuntimePolicy.network`, plus `privacy.piiEgressTrusted`, `privacy.piiEgressUntrusted`, `privacy.enabledCategories`, `privacy.bulkEgressBytes`, `privacy.bulkAttachmentBytes`, and `privacy.bulkFilePathCount`.
- [x] Restrict credential metadata to type and presence. Never retain the key, Authorization value, or a reversible digest.
- [x] Define `payloadBytes` as the UTF-8 byte length of the serialized request body. Use `undefined` when unavailable; do not present character count as exact bytes.
- [x] Define fail-closed behavior for approval timeouts, non-interactive hosts, and security-gate errors.
- [x] Add compatibility tests for old Cloud policies that omit the new fields.

**Acceptance:** Old policy caches continue to load. Without Cloud, the default local policy produces a deterministic decision or an explicit `partial/observe_only/unsupported` result for rules 14–19; missing fields never produce a misleading `allow`.

### Task 2: Implement static PII rules 1–10

**Files:**

- Create: `src/scanner/rules/privacy.ts`
- Modify: `src/scanner/rules/index.ts`
- Modify: `src/types/scanner.ts`
- Modify: `src/scanner/index.ts`
- Test: `src/tests/scanner.test.ts`
- Test fixtures: `src/tests/fixtures/privacy/`

- [x] Add ten `PII_*` risk tags and register a rule for each.
- [x] Implement validators such as Chinese national ID mod-11-2, bank-card Luhn, and IBAN mod-97.
- [x] Require both a field label and a value for ordinary PII; bare numbers must not match.
- [x] Exclude test cards, `example.com`, and faker/test/noreply patterns.
- [x] Lower severity by one level for `test`, `fixtures`, `examples`, and `mock` paths rather than ignoring them completely.
- [x] Require at least 20 phone numbers or email addresses for `PII_CONTACT_DUMP`.
- [x] Require at least three PII categories in the same structure for `PII_HARDCODED_DATASET`.
- [x] Update scanner summaries so privacy hits do not fall into generic security descriptions.

**Acceptance:** Every rule has at least one true-positive, false-positive-suppression, and path-degradation test. Test evidence contains no complete raw PII value.

### Task 3: Implement endpoint classification and static relay rules 11–13

**Files:**

- Create: `src/runtime/llm-endpoints.ts`
- Create: `src/scanner/rules/llm-relay.ts`
- Modify: `src/scanner/rules/index.ts`
- Modify: `src/types/scanner.ts`
- Test: `src/tests/llm-endpoints.test.ts`
- Test: `src/tests/scanner.test.ts`

- [x] Normalize URL case, default ports, IPv4/IPv6, punycode, trailing dots, userinfo, and redirect targets.
- [x] Fix classification precedence: identify loopback/T0 first, then classify ordinary IP literals as T4 so `127.0.0.1` and `::1` are not incorrectly blocked.
- [x] Establish default T0–T4 lists and allow policy to add private trusted endpoints.
- [x] Implement `LLM_ENDPOINT_OVERRIDE` for common OpenAI, Anthropic, Gemini, and agent base-URL variables/configuration formats.
- [x] Implement `RELAY_KEY_FORWARDING`, requiring credential access and a third-party network target in the same local window.
- [x] Implement `RELAY_INSTALL_SCRIPT` for shell rc files and OpenClaw, DSH, Hermes, Codex, and Claude Code model configuration.
- [x] Match host suffixes at label boundaries so `api.openai.com.attacker.test` is not treated as official.

**Acceptance:** Table-driven T0–T4 tests pass; spoofed official suffixes, IPs, shorteners, and custom ports have negative or high-risk coverage.

### Task 4: Implement the local runtime privacy evaluator and redaction

**Files:**

- Create: `src/runtime/privacy.ts`
- Modify: `src/runtime/evaluator.ts`
- Modify: `src/runtime/redaction.ts`
- Modify: `src/runtime/audit.ts`
- Modify: `src/runtime/protect.ts`
- Test: `src/tests/runtime-cloud.test.ts`
- Create: `src/tests/runtime-privacy.test.ts`

- [x] Generate reasons for rules 14–19 in `customPolicyReasons`.
- [x] Explicitly map every new reason in `policyDecisionFor`; do not rely on fallback `warn`.
- [x] Keep PII reason severity at `medium` or higher so scores below 20 cannot silently auto-allow it.
- [x] Extract PII detection into reusable local pure functions shared by static scanning and runtime body scanning.
- [x] Evidence contains only PII category, count, and mask; never a complete matched value.
- [x] Extend `REDACTION_PATTERNS` for all new PII types while retaining credential fallback redaction.
- [x] Count body, attachments, and file paths separately rather than relying only on a truncated `bodyPreview`.
- [x] Correlate request and response audit records with the same `requestId` without writing raw payloads to disk.

**Acceptance:** All six runtime rules have complete-fact and missing-fact tests covering allow/warn/approval/block and `partial/observe_only/unsupported`. Neither local audit nor simulated Cloud payloads contain the original test PII/API key.

### Task 5: Adapt the existing DSH `llm/stream` lifecycle

**AgentGuard files:**

- Modify: `src/dsh/plugin.ts`
- Create: `src/dsh/llm-privacy.ts`
- Modify: `dsh.cordis.patch.yml`
- Test: `src/tests/dsh-plugin.test.ts`
- Create: `src/tests/dsh-llm-privacy.test.ts`
- Extend: `scripts/test-dsh-plugin-e2e.mjs`

DSH source is read-only lifecycle-contract evidence. This task creates no DSH modification, patch, or release requirement.

- [x] Register an `llm/stream` waterfall listener in the AgentGuard DSH plugin.
- [x] Declare DSH capabilities: `modelRequest=blocking`; final destination, credential facts, and exact payload bytes are unavailable; auxiliary coverage depends on whether a call uses `ctx.llm.stream()`.
- [x] Read the actually available system, messages, tools, images, provider, and model from `GenerateOptions` to build a local `llm_request`. Keep missing purpose, attempt, and endpoint fields `unknown`.
- [x] Run AgentGuard before `next()`. Return a canonical error stream for `block` and use native DSH `approval/request` for `require_approval`.
- [x] Wrap the downstream stream to detect visible tool calls, commands, and package names. Mark response capability `blocking` only if the wrapper reliably short-circuits before DSH consumes it; otherwise use `observe_only`.
- [x] Verify by integration test whether conversation, compaction, session title, and other known consumers use `ctx.llm.stream()`. Record bypasses as adapter capability gaps instead of changing DSH.
- [x] Report missing transport facts for rules 14, 18, and 19; never infer the actual endpoint or key presence from a provider name.

**Acceptance:** Every call using existing `llm/stream` receives a consistent semantic-request decision. Final URL, authentication facts, exact bytes, adapter-internal retry/fallback, and direct SDK calls are explicitly `unsupported`; do not claim DSH fully covers rules 14–19.

### Task 6: Adapt the existing Hermes plugin lifecycle

**AgentGuard files:**

- Modify: `plugins/hermes/plugin.py`
- Modify: `plugins/hermes/bridge.py`
- Add tests: `plugins/hermes/tests/test_llm_request.py`
- Add tests: `plugins/hermes/tests/test_llm_response.py`
- Modify: `docs/hermes.md`

Hermes source is read-only lifecycle-contract evidence. This task creates no Hermes modification, patch, or release requirement. Existing boundaries:

- `pre_llm_call` fires once per user turn, not once per model request.
- `pre_api_request` fires for each main-loop API call, but its return value is ignored and exceptions are swallowed.
- It passes only `request_messages`; Anthropic system and tools have already been separated into other `api_kwargs` fields.
- `call_llm()`, `async_call_llm()`, title, compression, iteration summary, and some trajectory paths call the provider client directly and bypass the Hook.
- `post_api_request` can observe the primary response but not block it; `transform_llm_output` fires only after the entire tool loop.

- [x] Register existing `pre_llm_call`, `pre_api_request`, `post_api_request`, and `pre_tool_call`. Do not reference nonexistent request/response gates.
- [x] Declare Hermes capabilities: main-loop model request/response is `observe_only` and `pre_tool_call` is `blocking`; auxiliary models, complete system/tools, retry/fallback, and transport facts are incomplete or unavailable.
- [x] Map visible messages/provider/model/base URL from `pre_api_request` into `llm_request` with `canBlockCurrentAction=false`. Even if the local evaluator returns block, record only a violation/warning rather than “blocked.”
- [x] Map `post_api_request` to an `llm_response` observer. Record correlated response-poisoning risk, while `pre_tool_call` performs actual tool blocking.
- [x] Retain `pre_tool_call` as the final execution gate after endpoint hijacking or response poisoning.
- [x] Do not start a Node subprocess per large prompt. Provide a resident local AgentGuard daemon plus Unix socket; use a named pipe or authenticated loopback IPC on Windows.
- [x] Restrict IPC to the current user and enforce request size, timeout, and fail-closed behavior.
- [x] Report `unsupported` capabilities for title, compression, iteration summary, trajectory, and other known bypasses. Do not monkey-patch Hermes internals.

**Acceptance:** Visible Hermes main-loop model events enter redacted audit and dangerous local tools are blocked in `pre_tool_call`. Model requests themselves, auxiliary LLM calls, and raw model responses are explicitly `observe_only/unsupported`; never claim a T3 endpoint was blocked before send.

### Task 7: Adapt the existing OpenClaw plugin lifecycle

**AgentGuard files:**

- Modify: `src/adapters/openclaw-plugin.ts`
- Modify: `src/adapters/openclaw.ts`
- Test: `src/tests/adapter.test.ts`
- Modify: `docs/openclaw.md`

OpenClaw source is read-only lifecycle-contract evidence. This task creates no OpenClaw modification, patch, or release requirement. Existing boundaries:

- `before_agent_run` sees initial prompt/history once before a run, not every model call, tool turn, or retry.
- `before_model_resolve` can override provider/model and `before_prompt_build` can modify prompt context, but neither is a per-request security-decision gate.
- `llm_input` exposes run-level provider/model/system/prompt/history/tools and `llm_output` exposes part of the response, but both are observers.
- `model_call_started`/`model_call_ended` provide call ID, provider/model, and some byte statistics, but no final endpoint/credential.
- Provider `wrapStreamFn` is near each call but is owned by the provider and is not a global security chain available to every plugin.

- [x] Register `before_agent_run` as a run-level blocking gate for current prompt, loaded history, and system prompt; state clearly that it is not a per-model-call gate.
- [x] Register `llm_input`/`llm_output` and `model_call_started`/`model_call_ended` as observers and correlate audit by runId/callId where possible.
- [x] Record only provider/model, semantic content, and byte statistics supplied by the Hook. Keep endpoint, credential, and retry/fallback `unknown` without event evidence.
- [x] Register `before_tool_call`/`after_tool_call` to stop dangerous commands, sensitive-file reads, endpoint configuration changes, and execution induced by response poisoning.
- [x] Use OpenClaw's existing approval return shape for `requireApproval` in `before_tool_call`. `before_agent_run` supports pass/block only, so do not fabricate approval.
- [x] Do not register or occupy provider-private `wrapStreamFn` and do not monkey-patch provider runtime.
- [x] Black-box test the main run, second tool-loop request, compaction, retry/fallback, and auxiliary calls. Report paths without a public Hook as `unsupported`.

**Acceptance:** Initial runs and supported tools can be blocked by existing gates, while public LLM/diagnostic observers produce redacted audit. Per-model requests, final endpoint/credential, internal retry/fallback, and auxiliary calls without public Hooks remain `observe_only/unsupported`.

### Task 8: Implement limited coverage with native Codex Hooks

**AgentGuard files:**

- Modify: `src/installers.ts`
- Modify: `src/runtime/protect.ts`
- Modify: `docs/codex.md`
- Test: `src/tests/installers.test.ts`
- Add tests: `src/tests/codex-hooks.test.ts`

**Codex files generated in the target project:**

- Create or merge: `.codex/hooks.json`
- Create: `.codex/hooks/agentguard-user-prompt.sh`
- Create: `.codex/hooks/agentguard-pre-tool.sh`
- Create: `.codex/hooks/agentguard-post-tool.sh`

#### 8.1 Correct the integration

The earlier `agentguard init --agent codex` generated `.codex/skills/agentguard/SKILL.md` and `.codex/agentguard-hook.json`. The latter is not the official Codex Hook configuration, while the Skill relies on the model voluntarily invoking `agentguard protect` and cannot be an enforcement boundary.

- [x] Generate or safely merge the official `<repo>/.codex/hooks.json` without overwriting existing Hooks.
- [x] Keep the Skill as usage guidance, but never describe it as a security boundary.
- [x] Ask the user after installation to review and trust the Hook through `/hooks`; Codex skips untrusted project Hooks.
- [x] Record the minimum supported Codex version and check that the `hooks` feature is available during initialization.
- [x] Use the Git root or a stable absolute path resolved at installation; do not assume Codex always starts at the repository root.

#### 8.2 Hook mapping

- [x] `UserPromptSubmit`: map `prompt` to a local-only `user_prompt` privacy event. For block, emit `{ "decision": "block", "reason": "<redacted reason>" }` or exit 2; for warn, emit only a short `systemMessage`.
- [x] `PreToolUse`: map `tool_name` and `tool_input` to `shell`, `file_read`, `file_write`, `network`, or `mcp_tool`. Return official `permissionDecision: "deny"` for AgentGuard `block` and for `require_approval` that Codex cannot initiate natively.
- [x] `PostToolUse`: scan sensitive tool results and prevent a blocking result from continuing to the model, while stating that tool side effects cannot be undone.
- [x] `PermissionRequest`: handle only approvals Codex already initiated. AgentGuard may deny or allow but cannot create approval for ordinary actions.
- [x] `PreCompact`/`PostCompact`: record only redacted metadata and policy status; never upload transcript or compact content.
- [x] All security Hooks run synchronously; do not set `async: true`.

#### 8.3 Decisions and failure semantics

- [x] Stop emitting Codex-specific `{ "decision": "confirm" }`, which is not the current official `PreToolUse` format.
- [x] Do not emit `permissionDecision: "ask"`. Codex treats it as unsupported, reports Hook failure, and continues the tool call.
- [x] Initially fail closed for `require_approval`: deny the current tool call, return an action ID and redacted explanation, and require explicit user approval before retry. Prevent the Agent from self-executing the approval command.
- [x] Exit 2 on catchable JSON parse or evaluator errors. Record forced Hook termination or cases where the process never returns an exit code according to actual Codex semantics; do not broadly claim timeout is fail-closed.
- [x] Do not parse `transcript_path` to reconstruct a final model request. Its format is not a stable Hook interface and does not provide a reliable pre-send blocking point.
- [x] Hook stdout/stderr contains only rule ID, risk level, action ID, and redacted reason so long-output spilling cannot persist sensitive content.

#### 8.4 Codex-specific acceptance

- [x] `UserPromptSubmit` rejects a user prompt containing a policy-matched API key or identifier before model processing begins.
- [x] Bash, `apply_patch`, MCP, and confirmed supported local function tools pass through `PreToolUse`; dangerous calls are denied before execution.
- [x] Endpoint configuration changes, sensitive bulk file reads, and explicit `curl` egress have positive and false-positive-suppression tests.
- [x] `PostToolUse` can prevent sensitive results from entering the next model request, while tests confirm the original tool side effect is not reported as rolled back.
- [x] Existing `.codex/hooks.json` is structurally merged and repeated init is idempotent.
- [x] Untrusted Hooks, hosted WebSearch, specialized-tool bypass, and internal Codex model calls are documented gaps and are excluded from “protected” statistics.
- [x] Reports for rules 14–19 distinguish `full`, `partial`, `observe_only`, and `unsupported`; prompt/tool hit rate is never presented as model API traffic coverage.

**Acceptance:** Direct user input and supported local tool paths can be inspected and denied by official synchronous Codex Hooks. Documentation, CLI status, and audit show the limited coverage and do not claim visibility or control over final model endpoint, credential, complete payload, or raw model response.

### Task 9: Extend the native Claude Code Hook adapter

**AgentGuard files:**

- Modify: `src/installers.ts`
- Modify: `src/adapters/types.ts`
- Modify: `src/adapters/claude-code.ts`
- Modify: `src/runtime/types.ts`
- Modify: `src/runtime/protect.ts`
- Modify: `docs/claude-code.md`
- Modify: `src/tests/installer.test.ts`
- Modify: `src/tests/adapter.test.ts`
- Modify: `src/tests/integration.test.ts`
- Add tests: `src/tests/claude-code-lifecycle.test.ts`

**Claude Code files generated or merged in the target project:**

- Create or merge: `.claude/settings.local.json`
- Create/update: `.claude/hooks/agentguard-protect.sh`
- Optional Windows equivalent: `.claude/hooks/agentguard-protect.ps1`

Claude Code source and CLI are out of scope. AgentGuard installs only official settings Hooks and declares actual capabilities according to the host version.

#### 9.1 Installer and version capabilities

- [x] Structurally and idempotently merge `.claude/settings.local.json`, preserving existing settings and other Hooks for the same event. `--force` must not replace unknown configuration wholesale.
- [x] Use `${CLAUDE_PROJECT_DIR}` or a stable absolute path so Hooks remain available after `/cd` or startup from a subdirectory.
- [x] Record `claude --version` and gate events with explicit minimum versions; register `PreModelSwitch`/`PostModelSwitch` only for `2.1.251+`.
- [x] After installation, print enabled events, events blocked by version requirements, and the coverage matrix. If the CLI is absent, generate templates but mark status `unverified`.
- [x] Generate only local synchronous `type: "command"` Hooks by default. Do not send raw prompt/tool results to `http`, `prompt`, `agent`, or external MCP Hooks.

#### 9.2 Lifecycle mapping

- [x] `UserPromptSubmit`: map to `user_prompt` and scan the current prompt; block with top-level `{ "decision": "block", "reason": "<redacted reason>" }`.
- [x] `UserPromptExpansion`: map to `prompt_expansion` and use `expansion_type`, `command_name`, `command_args`, and `command_source` to stop untrusted slash/custom commands, skills, or MCP prompt expansion. Do not claim visibility into expanded text the Hook did not provide.
- [x] `PreToolUse`: dynamically map Bash/PowerShell, Read, Write/Edit, Web, MCP, and unknown tools from `tool_name`/`tool_input` rather than depending on a small hardcoded installer matcher list.
- [x] `@file` does not trigger `PreToolUse`. Idempotently merge exact Claude Code `Read` deny rules only for sensitive paths explicitly listed by AgentGuard policy. Mark other `@file` paths `unsupported`; never use a workspace-wide deny to simulate final-payload protection.
- [x] Continue using native `permissionDecision: "ask"` for `require_approval`. Test and document actual behavior without an approval UI or in a non-interactive environment.
- [x] `PostToolUse`: scan `tool_response` and use `updatedToolOutput` for built-in/MCP tools with stable schemas. Top-level `decision: "block"` is not a substitute because Claude still sees the original output.
- [x] `PostToolUseFailure`: map only failure type, redacted error summary, and coverage. This event cannot replace or block the failed result, so added context must not be recorded as successful redaction.
- [x] `PostToolBatch`: map to `post_tool_batch` and calculate PII, file-path count, and serialized-result bytes for the batch about to reach the model. End the agentic loop before the next model call when blocking policy matches.
- [x] `ConfigChange`: read `source`/`file_path` and detect unknown endpoints, key forwarding, or dangerous permission in the new configuration. Reject application to the current session where blockable, while stating that disk content is not rolled back.
- [x] `PreModelSwitch`: inspect `from_model`, `to_model`, `source`, and `context_tokens`; block a disallowed explicit switch or request approval for large-context resend, without treating a model ID as an endpoint.
- [x] `PostModelSwitch`: audit automatic/session model changes only; a one-off fallback without an event remains `unsupported`.
- [x] `MessageDisplay` and `Stop`: observe response text and optionally redact display. Fix `canBlockCurrentAction=false` or `display_only` and never claim transcript, model response, or prior tool behavior was changed.
- [x] `InstructionsLoaded`, `PreCompact`, and `PostCompact`: record only redacted metadata and coverage. Do not parse unstable transcripts to invent a final model payload.

#### 9.3 Decision, performance, and failure semantics

- [x] Catchable adapter/JSON/evaluator errors make blocking Hook wrappers exit 2; observer errors record only `SECURITY_GATE_ERROR`.
- [x] Claude Code command Hook timeout/failure may continue the original action. Mark this host fail-open gap, configure a reasonable timeout, and monitor it; documentation must not claim timeout is fail-closed.
- [x] Enable `PostToolUse.updatedToolOutput` only for output schemas verified by fixtures. Do not guess for unknown schemas; use `PostToolBatch` to stop the next call and mark coverage `partial`.
- [x] Parallel `PreToolUse` Hooks do not share reliable pre-batch state. Aggregate bulk-read thresholds in `PostToolBatch` and record that reads already occurred while model continuation was stopped. Existing transcript data and retransmission after resume are not guaranteed to be suppressed.
- [x] Hook output contains only rule IDs, masks, counts, and action ID. Never write raw PII, API keys, or large tool results to stdout/stderr, audit, or Cloud.

#### 9.4 Claude Code-specific acceptance

- [x] A user prompt containing PII/API keys is rejected before Claude processes it and does not enter the turn.
- [x] Direct slash/custom commands, skills, and MCP prompt expansion trigger `UserPromptExpansion`; untrusted commands are blocked from metadata without assuming expanded content is visible.
- [x] Bash, PowerShell, Read, Write/Edit, Web, MCP, and unknown tools have matcher/dynamic-mapping tests; dangerous calls deny or ask before execution.
- [x] `@sensitive-file` is blocked by merged `Read` deny rules when policy configures the exact path. An unconfigured fixture reports `unsupported` and is not counted in PreToolUse protection.
- [x] Sensitive results with a verified schema are replaced with `updatedToolOutput` and the next model-call fixture no longer contains the original.
- [x] For PII in failed-tool stderr/exception text, fixtures verify whether target-version `PostToolBatch.tool_response` contains the failed result and can stop the next call. Otherwise report `unsupported`.
- [x] Parallel sensitive-file reads are aggregated in `PostToolBatch`, which blocks before the next model call and reports file count and redacted bytes.
- [x] Endpoint settings changed by Agent tools are intercepted by `PreToolUse`. External changes are prevented from applying to the current session by `ConfigChange`, while disk changes are explicitly not rolled back.
- [x] Explicit model switches can deny/ask. Automatic fallback is audit-only or `unsupported` and is never reported as blocked.
- [x] `MessageDisplay` replacement counts only as `display_only`; tests show that the original transcript and Stop content are unaffected.
- [x] The installer idempotently merges existing settings. Hooks remain discoverable when started from a subdirectory or after `/cd`.
- [x] Every Hook fixture asserts policy decision, actual enforcement status, coverage level, and missing facts.

**Acceptance:** Claude Code's current prompt, command-expansion metadata, supported tools, verified tool output, and current batch of tool results can be inspected, blocked, or redacted by native synchronous Hooks. Configuration and explicit model switches receive partial protection. `@file` receives path-level compensation only for exact `Read` deny policy. Final model endpoint, credential, complete payload, automatic/temporary fallback, unconfigured `@file` injection, and raw model response remain `partial/unsupported`.

### Task 10: AgentGuard Cloud companion changes

Cloud is not a prerequisite for local execution, but it supports centralized policy and audit.

The local repository work is complete in the Task 10 wire contract. The Cloud service and Dashboard must implement the [Cloud requirements](./cloud-task-10-requirements.md).

#### 10.0 Local companion work

- [x] Policy, action, and audit wire payloads use a versioned schema and remain compatible with old policies that omit the schema.
- [x] Action/audit uploads preserve redacted lifecycle, coverage, enforcement, missing-fact, requestId, and related facts without uploading raw LLM content.
- [x] Cloud policy fields are normalized locally; Cloud disconnection, timeout, or legacy policy falls back to local/cached policy.
- [x] Add Cloud wire-contract, legacy-policy, redaction, and offline-fallback tests, and update native API/privacy-boundary documentation.

Cloud service work is defined in `docs/cloud-task-10-requirements.md`. The original checklist below still represents Cloud-side status.

**Cloud policy API:**

- [ ] Support `network.untrustedLlmEndpoint` and `network.trustedLlmEndpoints`.
- [ ] Support `privacy.piiEgressTrusted`, `privacy.piiEgressUntrusted`, and `privacy.enabledCategories`.
- [ ] Version the policy schema with backward-compatible defaults so old clients ignore new fields and new clients consume old policies.
- [ ] Normalize organization-configured trusted endpoints and never allow them to override a globally blocked domain.

**Cloud audit API/UI:**

- [ ] Accept `agentHost`, `lifecycleStage`, `coverageLevel`, `enforcementStatus`, `canBlockCurrentAction`, `missingFacts`, plus Hook-supplied endpoint tier, provider, model, purpose, payload size, PII category/count, credential kind, reason, decision, and requestId.
- [ ] Reject or redact suspected prompt, Authorization, API key, and raw PII values again on the server.
- [ ] Let the Dashboard filter by host, coverage, lifecycle stage, endpoint tier, reason code, decision, and purpose.
- [ ] Show retry/fallback relationships only when the host explicitly supplied them; do not show raw prompt/response or fill unknown facts with defaults.
- [ ] Add trends and alerts for rules 14–19 without allowing the audit API to reconstruct an individual's data.

**Acceptance:** Local protection is unchanged when Cloud is disconnected; Cloud captures/test fixtures contain no prompt, key, or complete PII; the Dashboard distinguishes blocked, observed-only, partial, and unsupported events.

### Task 11: Cross-host testing, release, and migration

**AgentGuard verification:**

```bash
npm run build
npm test
npm run test:dsh-package
python -m pytest plugins/hermes/tests -q
```

Do not run or require modified upstream tests for DSH, Hermes, OpenClaw, Codex, or Claude Code. Read-only host source analysis and official contracts may guide fixtures; all implementation verification occurs in the AgentGuard repository and its installation artifacts.

- [x] Create unified evaluator conformance fixtures: identical fact input must produce identical reason, risk score, and decision.
- [x] Create lifecycle fixtures for all five adapters, verifying event fields, `canBlockCurrentAction`, capability, and `missingFacts` mapping.
- [x] Create evaluator fixtures for local, official remote, known aggregator, unknown relay, and high-risk endpoints. Count endpoint coverage for a host only when its adapter provides the endpoint.
- [x] Assert `full/partial/observe_only/unsupported` separately for ordinary requests, the second tool-loop request, retry, fallback, auxiliary model calls, streaming responses, embeddings, and file uploads.
- [x] When destination and credential facts are visible, verify unknown endpoint plus key blocks even without PII. If either fact is invisible, the relevant rule returns `unsupported` rather than `allow`.
- [x] Verify PII-rule failure or Cloud outage never converts a local `block` into allow.
- [x] Collect false positives behind an `observe_only` feature flag first, then enable protect only for lifecycle stages explicitly marked `blocking` by each adapter.
- [x] State in release notes that a plugin cannot constrain malicious in-process code opening sockets directly; high-threat environments require container/OS network policy.

---

## 4. Cross-Host Acceptance Matrix

Under the constraints of no host source changes and no proxy, no host exposes every transport fact required by rules 14–19. Acceptance must reflect real capability:

| Rule | DSH | Hermes | OpenClaw | Codex | Claude Code |
| --- | --- | --- | --- | --- | --- |
| 14 `UNTRUSTED_LLM_ENDPOINT` | Final endpoint invisible: `unsupported`; configuration/explicit network tools can be protected preventively | Main-loop base URL may be visible but cannot be blocked: `observe_only/partial`; auxiliary calls `unsupported` | Final endpoint invisible: `unsupported`; configuration changes can be blocked | Model endpoint invisible: `unsupported`; configuration changes can be blocked | Model endpoint invisible: `unsupported`; `PreToolUse`/`ConfigChange` configuration protection is `partial` |
| 15 `PII_EGRESS` | Visible `llm/stream` semantic payload can be blocked before send: `partial` | Visible main-loop messages are audit-only: `observe_only/partial` | Initial run can block; `llm_input` observes only: `partial` | User prompt and tool results can be blocked: `partial` | Prompt can block, tool output can be replaced, and batch can stop before the next model call: `partial` |
| 16 `LLM_ENDPOINT_HIJACK` | Supported tool/file Hook can block: `partial` | `pre_tool_call` can block: `partial` | `before_tool_call` can block and approve: `partial` | `PreToolUse` can block: `partial` | `PreToolUse`, `ConfigChange`, and `PreModelSwitch` can block some hijacks: `partial` |
| 17 `RELAY_RESPONSE_TAMPERING` | Responses covered by the stream wrapper and final tool calls: `partial` | Response is observed; `pre_tool_call` blocks execution: `partial` | `llm_output` observes; `before_tool_call` blocks execution: `partial` | No raw-response Hook; `PreToolUse` blocks execution: `partial` | Raw response integrity `unsupported`; dangerous tool execution blocked by `PreToolUse`: `partial` |
| 18 `LLM_KEY_TO_UNKNOWN_HOST` | Model transport credential/destination combination invisible: `unsupported` | Model transport cannot be blocked and facts are incomplete: `unsupported` | Credential/destination invisible: `unsupported` | Credential/destination invisible: `unsupported` | Internal model transport invisible: `unsupported`; explicit tool egress can be blocked |
| 19 `WORKSPACE_BULK_EGRESS` | Can inspect semantic payload but lacks exact final bytes: `partial` | Only visible messages/tool actions: `observe_only/partial` | Run/tool/diagnostic fields allow heuristics: `partial` | Prompt and local tools allow heuristics: `partial` | `PostToolBatch` aggregates the batch but lacks final request bytes/history: `partial` |

Shared acceptance invariants:

| Scenario | Expected result |
| --- | --- |
| Hook supplies complete endpoint, credential, and payload facts | Apply T0–T4 and rule policy to produce allow/warn/approval/block |
| A rule's required facts are missing | Return `partial` or `unsupported`, never “passed” |
| Observer finds risk whose policy decision is block | Record `would_block` and the reason; never claim the request was blocked |
| A dangerous response produces a supported tool call | Blocking pre-tool denies or asks before execution |
| A tool changes the model base URL to T3/T4 | Deny or ask in an existing blocking tool Hook; do not promise the next model request can be revalidated |
| Retry/fallback has no independent event | Set `retryAndFallback=false` and do not create a fake second-check audit |
| Title/compaction/vision bypasses public Hooks | Mark `unsupported` and exclude it from protected-rate denominators/successes |
| Cloud times out or is offline | Supported local blocking remains active |
| Approval UI is unavailable for a blocking Hook | Treat `require_approval` as deny |

---

## 5. Product and Architecture Decisions with Recommended Defaults

These questions do not block the first four foundational AgentGuard tasks, but must be frozen before enabling protect for any adapter's blocking lifecycle.

| Question | Recommended default |
| --- | --- |
| Is PII to T1/T2 warning-only? | Preserve the original `warn` requirement. Organization policy may strengthen it but cannot go below the local mandatory floor |
| May a user approve sending a key to T3? | No. Rule 18 is always `block` |
| Should T3 responses be fully buffered? | Only when the existing DSH stream wrapper permits it. Other hosts rely on response observer plus blocking pre-tool and must not claim to block response prose |
| Bulk threshold | Default to `(payloadBytes >= 1 MiB and filePathCount >= 20) or attachmentBytes >= 5 MiB`; all three thresholds are policy-configurable |
| Who may configure a trusted private endpoint? | Local configuration for personal deployments; Cloud policy for organization-managed devices |
| Approval lifetime | The current blockable action only. Without a request gate, do not create a misleading “model request approved” record |
| Hook failure | Catchable AgentGuard blocking-Hook errors fail closed; host timeout/crash semantics are recorded by capability; observer failures record `SECURITY_GATE_ERROR` and a coverage gap |
| Claude Code Hook timeout | Official command Hooks, including `UserPromptSubmit` and `PreToolUse`, may continue the action after timeout/failure. Mark host fail-open and warn in Dashboard/CLI; AgentGuard configuration cannot hide it |
| Claude Code tool-output redaction | Enable `updatedToolOutput` only for tools with schema fixtures. For unknown tools, stop continuation in `PostToolBatch` and mark `partial` |
| Claude Code `@file` injection | Merge exact `Read` denies only for sensitive paths explicitly configured in policy; mark all others `unsupported` rather than using broad denies as a substitute for final-payload inspection |
| Should prompts be sent to an AgentGuard subprocess? | No process per request. Send only through restricted local IPC to a resident evaluator |
| Embeddings/file upload | Test hosts that expose a lifecycle; mark all others `unsupported` rather than implying coverage |

---

## 6. Release Milestones

1. **M0: Rule foundation** — Rules 1–13, endpoint tiers, PII redaction, and policy schema.
2. **M1: Local runtime core** — Rules 14–19, capability model, and missing-fact semantics produce correct decisions for normalized fixtures without requiring Cloud.
3. **M2: DSH adapter** — Blockable semantic-request protection through existing `llm/stream`, with explicit transport degradation.
4. **M3: Claude Code adapter** — Extend the existing PreToolUse integration with prompt, expansion, tool output, batch, config, and model-switch lifecycles, explicitly handling the `@file` boundary.
5. **M4: Hermes adapter** — Use existing observational API Hooks and blocking `pre_tool_call`, explicitly degrading auxiliary-call gaps.
6. **M5: OpenClaw adapter** — Use existing run gate, LLM observers, diagnostic events, and tool gate without requiring a new upstream Hook.
7. **M6: Native Codex Hooks** — Protect user prompts and the local tool layer with official Hooks, while showing partial/unsupported coverage for rules 14–19 in product status.
8. **M7: Cloud control plane** — Policy distribution, redacted audit, Dashboard, and organization endpoint management.
9. **M8: Capability-tiered release** — After evaluator conformance, adapter fixtures, false-positive observation, and rollback exercises, enable protect only for existing blocking lifecycle stages on each host.

Each milestone can ship and roll back independently. Every milestone modifies only AgentGuard. When a host upgrade changes its lifecycle, update only that adapter and its capability declaration.

---

## 7. Source Assessment Basis

Assessment date: 2026-09-16.

The following host source was used only to verify public lifecycles, event fields, and call coverage. It is outside implementation scope.

- AgentGuard: commit `14370b767a7f1847459fcfdaafcaaa841126112e`.
- DSH: commit `b150a551b8d465e31e418e1b2eaf5e79bbb7d28e`, version `0.1.1-rc.2`.
- Hermes: commit `64202200a6043b685750e16107067971446f8818`, version `0.15.1`.
- OpenClaw: local source version `2026.5.26`; the directory had no Git metadata, so no commit SHA was recorded.
- Codex: local `codex-cli 0.148.0-alpha.15`. The package contained only an executable and no complete source commit, so the local CLI/schema and public Hook contract were used.
- Claude Code: the local `claude` CLI was not installed and no local version/runtime test was performed. The official Hook/permissions contract retrieved on 2026-09-16 was used and must be validated against the minimum target version before release.

Key evidence:

- OpenClaw `src/plugins/hooks.ts`, `src/plugins/hook-types.ts`, and `src/plugins/hook-before-agent-start.types.ts`: existing `before_agent_run` gate, prompt/model Hooks, observational LLM Hooks, model-call diagnostics, and tool gates.
- OpenClaw `src/agents/pi-embedded-runner/run/attempt.ts`: actual wiring of `llm_input/output` and the stream-wrapper chain.
- DSH `packages/llm/llm/src/index.ts`: shared `llm/stream` waterfall entry point.
- DSH `packages/compaction/compaction-basic/README.md`: compaction also uses `ctx.llm.stream()` and can be intercepted by the same Hook.
- Hermes `agent/conversation_loop.py`: main-loop `pre_api_request`/`post_api_request`.
- Hermes `agent/auxiliary_client.py`: direct SDK paths for auxiliary model calls.
- Hermes `hermes_cli/plugins.py`: `pre_api_request`/`post_api_request` return values do not affect model-request execution.
- Hermes `SECURITY.md`: OS-level isolation is the only formal boundary against a malicious LLM.
- Codex [official Hooks documentation](https://learn.chatgpt.com/zh-Hans/docs/hooks): lifecycle events, trust model, tool-Hook coverage, and decision formats; it also states that tool Hooks are not a complete enforcement boundary.
- AgentGuard `src/installers.ts`: the previous Codex initializer generated only a Skill and unofficial `.codex/agentguard-hook.json` template.
- AgentGuard `src/runtime/protect.ts`: the previous Codex `confirm` output needed conversion to the official decision format, with fail-closed behavior where native approval cannot be initiated.
- Claude Code [Hooks reference](https://code.claude.com/docs/en/hooks): `UserPromptSubmit`, `UserPromptExpansion`, success/failure tool Hooks, `PostToolBatch`, `ConfigChange`, model-switch, display/stop, `@file` bypass, and their blocking/rewrite semantics.
- Claude Code [Permissions](https://code.claude.com/docs/en/permissions): `PreToolUse` runs before permission prompts, with deny/ask/allow precedence and tool-blocking boundaries.
- AgentGuard `src/installers.ts`, `src/adapters/claude-code.ts`, and `src/runtime/protect.ts`: the earlier Claude Code integration installed only PreToolUse and did not cover prompt, expansion, batch, config, model-switch, or tool-output rewrite lifecycles.

## 8. Definition of Done

Under the current constraints, “done” means that AgentGuard-side compatibility and capability-tiered protection are implemented. It must not be described as complete protection of real model API traffic for all five Agents. Completion requires all of the following:

- All code and installation-artifact changes are inside AgentGuard; there are no host patches, forks, monkey patches, or upstream release dependencies.
- Rules 1–19 are represented in AgentGuard types, scanner/evaluator, policy mapping, redaction, and tests.
- Every adapter statically declares lifecycle capabilities and emits `lifecycleStage`, `canBlockCurrentAction`, `coverageLevel`, and `missingFacts` for every event.
- Identical facts produce identical reason, risk score, and decision through the shared evaluator. Hosts differ only because visible facts and blocking capabilities differ.
- DSH claims blocking only for semantic requests passing through existing `llm/stream`. Final endpoint, credential, exact payload bytes, internal retry/fallback, and service-bypassing calls are explicit gaps.
- Hermes model API Hooks are `observe_only`, auxiliary calls are explicitly incomplete, and `pre_tool_call` provides real blocking for supported dangerous execution.
- OpenClaw claims blocking only for existing gates such as `before_agent_run` and `before_tool_call`. LLM Hooks/diagnostics are observers and final transport facts remain unknown.
- Codex `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, and `PostToolUse` use official configuration and return protocols. Model transport is `unsupported` and unsupported `permissionDecision: "ask"` is never used.
- Claude Code prompt, expansion, tool, output, batch, config, and model-switch Hooks use official return protocols. `updatedToolOutput` is enabled only for verified schemas; `MessageDisplay` is display-only; `@file` bypass, Hook timeout fail-open behavior, and model-transport gaps are explicit.
- Adapter fixtures report actual coverage for ordinary calls, tool loops, auxiliary calls, compaction, retry/fallback, embeddings, and file uploads. Paths without a public lifecycle are never counted as protected.
- Observer findings record only `would_block`, never “blocked.” When a dangerous response creates a supported tool call, a blocking pre-tool provides the final execution gate.
- Local offline protection works. Cloud never receives raw prompts, responses, keys, or complete PII and correctly displays `partial/observe_only/unsupported`.
- Documentation and product UI state that, without host source changes or a network proxy, rules 14 and 18 and parts of 15, 17, and 19 cannot receive complete model-transport guarantees.

If the product still requires checking final endpoint, credential, and complete payload before every model request reaches the socket, that goal is incompatible with this plan's constraints. It requires waiting for hosts to expose the relevant blocking lifecycle and then updating the AgentGuard adapter.
