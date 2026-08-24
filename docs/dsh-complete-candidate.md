# AgentGuard for DSH complete candidate

This candidate completes the agreed installation-time scanner and DSH-native pre-execute runtime guard without changing the bundle's non-disruptive installation default.

## Included

- DSH detection for bundles, profiles, Cordis patches, tools, providers, UI, sessions, storage, and runtime mutation.
- Local directory and pinned GitHub scanning with JSON, Markdown, and HTML reports.
- Full-repository and runtime-surface risk, evidence context, capability profile, impact layers, recommendation, and review priority.
- Structured scan coverage that fails closed when matching files are truncated, oversized, or unreadable.
- Bounded batch scanning and version/report comparison.
- DSH-native tools: `agentguard_dsh_scan`, `agentguard_dsh_scan_batch`, `agentguard_dsh_compare`, and `agentguard_dsh_runtime_summary`.
- Native pre/post lifecycle observation with shared AgentGuard policy semantics.
- Default `protect` mode for pre-execute allow, warn, DSH-native approval, and block.
- Optional block-class malicious network-response containment without returning untrusted response content.
- Exact operator-configured tool ownership attribution and monotonic per-owner policy floors.
- Fail-closed unexpected evaluator errors by default, with an explicit compatibility override.
- Bounded local audit and input-redacted summaries.
- Explicit startup and summary visibility for the configured `off`, `observe`, or `protect` runtime mode.
- Real DSH lifecycle, approval, nesting, concurrency, failure, disposal, packaging, update, removal, and Web startup tests.

## Installation posture

The packaged `dsh.cordis.patch.yml` enables `protect` by default, so a standard DSH installation enforces the configured runtime policy immediately. Operators can explicitly switch to `observe` for audit-only shadow evaluation.

To confirm protection in a profile, add this complete config override to that profile's `cordis.patch.yml`:

```yaml
- id: agentguard-dsh-plugin
  config:
    runtime:
      mode: protect
      failureMode: deny
      postResponseMode: block-malicious
```

DSH profile patches replace the row's entire `config`, so the complete runtime configuration is restated. Optional `attribution.toolOwners` entries must contain only exact owner bindings trusted by the operator; a corresponding `ownerPolicies.<owner>.minimumDecision` can raise that owner's calls to `warn`, `require_approval`, or `block`, but cannot weaken the shared policy. Removing the override returns the bundle to its packaged `protect` configuration after recomposition/restart.

## Acceptance status

The complete candidate passed all 11 guided DSH UAT cases on 2026-08-19. The accepted matrix covers tool registration, single and batch scanning, report comparison, safe execution, native one-shot approval, explicit rejection, pre-execute blocking, redacted runtime summaries, block-class malicious response containment, and Web service stability.

Automated DSH gates independently exercise the real `ToolRuntime`, `ApprovalService`, session event pairs, nested and concurrent calls, policy composition, plugin disposal, package lifecycle, and loopback Web startup. The UAT result validates the installed local composition in addition to those repository-level tests.

## Acceptance commands

For guided in-product acceptance, give DSH the Chinese [user acceptance test](dsh-user-acceptance-test.zh-CN.md). It uses shell short-circuit probes so dangerous branches remain inert even if protection is unavailable.

```bash
npm run build
npm test
npm run test:dsh-e2e
npm run test:dsh-protect
npm run test:dsh-approval
npm run test:dsh-post-enforcement
npm run test:dsh-lifecycle
npm run test:dsh-package
git diff --check
```

The pinned public-plugin benchmark is a separate network gate:

```bash
npm run benchmark:dsh
```

## Intentional boundaries

- Static reports are decision aids, not safety certificates.
- The package does not automatically install or execute a scanned target.
- Source-plugin ownership supports exact operator-configured `runtime.attribution.toolOwners` bindings; unmapped tools remain explicit `unknown` because current DSH lifecycle events do not expose a reliable owner/provider identity.
- Per-owner `minimumDecision` policy floors can raise attributed calls to warn, native approval, or block, but never downgrade a shared AgentGuard decision.
- Runtime policy is therefore action/tool based, not plugin-trust based.
- Post-response anomalies are audit-only by default. Explicit `postResponseMode: block-malicious` suppresses block-class malicious results; approval-class results remain audit-only because DSH has no resumable post-result approval contract.
- npm artifact/source equivalence, marketplace reputation, team policy, badges, and cloud history remain later platform work; they are not prerequisites for this local complete candidate.

## Confirmation decision

Confirm this candidate if the following product contract is acceptable:

1. installation remains observation-first;
2. protection is explicit and fails closed on unexpected evaluator errors;
3. approval is owned by DSH rather than a duplicate AgentGuard queue;
4. pre-execute protection is real, and optional post-response containment applies only to block-class results;
5. unattributed calls never receive plugin-specific trust automatically.
