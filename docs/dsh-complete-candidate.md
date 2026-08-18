# AgentGuard for DSH complete candidate

This candidate completes the agreed installation-time scanner and DSH-native pre-execute runtime guard without changing the bundle's non-disruptive installation default.

## Included

- DSH detection for bundles, profiles, Cordis patches, tools, providers, UI, sessions, storage, and runtime mutation.
- Local directory and pinned GitHub scanning with JSON, Markdown, and HTML reports.
- Full-repository and runtime-surface risk, evidence context, capability profile, impact layers, recommendation, and review priority.
- Bounded batch scanning and version/report comparison.
- DSH-native tools: `agentguard_dsh_scan`, `agentguard_dsh_scan_batch`, `agentguard_dsh_compare`, and `agentguard_dsh_runtime_summary`.
- Native pre/post lifecycle observation with shared AgentGuard policy semantics.
- Opt-in `protect` mode for pre-execute allow, warn, DSH-native approval, and block.
- Fail-closed unexpected evaluator errors by default, with an explicit compatibility override.
- Bounded local audit and input-redacted summaries.
- Real DSH lifecycle, approval, nesting, concurrency, failure, disposal, packaging, update, removal, and Web startup tests.

## Installation posture

The packaged `dsh.cordis.patch.yml` remains on `observe`. This avoids turning an ordinary plugin update into an unexpected behavior-changing policy rollout.

To confirm protection in a profile, add this complete config override to that profile's `cordis.patch.yml`:

```yaml
- id: agentguard-dsh-plugin
  config:
    runtime:
      mode: protect
      failureMode: deny
```

DSH profile patches replace the row's entire `config`, so both runtime fields are restated. Removing the override returns the bundle to its packaged `observe` configuration after recomposition/restart.

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
- Runtime policy is therefore action/tool based, not plugin-trust based.
- Post-response anomalies remain audit-only because DSH has no resumable post-result approval contract.
- npm artifact/source equivalence, marketplace reputation, team policy, badges, and cloud history remain later platform work; they are not prerequisites for this local complete candidate.

## Confirmation decision

Confirm this candidate if the following product contract is acceptable:

1. installation remains observation-first;
2. protection is explicit and fails closed on unexpected evaluator errors;
3. approval is owned by DSH rather than a duplicate AgentGuard queue;
4. pre-execute protection is real, while post-response enforcement is not overstated;
5. unattributed calls never receive plugin-specific trust automatically.
