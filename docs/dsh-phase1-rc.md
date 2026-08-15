# AgentGuard for DSH Phase 1 release candidate

## Frozen boundary

Phase 1 is a read-only, installation-time static decision aid. It detects DSH manifests and Cordis composition, reports full-repository and runtime-surface risk, and exposes the scanner through the native `agentguard_dsh_scan` tool. It does not intercept or block DSH runtime actions.

Risk-rule semantics are frozen at commit `83db977a566d8a853568a2d2903b142106d80196` for the `phase1-rc1` evaluation baseline. Stabilization changes may improve tests, benchmark infrastructure, documentation, packaging, or confirmed security defects. They must not silently retune risk outcomes to fit one new plugin.

## Acceptance gates

Before merging or releasing the RC:

1. `npm run build` succeeds.
2. `npm test` passes the complete unit/integration suite.
3. `npm run test:dsh-e2e` composes the installed profile, boots DSH, and invokes the scanner.
4. `npm run benchmark:dsh` matches all exact-commit real-world snapshots.
5. `git diff --check` reports no whitespace errors.
6. Every new or removed HIGH/CRITICAL runtime tag has a written human-review explanation.
7. The PR documents the Phase 1 boundary and known limitations.

The real-world benchmark requires GitHub network access. The synthetic labeled corpus remains part of the normal offline test suite.

## Frozen reference set

The versioned manifest and snapshot live under `benchmarks/dsh/`. The initial set deliberately spans LOW through CRITICAL runtime postures and includes generated bundles, active instructions, provider routing, self-update behavior, webhook capability, and credential access.

The benchmark is not a popularity ranking. Repository stars, names, and default branches are not security inputs; only the pinned commit and artifact hash identify the reviewed sample.

## Known evidence qualifications

- Generated code remains runtime-relevant even when source maps exist.
- Aggregated counts improve readability but do not increase or decrease severity.
- Pattern matches can still confuse method names with dangerous language primitives, such as a machine-learning model's `.eval()` method.
- Example webhook URLs can demonstrate a real capability while not being a live destination.
- Static scanning cannot prove whether credential-like values have been revoked.

These qualifications belong in manual review, not in silent post-processing that hides evidence.
