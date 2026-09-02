# AgentGuard for DSH `phase1-rc3` Targeted Acceptance Report

- **Test time**: 2026-08-19 03:00–03:05 (JST)
- **Git HEAD**: `557f73a` (includes the `2337e26` fail-closed fix, the `bf64fdd` baseline freeze, and the acceptance-test documentation commit)
- **scannerVersion**: `1.1.29-beta.0`
- **phase**: `phase1-rc3`
- **rulesBaseline**: `2337e266cf78f82e8d07f5555f7cc760b6ddc830`
- **Initial runtime mode**: `protect`
- **Final runtime mode**: `protect`
- **Overall result**: **PASS**

| Test case | Result | Key structured evidence | Difference from expected |
|---|---|---|---|
| UAT-RC3-01 Version and complete scan | PASS | All four tools available; scanner reported AgentGuard for DSH `1.1.29-beta.0` / `phase1-rc3` / baseline `2337e266...`; safe-theme coverage `{3,3,0,complete:true}`; LOW / safe-to-try / routine | None |
| UAT-RC3-02 Oversized-file fail-closed behavior | PASS | `lib/client.js` was 2,726,803 bytes; coverage `{15,14,1,complete:false}`; `oversized:1`; included `DSH_SCAN_INCOMPLETE`; repository/runtime/review were all high; expert-review-required; no safe-to-try result | None |
| UAT-RC3-03 Batch propagation | PASS | total 2 / succeeded 2 / failed 0 / incomplete 1; riskCounts low 1 + high 1; summary explicitly reported one incomplete scan | None |
| UAT-RC3-04 Protect-mode visibility | PASS | `configuredMode: protect`; `preExecuteProtectionActive: true`; `configuredPostResponseMode: block-malicious`; summary explicitly stated that pre-execute enforcement was active | None |
| UAT-RC3-05 Observe mode and recovery | PASS | In observe mode, `configuredMode: observe` and `preExecuteProtectionActive: false`; summary explicitly stated evaluation and auditing only; protect enforcement was active again after recovery | None |
| UAT-RC3-06 Final stable state | PASS | HTTP 200; configuration and summary both restored to protect; no residual changes; no scan target installed or executed | None |

## Scan Coverage Evidence

- safe-theme: discovered 3 / scanned 3 / skipped 0 / complete `true`
- dsh-deep-whale: discovered 15 / scanned 14 / skipped 1 / complete `false`
- skippedByReason: fileLimit 0 / oversized 1 / unreadable 0
- `DSH_SCAN_INCOMPLETE`: present
- Final repository/runtime risk for the incomplete target: high / high
- Final recommendation for the incomplete target: expert-review-required

## Runtime-State Visibility Evidence

- protect: `configuredMode: protect` / `preExecuteProtectionActive: true` / `configuredPostResponseMode: block-malicious`
- observe: `configuredMode: observe` / `preExecuteProtectionActive: false` / `configuredPostResponseMode: block-malicious`
- after recovery: `configuredMode: protect` / `preExecuteProtectionActive: true` / HTTP 200

## Issues and Recommendations

1. Both targeted acceptance goals were met: incomplete scans fail closed, and the current observe/protect state is clearly visible.
2. Non-blocking observation: the observe-mode `modelSummary` did not repeat the post-response mode, but the structured `configuredPostResponseMode` field correctly returned `block-malicious`; the configuration remained unchanged throughout.
3. `launchctl kickstart` briefly interrupts the current DSH session, which is expected when restarting the local service.

## Conclusion

All six `phase1-rc3` targeted acceptance tests passed. The final state was restored to protect, so the change can proceed to maintainer review and merge.
