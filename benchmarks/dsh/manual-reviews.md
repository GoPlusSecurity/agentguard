# Phase 1 RC manual source reviews

These reviews cover the exact commits in `real-world.manifest.json`. They validate what selected static findings mean in source; they do not certify the plugins as safe. Sensitive values are deliberately omitted.

## dsh-vision-router

- Artifact: `ysr666/dsh-vision-router@86268695b1fb537794b33d0fb5267ce64ddbb8ce`
- Static posture: CRITICAL repository / CRITICAL runtime / URGENT review.
- Confirmed behavior: `lib/update-check.js` contacts the configured npm registry for version metadata. `lib/self-update.js` can invoke the already-running DSH CLI to update `dsh-vision-router`; `index.js` exposes that operation through a settings-card endpoint.
- Trigger: startup performs a read-only version check. Mutation requires an update to exist and a POST carrying a process-local token returned by the same-origin update-check flow.
- Controls observed: profile-name validation, ownership verification of the active `@deepseek-ai/dsh` CLI entry, `execFile` argument arrays, `shell: false`, same-origin request checks, token rotation after success, and single-flight update execution.
- Residual risk: the update installs the registry's latest package rather than a reviewed immutable artifact. The plugin also takes over provider routing and exposes broad vision/file capabilities. A version pin alone does not neutralize a user-triggered self-update.
- Evidence nuance: the reported `DYNAMIC_CODE_EXECUTION` representative line is an `exec` alias and overlaps shell execution. The same nearby feature also creates a Worker with `eval: true`, so dynamic source execution exists, but future evidence should point to the precise construct.
- Verdict: confirmed expected-but-sensitive self-update and provider-routing capabilities. Keep CRITICAL/URGENT; use only in an isolated profile with update behavior understood.

## MisakaNet

- Artifact: `Ikalus1988/MisakaNet@90665bad188073cf995fd3ca4428273653f83b81`
- Static posture: CRITICAL repository / CRITICAL runtime / URGENT review.
- Confirmed behavior: notifier implementations POST structured operational data to caller-configured Discord, Slack, and Feishu webhook URLs. Token management reads the OS keyring and falls back to an owner-only plaintext file with an explicit warning. Numerous maintenance and integration paths execute subprocesses.
- Repository data: lesson material contains a live-looking Feishu webhook identifier and a shared-secret-like value from a historical configuration example. The repository security policy also documents an intentionally public, restricted registration PAT. Values are not repeated here; their revocation and rotation cannot be proven by static review.
- Controls observed: notifier URLs are configuration inputs rather than a hardcoded exfiltration destination; network calls use timeouts; keyring is preferred; plaintext fallback attempts mode `0600` and warns.
- Residual risk: this is a very large mixed-purpose repository, not a narrowly scoped DSH plugin artifact. Installing or trusting the repository as one unit exposes substantially more code and data than the Cordis integration alone. Public credential-like history should be removed or demonstrably revoked.
- Evidence nuance: the CRITICAL `WEBHOOK_EXFIL` representative match is a placeholder Discord URL in a module docstring, while the module's actual generic webhook POST capability is real. `hub/orchestrator/skill_indexer.py` calls a machine-learning model's `.eval()` mode; that is not Python's `eval()` and is a known `DYNAMIC_CODE_EXECUTION` false positive.
- Verdict: expert review remains appropriate because of real webhook, keyring, subprocess, and sensitive-history exposure. Individual critical evidence lines include false positives and must not be treated as proof of malicious intent.

## dsh-open-in-vscode

- Artifact: `omdsh-dev/dsh-open-in-vscode@149f21aed3d05d2b392206394c4a023e35d694c7`
- Static posture: HIGH repository / HIGH runtime / ELEVATED review.
- Confirmed behavior: `src/runtime.ts` launches a locally configured editor command with an argument array and a required absolute workspace path. The child is detached and uses no shell.
- Controls observed: strict remote invocation schema, absolute-path rejection, `spawn(executable, args)` rather than shell interpolation, and default command `code`.
- Residual risk: a local profile administrator may configure an arbitrary executable and arguments. That is expected host capability, but the plugin should not be installed where browser-accessible DSH endpoints are exposed to untrusted users.
- Evidence nuance: the generated `new Function` finding originates from bundled Schemastery dependency code, not first-party plugin source. The two large OBFUSCATION groups are generated Unicode locale data. Source maps make both origins reviewable but do not make the runtime bundle safe by definition.
- Verdict: HIGH is justified by intentional process launch. Dynamic-execution and obfuscation evidence are dependency/build context rather than suspicious first-party behavior.

## superdesign-skill control

- Artifact: `superdesigndev/superdesign-skill@dc60b43625426bdd1e88fe494739fd5ea27daedd`
- Static posture: HIGH repository / MEDIUM runtime / ELEVATED review.
- Confirmed behavior: `dsh/index.js` reads its packaged `SKILL.md` and registers a skill provider. It performs no network request, file write, subprocess launch, or lifecycle installation.
- Evidence nuance: the only SHELL_EXEC finding is an inert path example in skill reference documentation and is excluded from runtime surface.
- Verdict: the MEDIUM runtime result accurately reflects packaged file reading. This is the clean control for the RC benchmark.
