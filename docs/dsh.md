# AgentGuard for DeepSeek Harness plugins

AgentGuard for DeepSeek Harness (DSH) is an installation-time trust layer for the DSH plugin ecosystem. It identifies DSH bundles, profiles, client extensions, and Cordis configuration, then combines that context with AgentGuard's existing static rules to produce an explainable security report.

Phase 1 is intentionally read-only: it scans source, classifies capabilities, and recommends an installation posture. It never installs the target, executes package lifecycle scripts, evaluates Cordis `!!js` expressions, or starts DSH.

## Why this exists

DSH treats tools, providers, UI extensions, workflow components, and runtime behavior as plugins. That extensibility means a package presented as a theme can still read credentials, spawn a shell, replace a model provider, or intercept the tool pipeline. Generic JavaScript scanning catches some of those operations but cannot explain where they affect a composed DSH runtime.

The DSH scanner adds three pieces of context:

1. **Identity:** whether the artifact is a DSH bundle, profile, client extension, or related Cordis project.
2. **Effective capability:** the filesystem, network, shell, provider, UI, session, tool-registry, and runtime surfaces visible in static source.
3. **Composition impact:** which DSH layers the artifact can influence and whether a Cordis patch inserts a new row or replaces an existing one.

The result is designed to answer an installation decision, not to certify that code is safe.

## Scope

Phase 1 includes:

- Local directory scans.
- HTTPS GitHub repository scans.
- DSH manifest and Cordis YAML detection.
- Static capability and impact-layer classification.
- Explainable low, medium, high, and critical risk levels.
- JSON, Markdown, and self-contained HTML reports.
- A stable JSON report shape with `schemaVersion: 1`.

Phase 1 does not include:

- Installing a plugin or resolving its lifecycle scripts.
- Fetching a package by npm name or comparing an npm tarball with its source repository.
- Resolving every layer of an already-installed DSH profile into one effective runtime tree.
- Observing runtime calls or enforcing allow, warn, approve, or block decisions.
- Persisting scan history or integrating with a DSH marketplace.

## Command line

```bash
agentguard dsh-scan <local-directory-or-github-url> [options]
```

Supported inputs:

- A local plugin, bundle, or profile directory.
- An HTTPS GitHub URL in `https://github.com/owner/repository`, `https://github.com/owner/repository.git`, or either form with one trailing slash.

Options:

| Option | Default | Description |
|---|---|---|
| `-f, --format <format>` | `markdown` | Select `json`, `markdown`, or `html`. |
| `-o, --output <path>` | stdout | Write the selected report to a file. |

Examples:

```bash
# Human-readable terminal report
agentguard dsh-scan ./plugins/example

# Stable machine-readable output
agentguard dsh-scan ./plugins/example --format json

# Audit a repository's current default branch
agentguard dsh-scan https://github.com/owner/dsh-plugin --format json

# Produce a portable review artifact
agentguard dsh-scan ./plugins/example --format html --output dsh-report.html
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Scan completed and the result is low, medium, or high risk. |
| `2` | Scan completed with a critical-risk result. |
| Other non-zero | Input validation, clone, read, parse, or output failure. |

High risk deliberately remains exit code 0 in Phase 1 because it often describes the expected power of a tool or provider plugin. Automation should read `riskLevel` and `installRecommendation` from JSON when its policy needs a stricter gate.

## Programmatic API

The package exports the scanner and its supporting types:

```ts
import {
  scanDshPlugin,
  renderDshHtml,
  renderDshMarkdown,
  type DshPluginScanReport,
} from '@goplus/agentguard';

const report: DshPluginScanReport = await scanDshPlugin('./plugin');

if (report.riskLevel === 'critical') {
  throw new Error(report.summary);
}

const markdown = renderDshMarkdown(report);
const html = renderDshHtml(report);
```

Lower-level exports are available for consumers that need only one stage: `detectDshPlugin`, `parseDshPackage`, `parseCordisConfigs`, `buildCapabilityProfile`, `classifyDshPlugin`, and `classifyImpactLayers`.

## How scanning works

```text
local directory or HTTPS GitHub repository
                    |
                    v
             source resolver
                    |
                    v
       manifest + Cordis safe parsing
                    |
                    v
       AgentGuard and DSH static rules
                    |
                    v
     capability + impact classification
                    |
                    v
       risk and install recommendation
                    |
                    v
          JSON / Markdown / HTML
```

### 1. Source resolution

Local inputs are resolved to an absolute directory. GitHub inputs are shallow-cloned into a temporary directory with these constraints:

- Resolve the default branch HEAD first, then fetch and check out that exact commit at depth 1.
- Submodules are not initialized.
- Repository hooks are disabled for the clone operation.
- The temporary checkout is removed after scanning, including after failures.
- The checkout is verified against the pre-resolved HEAD, and the report records that commit and its commit time.

Other HTTP sources are rejected in Phase 1.

### 2. DSH detection

Detection uses multiple weighted signals rather than trusting a name:

- `package.json` fields under `dsh.bundle.patch`, `dsh.profile.bundles`, and `dsh.client`.
- `cordis.yml`, `cordis.yaml`, `cordis.patch.yml`, and `cordis.patch.yaml`.
- Dependencies on `@deepseek-ai/dsh-*` or `@deepseek-ai/cordis`.
- DSH APIs such as `ctx.tools.register()`, `ctx.tools.guard()`, and `tools/pre-execute`.
- Documentation that explicitly identifies the project as DSH-related.

The report exposes every matched signal and a confidence value of `none`, `low`, `medium`, or `high`.

### 3. Manifest and Cordis parsing

Only the DSH-owned portion of `package.json` is retained. Package code is never imported.

Cordis YAML is parsed with the YAML core schema and an explicit scalar resolver that preserves `!!js` expressions as inert strings. Expressions such as `!!js process.env.KEY` are never evaluated, while ordinary booleans and numbers retain their YAML core types. The parser distinguishes:

- `entry`: a normal row in a base Cordis document.
- `insert`: a row introduced through an `insert` patch.
- `replace`: an existing row targeted by a patch document or nested patch list.

This distinction prevents a new helper row named `tool-helper` from being reported as a replacement of DSH's core tool configuration.

### 4. Static rules

The artifact is scanned with AgentGuard's existing security rules plus DSH-specific rules:

| Rule | Severity | Meaning |
|---|---|---|
| `INSTALL_SCRIPT` | High | `preinstall`, `postinstall`, or `prepare` can execute during installation. |
| `NETWORK_ACCESS` | Medium | Source can make outbound requests. |
| `FILE_READ_ACCESS` | Medium | Source can read files or enumerate directories. |
| `FILE_WRITE_ACCESS` | High | Source can write, move, or remove files. |
| `DSH_PATCH_OVERRIDE` | High | A parsed Cordis patch replaces a security-relevant core row. |
| `DSH_TOOL_REGISTRY_MUTATION` | High | Source registers, restricts, guards, or intercepts tools. |
| `DSH_PROVIDER_MUTATION` | High | Source changes model, provider, or credential routing. |
| `DSH_RUNTIME_MUTATION` | High | Source intercepts agent, prompt, or runtime lifecycle behavior. |
| `DSH_SESSION_STORAGE_ACCESS` | Medium | Source accesses sessions, settings, credentials, or persistence. |
| `DSH_THEME_ELEVATED_CAPABILITY` | High | A benign-looking UI, theme, skin, or pet also requests elevated capabilities. |

All shipped paths participate in risk calculation, including test-like and fixture paths. Published packages can place executable behavior anywhere, so directory names are not treated as a security boundary.

### 5. Capability profile

Every report includes booleans for:

- File read and file write.
- Network access.
- Shell execution.
- Environment-variable access.
- Provider/model access.
- UI injection.
- Session and storage access.
- Tool-registry mutation.
- Runtime mutation.

These fields are evidence-based static inferences. `false` means the current rules did not detect the capability, not that the capability is impossible.

### 6. Impact layers

Capabilities and Cordis rows are mapped to DSH-facing impact layers:

| Layer | Examples |
|---|---|
| `ui` | Web client injection, themes, conversation UI. |
| `tool-registry` | Tool registration, guards, execution hooks. |
| `workflow` | Workflow or automation components. |
| `models-providers` | LLM providers, model routing, credentials. |
| `session-storage` | Sessions, settings, persistence, storage. |
| `runtime-core` | Bundles, profiles, agent loop, loader, core replacements. |

## Risk model

Risk is derived from visible rule severity and explicit compound conditions; there is no opaque model score.

| Risk | Typical meaning | Default recommendation |
|---|---|---|
| Low | No security-relevant capability was detected. | `safe-to-try` |
| Medium | Network, environment, file-read, or session access was detected. | `test-in-isolated-profile` |
| High | Shell execution, file writes, core replacement, tool interception, provider changes, or runtime mutation was detected. | `sandbox-only` or `avoid-on-primary-machine` |
| Critical | A critical base rule matched, or an install script combines executable loading with environment, network, or obfuscation signals. | `expert-review-required` |

Recommendations are deliberately conservative:

- High risk with shell execution or file writes becomes `avoid-on-primary-machine`.
- Other high-risk behavior becomes `sandbox-only`.
- A theme, skin, wallpaper, mascot, desktop companion, or pet that also performs network, environment, file-write, shell, or runtime operations receives a separate harmless-purpose mismatch finding.

Expected capability does not mean safe capability. For example, a plugin-discovery tool will normally register a tool and access the network; the report should still expose both facts so the operator can constrain where it runs.

## JSON report contract

The top-level report is `DshPluginScanReport`:

| Field | Purpose |
|---|---|
| `schemaVersion` | Report contract version; currently `1`. |
| `identity` | Package name, version, repository, hash, and inferred plugin kind. |
| `detection` | DSH decision, confidence, and matched signals. |
| `riskLevel` | `low`, `medium`, `high`, or `critical`. |
| `riskTags` | Deduplicated security rule identifiers. |
| `capabilityProfile` | Static effective-capability booleans. |
| `impactLayers` | DSH runtime areas the artifact can influence. |
| `findings` | Rule, severity, file, line, explanation, and matched snippet. |
| `installRecommendation` | Suggested isolation or review posture. |
| `summary` | Short human-readable decision summary. |
| `harmlessMismatch` | Whether a benign UI label conflicts with elevated behavior. |
| `source` | Original input, source kind, resolved reference, revision, and commit time. |
| `project` | Description, repository metadata, DSH manifest signals, and informational README install-documentation presence. `hasReadmeInstallInstructions` never affects risk or recommendations. |
| `diagnostics` | Non-fatal package-manifest and Cordis parse errors. |

The artifact hash is computed from the scanned files. Consumers should use it with the source revision when recording an approval because a repository name or package version alone does not identify immutable content.

## Resource and execution safety

The scanner treats its input as untrusted:

- No package or configuration code is evaluated.
- Cordis `!!js` tags are inert.
- No package manager is invoked.
- GitHub clones do not initialize submodules or run repository hooks.
- Individual scan files are limited to 2 MiB.
- A scan considers at most 10,000 matching files.
- Cordis ASTs are limited to 20,000 nodes and 64 levels, and only required map/sequence fields are read without materializing the document through `toJS()`.
- Common dependency, build, VCS, coverage, lockfile, and binary paths are skipped.
- HTML report values are escaped before rendering.

Limit warnings and Cordis parse failures matter: skipped or unparsed content may hide behavior and should trigger manual review even when the calculated risk is low.

## Recommended review workflow

1. Scan the exact artifact you intend to install. Prefer a pinned local checkout over an unpinned default branch.
2. Review `installRecommendation`, not only the risk color.
3. Confirm that every detected capability is necessary for the advertised purpose.
4. Inspect lifecycle scripts and every high or critical finding.
5. Compare the package-manager tarball with the reviewed repository when installing from a registry.
6. Install medium- or high-capability plugins in a separate DSH home/profile first.
7. Re-scan after updates and record the new artifact hash.

## Development and tests

```bash
npm install
npm run build
npm test
```

Focused coverage lives in `src/tests/dsh.test.ts` and verifies:

- Bundle, profile, client, and Cordis detection.
- Safe handling of `!!js` YAML values.
- Insert-versus-replace interpretation.
- Oversized Cordis rejection.
- Low-risk UI themes.
- Critical escalation for deceptive themes.
- Tool, file-write, provider, and credential classification.
- Inclusion of dangerous behavior under test-like paths in install recommendations.
- Markdown output and HTML escaping.

Before submission, also run:

```bash
git diff --check
```

## Compatibility and change policy

DSH is a developer preview and its manifest or Cordis conventions may change. DSH-specific parsing and classification live under `src/dsh/`, rules live under `src/scanner/rules/dsh/`, and report rendering lives under `src/reports/`. This separation lets DSH compatibility evolve without coupling generic AgentGuard rules to one plugin framework.

Changes that alter JSON field meaning or remove a field require a report schema version change. Adding a new optional finding, capability inference, or impact classification can remain within schema version 1 when existing consumers continue to parse the report safely.

## Known limitations

- Static analysis cannot prove that a plugin is safe.
- Computed property access, native code, packed binaries, generated source, and runtime-downloaded behavior can evade pattern matching.
- GitHub scans follow the current default branch; they do not accept a tag, branch, pull request, or commit selector in Phase 1.
- Repository scanning does not prove that an npm package with the same name contains the same files.
- The scanner does not resolve transitive dependencies into the plugin's capability profile.
- The current scanner reports a plugin in isolation rather than the final composed profile and every interaction between bundles.
- Runtime enforcement and source-plugin attribution are deferred to Phase 2.

## Phase 2 direction

Phase 2 can build on the report contract to add runtime attribution and policy enforcement:

- Attribute a runtime action to the DSH package or Cordis row that initiated it.
- Compare observed behavior with the installation-time capability profile.
- Apply allow, warn, approve, or block decisions per plugin and capability.
- Detect profile composition changes and require re-approval when the effective artifact hash changes.

Those controls are not implied by the Phase 1 command. Phase 1 remains a static, installation-time decision aid.
