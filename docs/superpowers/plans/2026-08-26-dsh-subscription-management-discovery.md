# DSH Subscription Management and Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete DSH threat-feed management with status and transaction-safe unsubscribe tools, exact runtime exemptions, and DSH-aware self-check discovery.

**Architecture:** Keep system cron and the existing single saved DSH subscription as the authority. Add a read-only system-cron inspection seam, implement status/unsubscribe as native structural DSH tools over existing state and queue APIs, and isolate DSH filesystem enumeration in a discovery module consumed by the existing self-check engine.

**Tech Stack:** TypeScript 5.7, Node.js 18+ filesystem APIs, Node test runner, DSH `0.1.1-rc.2` structural tool execution context.

**Spec:** `docs/superpowers/specs/2026-08-25-dsh-threat-feed-subscription-design.md`

## Global Constraints

- Work directly in `/Users/jeff/Desktop/agentguard` on `feat/dsh-threat-feed-subscription`; do not create a worktree.
- Do not modify `/Users/jeff/Desktop/deepseek-harness`.
- Preserve the user-owned untracked `next-steps.txt`.
- Tool callers cannot supply an agent/session id; identity comes only from DSH ToolExecution.
- Unsubscribe removes cron first and retains subscription state and queued notifications when cron removal is not confirmed.
- Status never returns advisory bodies, local matched paths, credentials, or Cloud remediation.
- DSH discovery respects `DSH_HOME`, bounds enumeration to direct profile dependencies, and never recursively walks an entire profile dependency tree.
- All new production behavior follows RED-GREEN-REFACTOR.

---

### Task 1: Read-only system cron status and reliable removal failure semantics

**Files:**
- Modify: `src/feed/cron.ts`
- Modify: `src/tests/feed-cron.test.ts`

**Interfaces:**
- Produces: `SystemThreatFeedCronStatus` and `inspectSystemThreatFeedCron(options, adapters?)`.
- Changes: `removeThreatFeedCron({ backend: 'system' })` reports an error when `crontab -l` is unavailable, while treating the platform's explicit “no crontab for user” result as confirmed absence.

- [ ] **Step 1: Write failing cron inspection and removal tests**

Add tests with injected `CommandRunner` values that assert an exact managed marker is reported installed, an empty table is reported absent, a `no crontab for user` error is confirmed absent, and an unrelated `crontab -l` failure returns `error` instead of silently claiming absence.

```ts
const status = await inspectSystemThreatFeedCron(
  { name: 'agentguard-threat-feed' },
  { runCommand: async () => ({ stdout: managedBlock, stderr: '' }) },
)
assert.equal(status.installed, true)
assert.equal(status.cronExpression, '0 * * * *')
```

- [ ] **Step 2: Verify RED**

Run `npm run build` and confirm compilation fails because `inspectSystemThreatFeedCron` is missing. Do not change production code before observing this failure.

- [ ] **Step 3: Implement inspection and distinguish absent/error reads**

Export:

```ts
export interface SystemThreatFeedCronStatus {
  name: string;
  installed: boolean;
  cronExpression?: string;
  error?: string;
}

export async function inspectSystemThreatFeedCron(
  options: { name: string },
  adapters: { runCommand?: CommandRunner } = {},
): Promise<SystemThreatFeedCronStatus>
```

Use exact `# AgentGuard begin <sanitized-name>` / end markers. Parse only the first five whitespace-delimited fields from the managed command line. Share one helper that classifies an explicit `no crontab for ...` error as absent and every other read failure as unknown/error. Make system removal return `{ removed: false, error }` for the latter without touching crontab.

- [ ] **Step 4: Verify GREEN and commit**

Run `npm run build` and `node --test dist/tests/feed-cron.test.js`, then commit:

```bash
git add src/feed/cron.ts src/tests/feed-cron.test.ts
git commit -m "fix: make system cron status failures explicit"
```

---

### Task 2: Native DSH subscription status tool

**Files:**
- Modify: `src/dsh/plugin.ts`
- Modify: `src/tests/dsh-plugin.test.ts`
- Modify: `scripts/test-dsh-package.mjs`

**Interfaces:**
- Produces: `createAgentGuardDshSubscriptionStatusTool(dependencies?)` registered as `agentguard_dsh_subscription_status`.
- Consumes: saved subscription loader, exact ToolExecution agent id, queue listing, and Task 1 cron inspection.

- [ ] **Step 1: Write failing status tests**

Assert no-subscription output, active subscription output, current-agent target comparison, exact pending count/latest timestamp, cron-installed status, and absence of queued `body` text or matched local paths.

```ts
assert.equal(result.subscribed, true)
assert.equal(result.subscriptionId, 'sub-1')
assert.equal(result.targetAgentId, 'agent-1')
assert.equal(result.currentAgentIsTarget, true)
assert.equal(result.cronExpression, '0 * * * *')
assert.equal(result.selfCheck, false)
assert.equal(result.cronInstalled, true)
assert.equal(result.pendingNotifications, 2)
assert.equal(result.latestQueuedAt, '2026-08-26T02:00:00.000Z')
assert.match(result.modelSummary, /2 queued/i)
```

- [ ] **Step 2: Verify RED**

Run the named plugin test and confirm the missing factory/tool registration causes failure.

- [ ] **Step 3: Implement the status tool**

Define a bounded discriminated result with `subscribed`, `currentAgentIsTarget`, `cronInstalled`, `pendingNotifications`, optional subscription fields and `latestQueuedAt`, plus a safe `modelSummary`. When there is a subscription, list only its exact `subscriptionId`/`agentId` notifications. Never include queue notice objects in the result.

- [ ] **Step 4: Register and verify GREEN**

Register the tool in `apply()`, update the expected tool order, and extend package smoke to require the exact tool name. Run build plus `dsh-plugin.test.js`.

---

### Task 3: Transaction-safe native unsubscribe and exact exemptions

**Files:**
- Modify: `src/dsh/plugin.ts`
- Modify: `src/dsh/runtime.ts`
- Modify: `src/tests/dsh-plugin.test.ts`
- Modify: `src/tests/dsh-runtime.test.ts`
- Modify: `scripts/test-dsh-package.mjs`

**Interfaces:**
- Produces: `createAgentGuardDshUnsubscribeTool(dependencies?)` registered as `agentguard_dsh_unsubscribe`.
- Result: `unsubscribed`, `cronRemoved`, `pendingNotificationsRemoved`, and bounded `modelSummary`.

- [ ] **Step 1: Write failing unsubscribe tests**

Cover idempotent no-state behavior, rejection when the current ToolExecution agent is not the saved target, successful cron→queue→state ordering, confirmed-absent cron cleanup, cron failure retaining state/queue, queue failure retaining state after cron removal, and safe output.

```ts
await assert.rejects(
  () => tool.execute({}, { agent: { id: 'other-agent' } }),
  /only the subscribed DSH session/i,
)
assert.deepEqual(order, ['cron', 'list-queue', 'remove-queue', 'remove-state'])
```

- [ ] **Step 2: Verify RED**

Run the named plugin tests and confirm failure because the factory and registration do not exist.

- [ ] **Step 3: Implement the minimal transaction**

Load state and validate the exact calling agent. Remove the system cron first. Continue only when the result is `removed: true` or `removed: false` without `error` (confirmed absent). Then list/remove exact valid notification ids, and delete subscription state last. On any failure before state deletion, throw and leave the state so a retry remains possible.

- [ ] **Step 4: Add exact exemptions and package registration**

Add only these literal names to `AGENTGUARD_DSH_TOOLS`:

```ts
'agentguard_dsh_subscription_status',
'agentguard_dsh_unsubscribe',
```

Assert prefix-similar names remain non-exempt. Extend package smoke for unsubscribe registration.

- [ ] **Step 5: Verify GREEN and commit Tasks 2-3**

Run build, plugin/runtime tests, and package smoke. Commit:

```bash
git add src/dsh/plugin.ts src/dsh/runtime.ts src/tests/dsh-plugin.test.ts src/tests/dsh-runtime.test.ts scripts/test-dsh-package.mjs
git commit -m "feat: add DSH subscription management tools"
```

---

### Task 4: DSH-aware self-check discovery

**Files:**
- Create: `src/feed/dsh-discovery.ts`
- Create: `src/tests/dsh-discovery.test.ts`
- Modify: `src/feed/selfcheck.ts`
- Modify: `src/tests/feed-selfcheck.test.ts`

**Interfaces:**
- Produces: `discoverDshSelfCheckRoots(options?)` returning `skillRoots`, `pluginRoots`, `supplyChainPaths`, and `urlScanPaths`.
- Consumes: `DSH_HOME` or `~/.dsh`, current working directory, profile manifests, profile direct dependencies, and Cordis patch files.

- [ ] **Step 1: Write failing discovery tests**

Build a temporary DSH tree with user and project skills, two profiles, scoped/unscoped direct dependencies, a transitive undeclared package, and Cordis patches. Assert the result includes:

```text
$DSH_HOME/skills
<cwd>/.dsh/skills
$DSH_HOME/profiles/*/package.json
$DSH_HOME/profiles/*/node_modules/<direct-dependency>
$DSH_HOME/cordis.patch.{yml,yaml}
$DSH_HOME/profiles/*/cordis.patch.{yml,yaml}
```

Assert it excludes undeclared transitive packages and rejects dependency names that escape `node_modules`.

- [ ] **Step 2: Verify RED**

Run build and confirm the new module import fails.

- [ ] **Step 3: Implement bounded discovery**

Resolve `DSH_HOME` at call time, enumerate only immediate profile directories, parse only object-shaped `dependencies` and `optionalDependencies`, validate npm package names, and add only existing files/directories. Sort and deduplicate every returned list. Never recursively enumerate `node_modules`.

- [ ] **Step 4: Integrate dynamic DSH defaults into self-check**

When a caller does not override a root family, merge current generic defaults with discovered DSH roots inside `listArtifactsForAdvisory()`. Preserve explicit `inspectPaths` precedence and existing `maxArtifacts` behavior. Add end-to-end matcher tests proving a skill, profile dependency manifest, profile manifest, and Cordis patch can be matched.

- [ ] **Step 5: Verify GREEN and commit**

Run build plus `dsh-discovery.test.js` and `feed-selfcheck.test.js`. Commit:

```bash
git add src/feed/dsh-discovery.ts src/feed/selfcheck.ts src/tests/dsh-discovery.test.ts src/tests/feed-selfcheck.test.ts
git commit -m "feat: discover DSH artifacts during feed self-check"
```

---

### Task 5: Documentation and complete verification

**Files:**
- Modify: `docs/dsh.md`
- Modify: `README.md`

- [ ] **Step 1: Update documentation**

Document both new tool names, status fields, exact-target unsubscribe restriction, transactional retry behavior, and the DSH discovery roots. Remove the statement that native status/unsubscribe are unavailable.

- [ ] **Step 2: Run focused verification**

Run:

```bash
npm run build
node --test dist/tests/feed-cron.test.js dist/tests/dsh-plugin.test.js dist/tests/dsh-runtime.test.js dist/tests/dsh-discovery.test.js dist/tests/feed-selfcheck.test.js
```

- [ ] **Step 3: Run full verification**

Run `npm test`, then:

```bash
env DSH_PACKAGE_BIN=/Users/jeff/.nvm/versions/node/v24.18.0/bin/dsh npm run test:dsh-package
```

- [ ] **Step 4: Inspect and commit**

Run `git diff --check`, confirm only `next-steps.txt` remains untracked, and commit:

```bash
git add README.md docs/dsh.md docs/superpowers/plans/2026-08-26-dsh-subscription-management-discovery.md
git commit -m "docs: complete DSH subscription operations guide"
```
