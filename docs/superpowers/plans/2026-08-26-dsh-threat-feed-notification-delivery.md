# DSH Threat-Feed Notification Delivery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist notification-worthy DSH cron pull results and deliver them as one safe follow-up to the exact subscribed DSH agent when it is live and idle.

**Architecture:** The existing system cron remains the poller and atomically publishes bounded immutable JSON notices under the AgentGuard home before feed seen-state advances. The DSH plugin consumes exact subscription/agent matches through the public Agent registry and `Agent.runMaintenance()`/`Agent.followup()` lifecycle, retaining files across downtime or delivery failure.

**Tech Stack:** TypeScript 5.7, Node.js 18+ filesystem/crypto APIs, Node test runner, DSH `0.1.1-rc.2` structural runtime interfaces, Cordis plugin lifecycle.

**Spec:** `docs/superpowers/specs/2026-08-26-dsh-threat-feed-notification-delivery-design.md`

## Global Constraints

- Do not modify `/Users/jeff/Desktop/deepseek-harness`.
- Do not add runtime dependencies on unpublished DSH internals; use structural interfaces matching DSH `0.1.1-rc.2` public Agent APIs.
- Keep the existing `agentguard_dsh_subscribe` input and output schema unchanged.
- Do not add status/unsubscribe tools, multi-session fan-out, automatic scans, remediation execution, or expanded artifact discovery.
- Queue directories use mode `0700`; queue files use mode `0600` and are atomically published without exposing partial JSON.
- Advisory remediation, details markdown, references, URL query strings, credentials, and complete local paths must not enter the DSH queue or follow-up.
- Only exact saved `subscriptionId` and `agentId` matches are deliverable.
- Preserve OpenClaw, QClaw, Hermes, interactive subscribe, and non-DSH system-cron behavior.
- Preserve the user-owned untracked `next-steps.txt` file.

---

### Task 1: Durable bounded DSH notification queue

**Files:**
- Create: `src/feed/dsh-notifications.ts`
- Create: `src/tests/dsh-notifications.test.ts`
- Modify: `docs/superpowers/specs/2026-08-26-dsh-threat-feed-notification-delivery-design.md`

**Interfaces:**
- Consumes: `DshThreatFeedSubscription`, `Advisory`, and `SelfCheckResult`.
- Produces: `DshThreatFeedNotification`, `QueuedDshThreatFeedNotification`, `buildDshThreatFeedNotification(options)`, `enqueueDshThreatFeedNotification(notification, home)`, `listDshThreatFeedNotifications(options, home)`, `removeDshThreatFeedNotifications(noticeIds, home)`, and `buildDshThreatFeedFollowup(notifications)`.

- [ ] **Step 1: Write the failing queue and safe-payload tests**

Add Node tests that import the wished-for API and assert:

```ts
const notice = buildDshThreatFeedNotification({
  subscription: existingSubscription(),
  freshAdvisories: [{
    id: 'AGS-1', ecosystem: 'plugin', severity: 'critical', summary: 'Bad plugin',
    detailsMd: 'secret details', affected: [], publishedAt: '2026-08-26T00:00:00.000Z',
    references: ['https://example.test/?token=secret'],
    selfCheck: { matchers: [], remediationMd: 'run rm -rf /' },
  }],
  results: [],
  selfCheck: false,
  now: '2026-08-26T01:00:00.000Z',
})
assert.ok(notice)
assert.match(notice.body, /AGS-1.*critical.*Bad plugin/i)
assert.doesNotMatch(JSON.stringify(notice), /secret details|token=secret|rm -rf/)
```

Also assert deterministic notice ids across different `now` values, match-mode bodies omit paths but include advisory id/count/matcher kinds, duplicate enqueue returns `created: false`, directory/file modes are `0700`/`0600`, listing filters exact subscription and agent ids, malformed files and symlinks are retained and reported, sorting is deterministic, removal accepts validated notice ids only, and follow-up framing is bounded to 20 notices/24,000 characters with the untrusted-data instruction.

- [ ] **Step 2: Build and run the new test to verify RED**

Run:

```bash
npm run build
node --test dist/tests/dsh-notifications.test.js
```

Expected: TypeScript compilation fails because `../feed/dsh-notifications.js` and its exports do not exist.

- [ ] **Step 3: Implement the minimal queue domain**

Create these exact public shapes:

```ts
export interface DshThreatFeedNotification {
  version: 1;
  noticeId: string;
  subscriptionId: string;
  agentId: string;
  kind: 'new-advisories' | 'self-check-matches';
  createdAt: string;
  title: string;
  body: string;
}

export interface QueuedDshThreatFeedNotification {
  notification: DshThreatFeedNotification;
}

export interface DshThreatFeedFollowup {
  noticeIds: string[];
  text: string;
}

export interface BuildDshThreatFeedNotificationOptions {
  subscription: DshThreatFeedSubscription;
  freshAdvisories: Advisory[];
  results: SelfCheckResult[];
  selfCheck: boolean;
  now?: string;
}

export interface ListDshThreatFeedNotificationsOptions {
  subscriptionId: string;
  agentId: string;
  limit?: number;
  onWarning?: (message: string) => void;
}
```

Use SHA-256 of a canonical JSON identity containing version, subscription id, agent id, kind, and sorted advisory/result identities. Build a separate safe body formatter; do not call the existing remediation-bearing manual formatter. Write to a same-directory `0600` temporary file and atomically publish without overwriting an existing final file (exclusive hard-link publication is acceptable); always clean the temporary file. Open queue files with `O_NOFOLLOW`, validate every field and bound, and construct removal paths only from `/^[a-f0-9]{64}$/` notice ids.

- [ ] **Step 4: Rebuild and verify GREEN**

Run:

```bash
npm run build
node --test dist/tests/dsh-notifications.test.js
```

Expected: all DSH notification queue tests pass.

- [ ] **Step 5: Refactor and keep the focused suite green**

Extract repeated validators/canonicalizers only inside `src/feed/dsh-notifications.ts`; rerun the Task 1 command and `git diff --check`.

- [ ] **Step 6: Commit the queue unit**

```bash
git add src/feed/dsh-notifications.ts src/tests/dsh-notifications.test.ts docs/superpowers/specs/2026-08-26-dsh-threat-feed-notification-delivery-design.md
git commit -m "feat: add durable DSH threat feed notification queue"
```

---

### Task 2: Enqueue DSH cron notifications before feed state advances

**Files:**
- Modify: `src/cli.ts`
- Modify: `src/tests/cli-subscribe.test.ts`

**Interfaces:**
- Consumes: Task 1 `buildDshThreatFeedNotification()` and `enqueueDshThreatFeedNotification()`, plus existing `loadDshThreatFeedSubscription()`.
- Produces: DSH internal cron behavior where a notification is durable before `saveFeedState()` records the same advisory ids as seen.

- [ ] **Step 1: Add failing CLI integration tests**

Extend the existing mocked Cloud subscribe suite with an initialized DSH config and saved subscription. Spawn:

```ts
await execFileAsync(process.execPath, [cliPath, 'subscribe', '--json', '--cron-run'], {
  env: { ...process.env, AGENTGUARD_HOME: home },
})
```

Assert a new advisory creates one queue file containing the exact subscription/agent ids, then assert the feed state contains that advisory id. Add cases proving no queue file for no new advisories, no DSH subscription, interactive runs, and non-DSH hosts. Add an enqueue-failure fixture (queue path is a regular file) and assert the command rejects while feed state does not mark the advisory seen.

- [ ] **Step 2: Build and verify RED**

Run:

```bash
npm run build
node --test --test-name-pattern='DSH cron notification' dist/tests/cli-subscribe.test.js
```

Expected: the positive test fails because no DSH notification file is created; the failure-order test shows current feed state advances without a queue publication attempt.

- [ ] **Step 3: Add the minimal CLI production hook**

After `buildSubscribeSummary()` and before the general `pendingStateEntry` save, add a DSH-only internal-cron branch equivalent to:

```ts
if (cronInternalRun && cronAgentHost === 'dsh' && summary.shouldNotify) {
  const subscription = await loadDshThreatFeedSubscription(getAgentGuardPaths().home);
  if (!subscription) throw new Error('DSH threat-feed subscription state is missing.');
  if (subscription.selfCheck !== quiet) {
    throw new Error('DSH threat-feed subscription mode does not match the cron runner.');
  }
  const notice = buildDshThreatFeedNotification({
    subscription, freshAdvisories: fresh, results, selfCheck: quiet,
  });
  if (notice) await enqueueDshThreatFeedNotification(notice, getAgentGuardPaths().home);
}
```

Keep this branch after the OpenClaw early-return path and before `saveFeedState()`. Do not change manual output or notification formatters used by other hosts.

- [ ] **Step 4: Rebuild and verify GREEN**

Run:

```bash
npm run build
node --test --test-name-pattern='DSH cron notification' dist/tests/cli-subscribe.test.js
node --test dist/tests/cli-subscribe.test.js dist/tests/feed-cron.test.js
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit the CLI ordering unit**

```bash
git add src/cli.ts src/tests/cli-subscribe.test.ts
git commit -m "feat: enqueue DSH feed notifications from cron"
```

---

### Task 3: Deliver queued notices to the exact live DSH agent

**Files:**
- Create: `src/dsh/notification-delivery.ts`
- Create: `src/tests/dsh-notification-delivery.test.ts`
- Modify: `src/dsh/plugin.ts`
- Modify: `src/tests/dsh-plugin.test.ts`

**Interfaces:**
- Consumes: Task 1 queue list/remove/follow-up functions and existing subscription loader.
- Produces: `installDshThreatFeedNotificationDelivery(ctx, dependencies?)`, structural `DshNotificationAgent`, and plugin lifecycle registration with `inject = ['tools', 'agents']`.

- [ ] **Step 1: Add failing delivery-domain tests**

Use real temporary queue files plus small structural fake agents. Assert:

```ts
const target = fakeAgent('dsh-agent-1')
const other = fakeAgent('dsh-agent-2')
installDshThreatFeedNotificationDelivery(fakeContext([target, other]), {
  agentGuardHome: () => home,
})
await eventually(() => target.followups.length === 1)
assert.equal(other.followups.length, 0)
assert.match(target.followups[0].content[0].text, /untrusted threat intelligence data/i)
assert.equal((await listDshThreatFeedNotifications(match, home)).length, 0)
```

Add separate tests for already-live activation, later `agent/created`, busy `runMaintenance()` rejection followed by `agent/status: idle`, concurrent triggers coalescing to one follow-up, followup failure retaining files, mismatched subscription/agent isolation, batching at 20, and listener teardown preventing later delivery.

- [ ] **Step 2: Build and verify RED**

Run:

```bash
npm run build
node --test dist/tests/dsh-notification-delivery.test.js
```

Expected: compilation fails because `notification-delivery.ts` does not exist.

- [ ] **Step 3: Implement the delivery coordinator**

Define structural DSH shapes without importing DSH runtime packages:

```ts
export interface DshNotificationAgent {
  id: unknown;
  status?: unknown;
  runMaintenance<T>(task: (signal: AbortSignal) => Promise<T>): Promise<T>;
  followup(message: {
    id: string; role: 'user'; content: Array<{ type: 'text'; text: string }>;
    source: { kind: 'plugin'; plugin: 'agentguard' };
  }): void;
}
```

The installer tracks one in-flight promise per normalized agent id, reads the subscription both before scheduling and inside maintenance, lists exact matching notifications, builds one bounded follow-up, calls `followup()` synchronously, then removes only the selected notice ids. Catch busy/failure paths, retain files, and emit bounded warnings. Register global `agent/created` and `agent/status` listeners and inspect `ctx.agents.list()` at activation. Return an async disposer that disables new attempts, calls every listener disposer, and awaits all captured in-flight promises. Register that disposer through `ctx.effect()` from `apply()` so Cordis teardown drains delivery work.

- [ ] **Step 4: Rebuild and verify delivery GREEN**

Run:

```bash
npm run build
node --test dist/tests/dsh-notification-delivery.test.js
```

Expected: all delivery lifecycle tests pass.

- [ ] **Step 5: Wire delivery into the DSH plugin with a failing registration test first**

Update `src/tests/dsh-plugin.test.ts` to assert:

```ts
assert.deepEqual(inject, ['tools', 'agents'])
assert.deepEqual(registeredEvents.filter(name => name.startsWith('agent/')).sort(), [
  'agent/created',
  'agent/status',
])
```

Run the plugin test and confirm it fails before changing `src/dsh/plugin.ts`. Then import/install the coordinator from `apply()`, expand the structural context, and preserve existing tool/runtime listener behavior.

- [ ] **Step 6: Verify plugin integration GREEN**

Run:

```bash
npm run build
node --test dist/tests/dsh-plugin.test.js dist/tests/dsh-notification-delivery.test.js dist/tests/dsh-runtime.test.js
```

Expected: all selected tests pass.

- [ ] **Step 7: Commit the DSH delivery unit**

```bash
git add src/dsh/notification-delivery.ts src/dsh/plugin.ts src/tests/dsh-notification-delivery.test.ts src/tests/dsh-plugin.test.ts
git commit -m "feat: deliver threat feed notices to DSH sessions"
```

---

### Task 4: Documentation, package smoke, and complete verification

**Files:**
- Modify: `docs/dsh.md`
- Modify: `README.md`
- Modify: `scripts/test-dsh-package.mjs` only if the packaged registration assertion needs the new injected lifecycle.

**Interfaces:**
- Consumes: completed CLI queue production and DSH delivery lifecycle.
- Produces: reproducible macOS local testing instructions and verified package behavior.

- [ ] **Step 1: Update local installation and notification documentation**

Document this exact split:

```bash
cd /absolute/path/to/agentguard
npm run build

agentguard_pack_dir="$(mktemp -d)"
npm pack --pack-destination "$agentguard_pack_dir"
npm install -g "$agentguard_pack_dir"/goplus-agentguard-*.tgz

dsh plugin --profile web add link:/absolute/path/to/agentguard
```

Explain that the tarball copy is for unattended cron on macOS, the DSH `link:` remains for fast plugin rebuilds, queued notices survive DSH downtime, delivery occurs only when the exact session is live, and the narrow accepted-before-delete window is at-least-once.

- [ ] **Step 2: Run focused feature tests**

```bash
npm run build
node --test dist/tests/dsh-notifications.test.js dist/tests/cli-subscribe.test.js dist/tests/dsh-notification-delivery.test.js dist/tests/dsh-plugin.test.js dist/tests/feed-cron.test.js
```

Expected: all focused tests pass with no warnings or unhandled rejections.

- [ ] **Step 3: Run the complete unit suite**

```bash
npm test
```

Expected: every test passes.

- [ ] **Step 4: Run packaged DSH smoke verification**

```bash
env DSH_PACKAGE_BIN=/Users/jeff/.nvm/versions/node/v24.18.0/bin/dsh npm run test:dsh-package
```

Expected: the local package loads in an isolated DSH profile, registers `agentguard_dsh_subscribe`, and preserves the existing protect-mode checks.

- [ ] **Step 5: Inspect final repository state**

```bash
git diff --check
git status --short
git log --oneline -8
```

Expected: no whitespace errors; only the user-owned `next-steps.txt` may remain untracked before the final documentation commit.

- [ ] **Step 6: Commit documentation and any smoke-test adjustment**

```bash
git add docs/dsh.md README.md scripts/test-dsh-package.mjs
git commit -m "docs: explain DSH threat feed notification delivery"
```

If `scripts/test-dsh-package.mjs` did not require a change, omit it from `git add`.
