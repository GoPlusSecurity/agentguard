# DSH Subscribe Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a native `agentguard_dsh_subscribe` tool that binds a threat-feed subscription to the calling DSH agent, subscribes the connected Cloud identity, installs the existing system cron poller, and persists versioned local state.

**Architecture:** Keep filesystem state in a focused `src/feed/dsh-subscription.ts` module and keep tool orchestration in the existing DSH plugin. The tool obtains the target only from DSH `ToolRunContext.agent`, delegates Cloud and cron effects to existing AgentGuard services, and accepts injected boundary adapters in tests so tests never touch the real Cloud or crontab.

**Tech Stack:** TypeScript 5.7, Node.js 18+ filesystem APIs, Node test runner, existing AgentGuard Cloud client and feed cron service.

**Spec:** `docs/superpowers/specs/2026-08-25-dsh-threat-feed-subscription-design.md`

## Global Constraints

- Implement only `agentguard_dsh_subscribe`; status, unsubscribe, notification queue delivery, and expanded DSH self-check discovery remain outside this sub-project.
- Support DeepSeek Harness `0.1.1-rc.2` without changing DeepSeek Harness source.
- Use a system crontab poller so polling survives DSH process shutdown.
- Derive the target agent id only from DSH execution context; never accept it as a tool argument.
- Default to hourly manual notification mode; local self-check requires explicit `selfCheck: true`.
- Do not execute advisory remediation or arbitrary advisory-controlled content.

---

### Task 1: Versioned DSH subscription state

**Files:**
- Create: `src/feed/dsh-subscription.ts`
- Create: `src/tests/dsh-subscription.test.ts`

**Interfaces:**
- Produces: `DshThreatFeedSubscription`, `dshThreatFeedSubscriptionPath(home?: string)`, `loadDshThreatFeedSubscription(home?: string)`, `saveDshThreatFeedSubscription(subscription, home?: string)`, and `removeDshThreatFeedSubscription(home?: string)`.
- Persists: `dsh-threat-feed-subscription.json` with schema version `1`, mode `0600`, and atomic same-directory rename.

- [x] **Step 1: Write failing persistence tests**

Add tests that save and reload this literal record, verify `0600`, reject malformed/unknown-version JSON, return `null` when absent, and remove an existing record:

```ts
const subscription = {
  version: 1 as const,
  subscriptionId: 'sub-test-1',
  agentId: 'dsh-agent-1',
  cronName: 'agentguard-threat-feed',
  cronExpression: '0 * * * *',
  selfCheck: false,
  createdAt: '2026-08-25T00:00:00.000Z',
  updatedAt: '2026-08-25T00:00:00.000Z',
};
```

- [x] **Step 2: Run the test and verify RED**

Run: `npm run build && node --test dist/tests/dsh-subscription.test.js`

Expected: TypeScript fails because `../feed/dsh-subscription.js` does not exist.

- [x] **Step 3: Implement minimal atomic state storage**

Implement strict runtime validation for every field. Create the AgentGuard home with `0700`, write JSON plus a final newline to a random same-directory temporary file using `0600`, rename it atomically, chmod the final file to `0600`, and remove the temporary file in `finally`.

- [x] **Step 4: Run the state tests and verify GREEN**

Run: `npm run build && node --test dist/tests/dsh-subscription.test.js`

Expected: all state tests pass with zero failures.

- [x] **Step 5: Commit the state module**

```bash
git add docs/superpowers/plans/2026-08-25-dsh-subscribe-tool.md src/feed/dsh-subscription.ts src/tests/dsh-subscription.test.ts
git commit -m "feat: add DSH threat feed subscription state"
```

### Task 2: Native subscribe tool orchestration

**Files:**
- Modify: `src/dsh/plugin.ts`
- Modify: `src/tests/dsh-plugin.test.ts`
- Modify: `src/dsh/runtime.ts`
- Modify: `src/tests/dsh-runtime.test.ts`

**Interfaces:**
- Consumes: Task 1 state functions and `installThreatFeedCron()`.
- Produces: `createAgentGuardDshSubscribeTool(dependencies?)` and registered tool name `agentguard_dsh_subscribe`.
- Tool input: `{ cron?: string; selfCheck?: boolean; force?: boolean }`.
- Tool output: `{ subscriptionId, targetAgentId, cronName, cronExpression, selfCheck, backend, created, modelSummary }`.

- [x] **Step 1: Write failing tool behavior tests**

Add tests that exercise the real tool factory with a temporary AgentGuard home and boundary adapters. Verify:

```ts
await tool.execute(
  { cron: '*/15 * * * *', selfCheck: true },
  { agent: { id: 'dsh-agent-1' } },
);
```

persists `dsh-agent-1`, requests the system backend, maps `selfCheck` to cron `quiet`, calls Cloud subscription before cron installation, and returns a bounded result. Add separate tests for missing agent context, missing Cloud credentials, non-DSH configuration, conflict without `force`, idempotent same-subscription calls, and best-effort rollback when state persistence fails.

- [x] **Step 2: Add failing registration and recursive-exemption tests**

Update the plugin registration expectation so `agentguard_dsh_subscribe` appears after the four existing tools. Assert `isAgentGuardDshTool('agentguard_dsh_subscribe')` is true while `agentguard_dsh_subscribe_evil` remains false.

- [x] **Step 3: Run focused tests and verify RED**

Run: `npm run build`

Expected: TypeScript fails because the subscribe factory and types are not defined.

- [x] **Step 4: Implement the minimal tool**

Extend the local DSH tool definition to accept the optional execution context argument. Implement validation, idempotency/conflict handling, connected Cloud subscription, explicit system cron installation, atomic state save, config cron metadata update, and rollback of a newly created cron when persistence fails. Register the tool in `apply()` and add its exact name to the runtime self-exemption set.

- [x] **Step 5: Run focused tests and verify GREEN**

Run: `npm run build && node --test dist/tests/dsh-subscription.test.js dist/tests/dsh-plugin.test.js dist/tests/dsh-runtime.test.js dist/tests/feed-cron.test.js`

Expected: all focused tests pass with zero failures.

- [ ] **Step 6: Commit the native tool**

```bash
git add docs/superpowers/plans/2026-08-25-dsh-subscribe-tool.md src/dsh/plugin.ts src/dsh/runtime.ts src/tests/dsh-plugin.test.ts src/tests/dsh-runtime.test.ts
git commit -m "feat: add native DSH threat feed subscribe tool"
```

### Task 3: Documentation and verification

**Files:**
- Modify: `docs/dsh.md`

**Interfaces:**
- Documents: tool arguments, Cloud prerequisite, system cron behavior, current absence of automatic DSH-session notification delivery, and local link/restart flow.

- [ ] **Step 1: Document the implemented boundary**

Add a DSH threat-feed section with this example request:

```text
Use AgentGuard to subscribe this DSH session to the threat feed every 15 minutes without automatic self-checks.
```

State explicitly that this implementation creates/persists the subscription but does not yet deliver notifications back into a DSH session; current cron output remains in `~/.agentguard/feed-cron.log`.

- [ ] **Step 2: Run verification**

Run: `npm run build`

Run outside the restricted listener sandbox: `npm test`

Run when the local DSH binary is available: `env DSH_PACKAGE_BIN=/Users/jeff/.nvm/versions/node/v24.18.0/bin/dsh npm run test:dsh-package`

Expected: build and all applicable tests pass with zero failures.

- [ ] **Step 3: Commit the sub-project**

```bash
git add docs/superpowers/plans/2026-08-25-dsh-subscribe-tool.md docs/dsh.md src/feed/dsh-subscription.ts src/dsh/plugin.ts src/dsh/runtime.ts src/tests/dsh-subscription.test.ts src/tests/dsh-plugin.test.ts src/tests/dsh-runtime.test.ts
git commit -m "feat: add DSH threat feed subscribe tool"
```
