# DSH real-world regression benchmark

This benchmark complements the synthetic fixtures under `src/tests/fixtures/dsh-eval/`. It pins reviewed public repositories to exact commits and stores a deterministic subset of each DSH report. It is an engineering regression gate, not a malware leaderboard or a claim that any repository is malicious.

## Baseline

`real-world.manifest.json` is the source list. Every entry must use an HTTPS GitHub repository, a full 40-character commit, and an optional safe repository-relative subpath. `real-world.snapshot.json` records artifact identity, risk outcomes, sorted tags, and aggregated finding counts. Volatile fields such as scan time and duration are intentionally excluded.

The Phase 1 RC baseline contains:

- A low runtime-risk UI bundle (`dsh-deep-whale`).
- A medium runtime-risk skill provider (`superdesign-skill`).
- A generated bundle with expected host command execution (`dsh-open-in-vscode`).
- A provider-routing plugin with a user-triggered self-update path (`dsh-vision-router`).
- A large mixed-purpose repository with credential and webhook evidence (`MisakaNet`).

## Run

Build first, then compare the current scanner with the committed snapshot:

```bash
npm run build
npm run benchmark:dsh
```

Run one pinned case while investigating a change:

```bash
node scripts/dsh-benchmark.mjs --case dsh-vision-router
```

The command exits non-zero and prints field-level differences when a result changes. It fetches only the exact pinned commits and checks the resulting HEAD before scanning.

## Updating the baseline

Do not update the snapshot merely to make a failure disappear. First record:

1. The scanner change that caused the difference.
2. Whether the difference fixes a false positive, closes a false negative, or is an intentional model change.
3. Human review of any new or removed HIGH/CRITICAL runtime tag.
4. The exact upstream commit when changing a sample revision.

After review:

```bash
npm run benchmark:dsh:update
npm run benchmark:dsh
```

Repository owners can change or delete public commits. Such an acquisition failure is a benchmark infrastructure failure, not permission to silently follow the default branch.

## Privacy and evidence handling

Snapshots contain rule names and counts, not matched secret values or full source snippets. Human review notes must not reproduce tokens, webhook identifiers, private keys, or other live-looking credentials.
