import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { scanDshPlugin } from '../dist/dsh/scan.js';

const execFileAsync = promisify(execFile);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const options = {
    manifest: join(repoRoot, 'benchmarks/dsh/real-world.manifest.json'),
    update: false,
    caseIds: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--update') options.update = true;
    else if (argument === '--manifest') options.manifest = resolve(argv[++index]);
    else if (argument === '--case') options.caseIds.push(argv[++index]);
    else throw new Error(`Unknown argument: ${argument}`);
  }
  return options;
}

function assertManifest(manifest) {
  if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.cases) || manifest.cases.length === 0) {
    throw new Error('Benchmark manifest must use schemaVersion 1 and contain cases');
  }
  const ids = new Set();
  for (const entry of manifest.cases) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(entry.id ?? '')
      || !/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/.test(entry.repository)) {
      throw new Error(`Invalid repository entry: ${entry.id ?? '<missing id>'}`);
    }
    if (ids.has(entry.id)) throw new Error(`Duplicate benchmark id: ${entry.id}`);
    ids.add(entry.id);
    if (!/^[0-9a-f]{40}$/i.test(entry.revision)) throw new Error(`Invalid pinned revision for ${entry.id}`);
    if (entry.subpath && (entry.subpath.startsWith('/') || entry.subpath.split('/').includes('..'))) {
      throw new Error(`Unsafe subpath for ${entry.id}`);
    }
  }
}

async function checkoutPinned(entry, root) {
  const checkout = join(root, entry.id);
  await execFileAsync('git', ['-c', 'core.hooksPath=/dev/null', 'init', checkout], { timeout: 15_000 });
  await execFileAsync('git', ['-C', checkout, 'remote', 'add', 'origin', `${entry.repository}.git`], { timeout: 10_000 });
  await execFileAsync('git', [
    '-c', 'core.hooksPath=/dev/null', '-C', checkout,
    'fetch', '--depth', '1', '--no-tags', 'origin', entry.revision,
  ], { timeout: 120_000, maxBuffer: 4 * 1024 * 1024 });
  await execFileAsync('git', ['-c', 'core.hooksPath=/dev/null', '-C', checkout, 'checkout', '--detach', entry.revision], {
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  const { stdout } = await execFileAsync('git', ['-C', checkout, 'rev-parse', 'HEAD'], { timeout: 10_000 });
  if (stdout.trim().toLowerCase() !== entry.revision.toLowerCase()) {
    throw new Error(`${entry.id} checkout did not resolve to ${entry.revision}`);
  }
  const target = resolve(checkout, entry.subpath ?? '.');
  if (target !== checkout && !target.startsWith(`${checkout}${sep}`)) throw new Error(`Unsafe target for ${entry.id}`);
  return target;
}

function summarizeFindings(findings) {
  const counts = new Map();
  const generated = new Map();
  for (const finding of findings) {
    const count = finding.occurrenceCount ?? 1;
    counts.set(finding.ruleId, (counts.get(finding.ruleId) ?? 0) + count);
    if (finding.likelyGenerated) generated.set(finding.ruleId, (generated.get(finding.ruleId) ?? 0) + count);
  }
  const sortedObject = map => Object.fromEntries([...map.entries()].sort(([left], [right]) => left.localeCompare(right)));
  return { counts: sortedObject(counts), generatedCounts: sortedObject(generated) };
}

function normalize(entry, report) {
  const findingSummary = summarizeFindings(report.findings);
  return {
    id: entry.id,
    repository: entry.repository,
    revision: entry.revision.toLowerCase(),
    subpath: entry.subpath,
    artifactHash: report.identity.artifactHash,
    pluginKind: report.identity.pluginKind,
    riskLevel: report.riskLevel,
    runtimeSurfaceRiskLevel: report.runtimeSurfaceRiskLevel,
    reviewPriority: report.reviewPriority,
    installRecommendation: report.installRecommendation,
    runtimeSurfaceRecommendation: report.runtimeSurfaceRecommendation,
    riskTags: [...report.riskTags].sort(),
    runtimeSurfaceRiskTags: [...(report.runtimeSurfaceRiskTags ?? [])].sort(),
    findingCounts: findingSummary.counts,
    generatedFindingCounts: findingSummary.generatedCounts,
  };
}

function collectDiffs(expected, actual, path = '$', diffs = []) {
  if (Object.is(expected, actual)) return diffs;
  if (typeof expected !== 'object' || expected === null || typeof actual !== 'object' || actual === null) {
    diffs.push(`${path}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
    return diffs;
  }
  if (Array.isArray(expected) || Array.isArray(actual)) {
    if (JSON.stringify(expected) !== JSON.stringify(actual)) {
      diffs.push(`${path}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
    }
    return diffs;
  }
  for (const key of [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort()) {
    collectDiffs(expected[key], actual[key], `${path}.${key}`, diffs);
  }
  return diffs;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = JSON.parse(await readFile(options.manifest, 'utf8'));
  assertManifest(manifest);
  const selected = options.caseIds.length > 0
    ? manifest.cases.filter(entry => options.caseIds.includes(entry.id))
    : manifest.cases;
  if (selected.length === 0) throw new Error('No benchmark cases selected');
  const unknown = options.caseIds.filter(id => !manifest.cases.some(entry => entry.id === id));
  if (unknown.length > 0) throw new Error(`Unknown benchmark cases: ${unknown.join(', ')}`);

  const tempRoot = await mkdtemp(join(tmpdir(), 'agentguard-dsh-benchmark-'));
  try {
    const results = [];
    for (const entry of selected) {
      process.stderr.write(`Scanning ${entry.id}@${entry.revision.slice(0, 12)}\n`);
      const target = await checkoutPinned(entry, tempRoot);
      results.push(normalize(entry, await scanDshPlugin(target)));
    }
    const snapshot = {
      schemaVersion: 1,
      baseline: manifest.baseline,
      rulesFrozenAt: manifest.rulesFrozenAt,
      cases: results,
    };
    const snapshotPath = resolve(dirname(options.manifest), manifest.snapshot ?? 'real-world.snapshot.json');
    if (options.update) {
      if (options.caseIds.length > 0) throw new Error('--update requires the full manifest, without --case');
      await writeFile(snapshotPath, `${JSON.stringify(snapshot, null, 2)}\n`, 'utf8');
      console.log(`Updated ${relative(repoRoot, snapshotPath)}`);
      return;
    }
    const expected = JSON.parse(await readFile(snapshotPath, 'utf8'));
    const expectedSubset = options.caseIds.length > 0
      ? { ...expected, cases: expected.cases.filter(entry => options.caseIds.includes(entry.id)) }
      : expected;
    const diffs = collectDiffs(expectedSubset, snapshot);
    if (diffs.length > 0) {
      console.error(`DSH benchmark changed (${diffs.length} differences):\n${diffs.slice(0, 100).join('\n')}`);
      process.exitCode = 1;
      return;
    }
    console.log(`DSH benchmark stable: ${results.length} pinned cases`);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

await main();
