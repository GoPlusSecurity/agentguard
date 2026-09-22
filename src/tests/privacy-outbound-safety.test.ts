import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanSurfaces } from '../privacy/surfaces.js';
import { JevAdjudicator } from '../privacy/providers/jev.js';
import { DEFAULT_ADJUDICATE_OPTIONS, TokenBudget } from '../privacy/types.js';
import { extractCandidates } from '../privacy/candidates.js';
import { chunkLocator, splitChunks } from '../privacy/chunks.js';
import {
  findForbiddenOutbound,
  isCredentialStore,
  outboundContext,
} from '../privacy/redact-outbound.js';

const AWS_SECRET = 'wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY';
const STRIPE_KEY = 'sk-live_51H8xQ2abcdefghijklmnop';

/** Captures every serialized request a scan would put on the wire. */
function recordingProvider() {
  const bodies: string[] = [];
  const fetchImpl = (async (_url: string, init: { body: string }) => {
    bodies.push(init.body);
    const parsed = JSON.parse(init.body) as { questions: Record<string, unknown> };
    const answers: Record<string, unknown> = {};
    for (const key of Object.keys(parsed.questions)) answers[key] = { type: 'noul', noul: 0.9 };
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ model: 'm', answers, usage: { input_tokens: 1, output_tokens: 1 } }),
    };
  }) as unknown as typeof fetch;
  return {
    bodies,
    adjudicator: new JevAdjudicator({ apiKey: 'test', fetchImpl }),
  };
}

describe('Outbound credential safety', () => {
  /**
   * Regression for the review blocker: a credential that is not itself a
   * candidate but shares a line with one was reaching the provider inside the
   * candidate's context. The CLI consent text promises credentials are never
   * sent, so this must hold for any file that reaches the scanner.
   */
  it('never sends a credential that shares a line with a candidate', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ag-leak-'));
    try {
      writeFileSync(
        join(dir, 'notes.md'),
        `运维交接：联系人 ops@corp.invalid，手机 13812345678，临时密钥 ${STRIPE_KEY} 请尽快轮换。`,
      );
      writeFileSync(
        join(dir, 'conf.yaml'),
        `owner: { email: "ops@corp.invalid", aws_secret_access_key: "${AWS_SECRET}" }`,
      );
      const { bodies, adjudicator } = recordingProvider();
      await scanSurfaces([join(dir, 'notes.md'), join(dir, 'conf.yaml')], {
        scope: 'filtered',
        adjudicator,
        settings: DEFAULT_ADJUDICATE_OPTIONS,
      });
      const wire = bodies.join('\n');
      assert.ok(bodies.length > 0, 'the test is meaningless if nothing was sent');
      assert.ok(!wire.includes(STRIPE_KEY), 'Stripe key reached the provider');
      assert.ok(!wire.includes(AWS_SECRET), 'AWS secret reached the provider');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('excludes credential stores from analysis entirely', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ag-env-'));
    try {
      writeFileSync(join(dir, '.env'), `# ops@corp.invalid\nSTRIPE_KEY=${STRIPE_KEY}\n`);
      const { bodies, adjudicator } = recordingProvider();
      const scan = await scanSurfaces([join(dir, '.env')], {
        scope: 'filtered',
        adjudicator,
        settings: DEFAULT_ADJUDICATE_OPTIONS,
      });
      assert.equal(bodies.length, 0, 'a credential store must not be read for analysis');
      assert.equal(scan.filesExamined, 0);
      assert.equal(scan.filesSkipped, 1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('recognises credential stores by name and extension', () => {
    for (const path of ['/a/.env', '/a/.env.production', '/a/id_rsa', '/a/server.pem', '/a/.npmrc', '/a/credentials']) {
      assert.ok(isCredentialStore(path), `${path} should be excluded`);
    }
    for (const path of ['/a/notes.md', '/a/config.yaml', '/a/index.ts']) {
      assert.ok(!isCredentialStore(path), `${path} should be analysed`);
    }
  });

  /**
   * Narrowing before redacting can slice a secret in half, leaving a fragment
   * the redaction patterns no longer match. The padded region must therefore be
   * redacted before the emitted window is cut from it.
   */
  it('redacts before narrowing so a window cannot bisect a secret', () => {
    const source = `owner email ops@corp.invalid and aws_secret_access_key: "${AWS_SECRET}" end`;
    const start = source.indexOf('ops@corp.invalid');
    const context = outboundContext(source, start, start + 'ops@corp.invalid'.length);
    assert.ok(!context.includes(AWS_SECRET), 'secret survived the redaction window');
  });

  it('refuses a payload that still carries a credential shape', () => {
    assert.notEqual(findForbiddenOutbound(`token ${STRIPE_KEY}`), null);
    assert.notEqual(findForbiddenOutbound('AKIAIOSFODNN7EXAMPLE'), null);
    assert.notEqual(findForbiddenOutbound('-----BEGIN RSA PRIVATE KEY-----'), null);
    assert.equal(findForbiddenOutbound('收件人是陈立群，电话 13701234567'), null);
  });
});

describe('Capture offset accuracy', () => {
  /**
   * Deriving a capture offset by searching for the captured text picks the wrong
   * occurrence whenever it repeats inside the match, and a wrong offset masks
   * the wrong span — leaving the real data exposed.
   */
  it('reports exact offsets when the captured text repeats', () => {
    const text = '客户是王王，收件人是王王王，联系人叫李李。';
    const candidates = extractCandidates(text, chunkLocator(splitChunks(text)));
    assert.ok(candidates.length >= 3);
    for (const candidate of candidates) {
      assert.equal(
        text.slice(candidate.start, candidate.end),
        candidate.value,
        `offset does not resolve to the captured value: ${candidate.value}`,
      );
    }
  });
});

describe('Shared budget reconciliation', () => {
  /**
   * Reservations come from a character estimate. Without reconciling against
   * reported usage, repeated undercounts let actual egress drift above the
   * configured ceiling.
   */
  it('charges an undercount back to the ceiling', () => {
    const budget = new TokenBudget(1000);
    assert.equal(budget.tryConsume(100), true);
    budget.reconcile(100, 900);
    assert.equal(budget.remaining, 100, 'the undercount was not charged');
    assert.equal(budget.tryConsume(500), false, 'spending must stop once reconciled over');
  });

  it('never credits an overestimate back', () => {
    const budget = new TokenBudget(1000);
    budget.tryConsume(500);
    budget.reconcile(500, 100);
    assert.equal(budget.remaining, 500, 'reconciliation must not refund');
  });
});
