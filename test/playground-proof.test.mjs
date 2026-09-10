import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import fs from 'node:fs/promises';
import { FORMAT, DEFAULT_CLAIMS, canonicalize, parseBundle, createDemo, verifyBundle, tamperBundle } from '../playground/proof.mjs';
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
const now = 1800000000000;

test('browser demo uses actual Ed25519 and preserves its fixture boundary', async () => {
  const bundle = await createDemo({ now });
  const result = await verifyBundle(bundle, { now: now + 1 });
  assert.equal(result.status, 'verified');
  assert.equal(result.accepted, true);
  assert.equal(result.sourceSignature, true);
  assert.equal(result.receiptSignature, true);
  assert.equal(result.bindingValid, true);
  assert.equal(bundle.format, FORMAT);
  assert.equal(bundle.source.algorithm, 'Ed25519');
  assert.equal(bundle.source.publicKey.length, 64);
  assert.equal(bundle.source.signature.length, 128);
  assert.equal(bundle.receipt.payload.trustLevel, 'untrusted-fixture');
  assert.equal(bundle.receipt.payload.agent.kind, 'deterministic-fixture');
  assert.equal(bundle.receipt.payload.effect, 'browser-memory-record-only');
  assert.deepEqual(Object.keys(bundle.receipt.payload.context).sort(), ['approvedLimit', 'organization', 'requestedAmount']);
  assert.equal(JSON.stringify(bundle.receipt.payload).includes(DEFAULT_CLAIMS.privateContact), false);
  assert.equal(bundle.source.payload.claims.privateContact, DEFAULT_CLAIMS.privateContact);
  assert.equal(JSON.stringify(bundle).includes('privateKey'), false);
  const key = await webcrypto.subtle.importKey('raw', Buffer.from(bundle.receipt.publicKey, 'hex'), 'Ed25519', false, ['verify']);
  assert.equal(await webcrypto.subtle.verify('Ed25519', key, Buffer.from(bundle.receipt.signature, 'hex'), Buffer.from(canonicalize(bundle.receipt.payload))), true);
});

test('a signed source edited after signing stops before context and agent', async () => {
  const bundle = await createDemo({ now, scenario: 'tampered' });
  const result = await verifyBundle(bundle, { now });
  assert.equal(result.status, 'tampered');
  assert.equal(result.sourceSignature, false);
  assert.equal(result.receiptSignature, true);
  assert.equal(result.accepted, false);
  assert.equal(bundle.receipt.payload.context, null);
  assert.equal(bundle.receipt.payload.agent, null);
  assert.equal(bundle.receipt.payload.policy.decision, 'not-evaluated');
  assert.equal(bundle.receipt.payload.effect, 'no-action');
});

test('expired evidence remains expired despite valid signatures', async () => {
  const bundle = await createDemo({ now, scenario: 'expired' });
  const result = await verifyBundle(bundle, { now });
  assert.equal(result.status, 'expired');
  assert.equal(result.sourceSignature, true);
  assert.equal(result.receiptSignature, true);
  assert.equal(result.accepted, false);
  assert.equal(bundle.receipt.payload.context, null);
  const fresh = await createDemo({ now });
  assert.equal((await verifyBundle(fresh, { now: now + 300001 })).status, 'expired');
});

test('authorization and amount constraints deny local action without lying about signatures', async () => {
  for (const options of [{ scenario: 'denied' }, { claims: { ...DEFAULT_CLAIMS, requestedAmount: 6000 } }]) {
    const bundle = await createDemo({ now, ...options });
    const result = await verifyBundle(bundle, { now });
    assert.equal(result.status, 'denied');
    assert.equal(result.sourceSignature, true);
    assert.equal(result.receiptSignature, true);
    assert.equal(result.bindingValid, true);
    assert.equal(result.accepted, false);
    assert.equal(bundle.receipt.payload.effect, 'no-action');
    assert.ok(bundle.receipt.payload.agent);
  }
});

test('receipt tampering fails and leaves the original intact', async () => {
  const original = await createDemo({ now });
  const copy = tamperBundle(original);
  const result = await verifyBundle(copy, { now });
  assert.equal(result.status, 'tampered');
  assert.equal(result.receiptSignature, false);
  assert.equal(result.bindingValid, false);
  assert.equal((await verifyBundle(original, { now })).status, 'verified');
});

test('context, policy, outcome, time and key edits cannot retain verified status', async () => {
  const bundle = await createDemo({ now });
  for (const mutate of [
    b => { b.receipt.payload.context.privateContact = 'injected'; },
    b => { b.receipt.payload.context.requestedAmount = 1; },
    b => { b.receipt.payload.policy.authorized = false; },
    b => { b.receipt.payload.agent.statement = 'Unbound claim'; },
    b => { b.receipt.payload.createdAt = now + 50000; },
    b => { b.source.payload.audience = 'different-audience'; },
    b => { b.receipt.publicKey = '0'.repeat(64); },
    b => { b.receipt.algorithm = 'none'; },
  ]) {
    const copy = structuredClone(bundle); mutate(copy);
    assert.equal((await verifyBundle(copy, { now })).accepted, false);
  }
});

test('JSON round-trip, reordered keys and independent ephemeral keys behave honestly', async () => {
  const a = await createDemo({ now }); const b = await createDemo({ now });
  assert.notEqual(a.source.publicKey, b.source.publicKey);
  assert.notEqual(a.receipt.publicKey, b.receipt.publicKey);
  const restored = parseBundle(JSON.stringify(a));
  restored.receipt.payload.context = Object.fromEntries(Object.entries(restored.receipt.payload.context).reverse());
  assert.equal((await verifyBundle(restored, { now })).accepted, true);
  assert.match(restored.demonstration, /Not a NOVA runtime credential/);
});

test('invalid input and malformed or oversized bundles are rejected', async () => {
  for (const claims of [null, [], {}, { ...DEFAULT_CLAIMS, requestedAmount: -1 }, { ...DEFAULT_CLAIMS, approvedLimit: '5000' }, { ...DEFAULT_CLAIMS, extra: true }]) await assert.rejects(createDemo({ now, claims }));
  await assert.rejects(createDemo({ now, scenario: 'provider' }));
  await assert.rejects(verifyBundle({ format: 'runtime-credential' }));
  assert.throws(() => parseBundle('not JSON'));
  assert.throws(() => parseBundle(' '.repeat(131073)));
  assert.throws(() => canonicalize(Number.NaN));
  assert.throws(() => parseBundle('['.repeat(26) + '0' + ']'.repeat(26)));
});

test('static UI stays self-contained and describes the proof boundary', async () => {
  const html = await fs.readFile(new URL('../playground/index.html', import.meta.url), 'utf8');
  const app = await fs.readFile(new URL('../playground/app.mjs', import.meta.url), 'utf8');
  assert.match(html, /<html lang="en">/);
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /Browser proof demonstration/i);
  assert.match(html, /deterministic fixture agent/);
  assert.match(html, /\.\/app\.mjs/);
  assert.match(html, /\.\/styles\.css/);
  assert.equal(/fetch\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage|innerHTML/.test(app), false);
  for (const id of ['run-form', 'source-input', 'receipt-json', 'receipt-file', 'verify-button', 'download-button', 'tamper-button']) assert.match(html, new RegExp(`id="${id}"`));
});
