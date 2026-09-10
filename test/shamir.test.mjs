import assert from 'node:assert/strict';
import test from 'node:test';
import { sha256 } from '../src/canonical.mjs';
import { createKeyBundle } from '../src/crypto.mjs';
import { combineKeyBundle, combineShares, splitKeyBundle, splitSecret } from '../src/shamir.mjs';

function resign(share, changes = {}) {
  const { checksum: _checksum, ...unsigned } = { ...structuredClone(share), ...changes };
  return { ...unsigned, checksum: sha256(unsigned) };
}

function alterEncoded(value) {
  const bytes = Buffer.from(value, 'base64url');
  bytes[0] ^= 0x01;
  return bytes.toString('base64url');
}

test('audited Shamir implementation recovers with the threshold and not below it', async () => {
  const secret = Buffer.from('NOVA recovery material');
  const shares = await splitSecret(secret, { shares: 5, threshold: 3 });
  assert.equal(Object.hasOwn(shares[0], 'secretHash'), false);
  assert.equal(JSON.stringify(shares).includes(secret.toString('utf8')), false);
  assert.deepEqual(await combineShares([shares[0], shares[2], shares[4]]), secret);
  await assert.rejects(combineShares(shares.slice(0, 2)), error => error.code === 'insufficient_shards');
  const altered = structuredClone(shares[0]);
  altered.data = `${altered.data[0] === 'A' ? 'B' : 'A'}${altered.data.slice(1)}`;
  await assert.rejects(combineShares([altered, shares[1], shares[2]]), error => error.code === 'shard_checksum_failed');
});

test('share decoding rejects unbounded encoded input before reconstruction', async () => {
  const [first, second] = await splitSecret(Buffer.from('bounded material'), { shares: 2, threshold: 2 });
  const oversized = structuredClone(first);
  oversized.data = 'A'.repeat(129);
  await assert.rejects(combineShares([oversized, second]), error => error.code === 'invalid_shard');
});

test('share recovery rejects mixed sets and duplicate shares', async () => {
  const left = await splitSecret(Buffer.from('left material'), { shares: 3, threshold: 2 });
  const right = await splitSecret(Buffer.from('right material'), { shares: 3, threshold: 2 });
  await assert.rejects(combineShares([left[0], right[1]]), error => error.code === 'shard_set_mismatch');
  await assert.rejects(combineShares([left[0], left[0]]), error => error.code === 'duplicate_shard');
});

test('authenticated envelope rejects forged threshold and encrypted fields even with recomputed checksums', async () => {
  const shares = await splitSecret(Buffer.from('authenticated material'), { shares: 4, threshold: 3 });
  const weakened = shares.slice(0, 2).map(share => resign(share, { threshold: 2 }));
  await assert.rejects(combineShares(weakened), error => error.code === 'shard_recovery_failed');

  for (const field of ['ciphertext', 'iv', 'tag']) {
    const altered = shares.slice(0, 3).map(share => resign(share, { [field]: alterEncoded(share[field]) }));
    await assert.rejects(combineShares(altered), error => error.code === 'shard_recovery_failed');
  }
});

test('share decoding rejects non-canonical base64url values', async () => {
  const shares = await splitSecret(Buffer.from('canonical material'), { shares: 2, threshold: 2 });
  const malformed = resign(shares[0], { data: 'A' });
  await assert.rejects(combineShares([malformed, shares[1]]), error => error.code === 'invalid_shard');
});

test('signing key bundles can be split and recovered without changing key material', async () => {
  const bundle = createKeyBundle({ issuer: 'https://issuer.example' });
  const shards = await splitKeyBundle(bundle, { shares: 3, threshold: 2 });
  const recovered = await combineKeyBundle([shards[0], shards[2]]);
  assert.deepEqual(recovered, bundle);
});
