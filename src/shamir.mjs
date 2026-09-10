import crypto from 'node:crypto';
import { combine, split } from 'shamir-secret-sharing';

import { canonical, isPlainObject, sha256 } from './canonical.mjs';
import { assert } from './errors.mjs';

const PROFILE = 'nova-privy-shamir-aes-256-gcm-0.2';
const MAX_SECRET_BYTES = 64 * 1024;
const MAX_SHARE_DATA_CHARACTERS = 128;
const MAX_CIPHERTEXT_CHARACTERS = Math.ceil(MAX_SECRET_BYTES * 4 / 3) + 8;

function decodeCanonicalBase64url(value, { minimumBytes = 1, maximumBytes, exactBytes } = {}) {
  assert(typeof value === 'string' && value.length > 0 && /^[A-Za-z0-9_-]+$/.test(value), 'invalid_shard', 'The shard content is invalid.');
  const decoded = Buffer.from(value, 'base64url');
  assert(decoded.toString('base64url') === value
    && (exactBytes === undefined || decoded.length === exactBytes)
    && decoded.length >= minimumBytes
    && (maximumBytes === undefined || decoded.length <= maximumBytes),
  'invalid_shard', 'The shard content is not canonical or has an invalid size.');
  return decoded;
}

function signedShare(content) {
  return { ...content, checksum: sha256(content) };
}

function validateShare(share) {
  const fields = ['checksum', 'ciphertext', 'data', 'implementation', 'index', 'iv', 'profile', 'setId', 'shareCount', 'tag', 'threshold', 'version'];
  assert(
    isPlainObject(share)
      && Object.keys(share).sort().join(',') === fields.sort().join(',')
      && share.version === 2
      && share.profile === PROFILE
      && share.implementation === 'shamir-secret-sharing@0.0.4'
      && typeof share.setId === 'string'
      && share.setId.length > 0
      && share.setId.length <= 160
      && Number.isInteger(share.index)
      && share.index >= 1
      && share.index <= 255,
    'invalid_shard',
    'The shard format is invalid.',
  );
  assert(Number.isInteger(share.threshold) && share.threshold >= 2 && share.threshold <= 255, 'invalid_shard', 'The shard threshold is invalid.');
  assert(Number.isInteger(share.shareCount) && share.shareCount >= share.threshold && share.shareCount <= 255, 'invalid_shard', 'The shard share count is invalid.');
  assert(typeof share.data === 'string' && share.data.length <= MAX_SHARE_DATA_CHARACTERS
    && typeof share.ciphertext === 'string' && share.ciphertext.length <= MAX_CIPHERTEXT_CHARACTERS
    && typeof share.iv === 'string'
    && typeof share.tag === 'string'
    && typeof share.checksum === 'string' && /^[a-f0-9]{64}$/.test(share.checksum), 'invalid_shard', 'The shard content is invalid.');
  decodeCanonicalBase64url(share.data, { exactBytes: 33 });
  decodeCanonicalBase64url(share.ciphertext, { maximumBytes: MAX_SECRET_BYTES });
  decodeCanonicalBase64url(share.iv, { exactBytes: 12 });
  decodeCanonicalBase64url(share.tag, { exactBytes: 16 });
  const { checksum, ...content } = share;
  assert(sha256(content) === checksum, 'shard_checksum_failed', 'The shard checksum is invalid.', 409);
  return content;
}

export async function splitSecret(secret, { shares = 3, threshold = 2 } = {}) {
  assert(typeof secret === 'string' || Buffer.isBuffer(secret) || secret instanceof Uint8Array, 'invalid_secret', 'The secret must be a string, Buffer, or Uint8Array.');
  const bytes = Buffer.isBuffer(secret) ? secret : Buffer.from(secret);
  assert(bytes.length > 0 && bytes.length <= MAX_SECRET_BYTES, 'invalid_secret', `The secret must contain between 1 and ${MAX_SECRET_BYTES} bytes.`);
  assert(Number.isInteger(shares) && shares >= 2 && shares <= 255, 'invalid_share_count', 'Share count must be between 2 and 255.');
  assert(Number.isInteger(threshold) && threshold >= 2 && threshold <= shares, 'invalid_threshold', 'Threshold must be between 2 and the share count.');

  // Split a random wrapping key rather than the caller's secret. Publishing a
  // direct secret hash with every Shamir share would create an offline password
  // guessing oracle for low-entropy inputs.
  const wrappingKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, iv);
  const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  const outputs = await split(new Uint8Array(wrappingKey), shares, threshold);
  const setId = `shardset_${crypto.randomUUID()}`;
  return outputs.map((data, index) => signedShare({
    version: 2,
    profile: PROFILE,
    implementation: 'shamir-secret-sharing@0.0.4',
    setId,
    index: index + 1,
    threshold,
    shareCount: shares,
    data: Buffer.from(data).toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    iv: iv.toString('base64url'),
    tag: tag.toString('base64url'),
  }));
}

export async function combineShares(input) {
  assert(Array.isArray(input) && input.length >= 2 && input.length <= 255, 'insufficient_shards', 'Between two and 255 shards are required.');
  const shares = input.map(validateShare);
  const { threshold, shareCount, setId, ciphertext, iv, tag } = shares[0];
  assert(shares.length >= threshold, 'insufficient_shards', `At least ${threshold} shards are required.`);
  assert(
    shares.every(share => share.threshold === threshold && share.shareCount === shareCount && share.setId === setId
      && share.ciphertext === ciphertext && share.iv === iv && share.tag === tag),
    'shard_set_mismatch',
    'Shards do not belong to the same secret.',
    409,
  );
  assert(new Set(shares.map(share => share.index)).size === shares.length, 'duplicate_shard', 'Duplicate shard indexes are not accepted.');
  assert(new Set(shares.map(share => share.data)).size === shares.length, 'duplicate_shard', 'Duplicate shard data is not accepted.');

  const decoded = shares.slice(0, threshold).map(share => Buffer.from(share.data, 'base64url'));
  const length = decoded[0].length;
  assert(length > 0 && decoded.every(share => share.length === length), 'shard_length_mismatch', 'Shard lengths do not match.', 409);
  const wrappingKey = Buffer.from(await combine(decoded.map(value => new Uint8Array(value))));
  assert(wrappingKey.length === 32, 'shard_recovery_failed', 'Recovered wrapping key has an invalid length.', 409);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', wrappingKey, Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    const recovered = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]);
    assert(recovered.length > 0 && recovered.length <= MAX_SECRET_BYTES, 'shard_recovery_failed', 'Recovered secret has an invalid size.', 409);
    return recovered;
  } catch (error) {
    if (error?.code === 'shard_recovery_failed') throw error;
    assert(false, 'shard_recovery_failed', 'Authenticated secret recovery failed.', 409);
  }
}

export async function splitKeyBundle(bundle, options) {
  return splitSecret(Buffer.from(canonical(bundle)), options);
}

export async function combineKeyBundle(shares) {
  return JSON.parse((await combineShares(shares)).toString('utf8'));
}
