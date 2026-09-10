import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assert, fail } from './errors.mjs';
import { base64url, canonical, decodeBase64url } from './canonical.mjs';

const allowedAlgorithms = new Set(['EdDSA']);

export function createKeyBundle({ issuer = 'https://nova-one.local', keyId = 'nova-ed25519-v1' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    version: 1,
    issuer,
    activeKeyId: keyId,
    keys: {
      [keyId]: {
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      },
    },
  };
}

export function writeKeyBundle(file, bundle) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${JSON.stringify(bundle, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}

export function loadKeyBundle(file) {
  assert(fs.existsSync(file), 'signer_not_configured', `Signing key file is missing: ${file}`, 503);
  const bundle = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert(bundle?.version === 1 && bundle.issuer && bundle.activeKeyId && bundle.keys?.[bundle.activeKeyId], 'invalid_key_bundle', 'The NOVA signing key bundle is invalid.', 503);
  return bundle;
}

export function publicJwk(bundle, keyId = bundle.activeKeyId) {
  const record = bundle.keys[keyId];
  assert(record?.publicKeyPem, 'unknown_key', 'The requested public key is unavailable.', 404);
  return { ...crypto.createPublicKey(record.publicKeyPem).export({ format: 'jwk' }), kid: keyId, use: 'sig', alg: 'EdDSA' };
}

export function signBytes(bundle, bytes, keyId = bundle.activeKeyId) {
  const record = bundle.keys[keyId];
  assert(record?.privateKeyPem, 'signer_not_configured', 'The requested private signing key is unavailable.', 503);
  return crypto.sign(null, Buffer.from(bytes), crypto.createPrivateKey(record.privateKeyPem)).toString('base64url');
}

export function verifyBytes(publicKey, bytes, signature) {
  try {
    const key = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : crypto.createPublicKey({ key: publicKey, format: 'jwk' });
    return crypto.verify(null, Buffer.from(bytes), key, decodeBase64url(signature));
  } catch {
    return false;
  }
}

export function signCompactJwt(bundle, payload, { typ = 'JWT', audience, subject, expiresIn = 300, now = Math.floor(Date.now() / 1000) } = {}) {
  const header = { alg: 'EdDSA', kid: bundle.activeKeyId, typ };
  const body = {
    ...payload,
    iss: bundle.issuer,
    iat: now,
    nbf: now,
    exp: now + expiresIn,
    ...(audience ? { aud: audience } : {}),
    ...(subject ? { sub: subject } : {}),
  };
  const input = `${base64url(canonical(header))}.${base64url(canonical(body))}`;
  return `${input}.${signBytes(bundle, input)}`;
}

export function decodeCompactJwt(token) {
  assert(typeof token === 'string' && token.length <= 64_000, 'invalid_token', 'The signed token is missing or too large.');
  const parts = token.split('.');
  assert(parts.length === 3, 'invalid_token', 'The signed token is malformed.');
  try {
    return {
      header: JSON.parse(decodeBase64url(parts[0]).toString('utf8')),
      payload: JSON.parse(decodeBase64url(parts[1]).toString('utf8')),
      signature: parts[2],
      signingInput: `${parts[0]}.${parts[1]}`,
    };
  } catch {
    fail('invalid_token', 'The signed token cannot be decoded.');
  }
}

export function verifyCompactJwt(token, { trustedIssuers, audience, subject, typ, now = Math.floor(Date.now() / 1000) } = {}) {
  const decoded = decodeCompactJwt(token);
  assert(allowedAlgorithms.has(decoded.header.alg), 'invalid_algorithm', 'Only EdDSA signatures are accepted.', 401);
  if (typ) assert(decoded.header.typ === typ, 'invalid_token_type', 'The signed token type is not accepted.', 401);
  const issuer = trustedIssuers?.find(candidate => candidate.id === decoded.payload.iss && candidate.status !== 'suspended');
  assert(issuer, 'untrusted_issuer', 'The token issuer is not trusted.', 403);
  const jwk = issuer.keys?.find(key => key.kid === decoded.header.kid && key.kty === 'OKP' && key.crv === 'Ed25519');
  assert(jwk && verifyBytes(jwk, decoded.signingInput, decoded.signature), 'invalid_signature', 'The token signature is invalid.', 401);
  assert(Number.isInteger(decoded.payload.iat) && Number.isInteger(decoded.payload.nbf) && Number.isInteger(decoded.payload.exp), 'invalid_time_claims', 'Required time claims are missing.', 401);
  assert(decoded.payload.iat <= now && decoded.payload.nbf <= now && decoded.payload.exp > now, 'expired_or_not_yet_valid', 'The token is expired or not yet valid.', 401);
  if (audience) assert(decoded.payload.aud === audience, 'audience_mismatch', 'The token audience does not match.', 403);
  if (subject) assert(decoded.payload.sub === subject, 'subject_mismatch', 'The token subject does not match.', 403);
  return decoded;
}
