import crypto from 'node:crypto';
import { SDJwtInstance, encodePath } from '@sd-jwt/core';

import { isPlainObject, sha256, timestamp } from './canonical.mjs';
import { signBytes, verifyBytes } from './crypto.mjs';
import { assert, fail } from './errors.mjs';
import { assertJsonSchema } from './sources.mjs';

const SD_JWT_PROFILE = 'nova-rfc9901-sd-jwt-0.2';
const RESERVED_CLAIMS = new Set(['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti', '_sd', '_sd_alg', 'purpose', 'jurisdiction']);

function hasher(data, algorithm) {
  const names = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512' };
  assert(names[algorithm], 'unsupported_hash_algorithm', 'The SD-JWT hash algorithm is not supported.');
  return new Uint8Array(crypto.createHash(names[algorithm]).update(Buffer.from(data)).digest());
}

function saltGenerator(length) {
  return crypto.randomBytes(Math.max(16, length)).toString('base64url');
}

function parseHeader(signingInput) {
  try {
    return JSON.parse(Buffer.from(signingInput.split('.')[0], 'base64url').toString('utf8'));
  } catch {
    fail('invalid_sd_jwt', 'The SD-JWT protected header is invalid.', 401);
  }
}

function issuerJwtHash(token) {
  return sha256(String(token).split('~')[0]);
}

function validateScope(payload, { audience, purpose, subject }, now) {
  assert(payload.iss && payload.sub && payload.aud && payload.jti, 'invalid_sd_jwt_claims', 'Required SD-JWT claims are missing.', 401);
  assert(payload.aud === audience, 'audience_mismatch', 'The SD-JWT audience does not match.', 403);
  assert(payload.purpose === purpose, 'purpose_mismatch', 'The SD-JWT purpose does not match.', 403);
  assert(payload.sub === subject, 'subject_mismatch', 'The SD-JWT subject does not match.', 403);
  assert(Number.isInteger(payload.iat) && Number.isInteger(payload.nbf) && Number.isInteger(payload.exp), 'invalid_time_claims', 'Required SD-JWT time claims are missing.', 401);
  assert(payload.iat <= now && payload.nbf <= now && payload.exp > now, 'expired_or_not_yet_valid', 'The SD-JWT is expired or not yet valid.', 401);
}

export class PrivacyService {
  constructor(state, credentials, ledger) {
    this.state = state;
    this.credentials = credentials;
    this.ledger = ledger;
  }

  #sdJwt() {
    const keys = this.credentials.keys;
    return new SDJwtInstance({
      signer: data => signBytes(keys, data),
      signAlg: 'EdDSA',
      verifier: (data, signature) => {
        const header = parseHeader(data);
        assert(header.alg === 'EdDSA' && header.typ === 'nova+sd-jwt', 'invalid_sd_jwt_header', 'The SD-JWT protected header is not accepted.', 401);
        const candidate = keys.keys?.[header.kid];
        return Boolean(candidate?.publicKeyPem && verifyBytes(candidate.publicKeyPem, data, signature));
      },
      hasher,
      hashAlg: 'sha-256',
      allowedDisclosureHashAlgorithms: ['sha-256'],
      saltGenerator,
    });
  }

  async issueSelectiveDisclosure({ subject, claims, audience, purpose, jurisdiction = 'GLOBAL', ttl = 300, actor = subject }) {
    assert(isPlainObject(claims) && Object.keys(claims).length > 0, 'invalid_disclosure_claims', 'At least one selectively disclosable claim is required.');
    assertJsonSchema(claims, { type: 'object', additionalProperties: true }, 'invalid_disclosure_claims');
    const claimNames = Object.keys(claims);
    assert(claimNames.length <= 100 && claimNames.every(name => typeof name === 'string' && name.length > 0 && name.length <= 160 && !RESERVED_CLAIMS.has(name)), 'invalid_disclosure_claims', 'Selective claim names must be bounded and cannot use reserved JWT names.');
    assert(typeof subject === 'string' && subject.length > 0 && subject.length <= 240, 'invalid_subject', 'A bounded subject identifier is required.');
    assert(typeof audience === 'string' && audience.length > 0 && audience.length <= 240, 'invalid_audience', 'A bounded audience is required.');
    assert(typeof purpose === 'string' && purpose.length > 0 && purpose.length <= 160, 'invalid_purpose', 'A bounded purpose is required.');
    assert(typeof jurisdiction === 'string' && jurisdiction.length > 0 && jurisdiction.length <= 64, 'invalid_jurisdiction', 'A bounded jurisdiction label is required.');
    assert(typeof actor === 'string' && actor.length > 0 && actor.length <= 240, 'invalid_actor', 'A bounded actor identifier is required.');
    assert(Number.isInteger(ttl) && ttl >= 15 && ttl <= 3600, 'invalid_ttl', 'Credential TTL must be between 15 and 3600 seconds.');

    const now = this.credentials.now();
    const id = `urn:uuid:${crypto.randomUUID()}`;
    const payload = { iss: this.credentials.keys.issuer, sub: subject, aud: audience, iat: now, nbf: now, exp: now + ttl, jti: id, purpose, jurisdiction, claims };
    const token = await this.#sdJwt().issue(payload, { claims: { _sd: claimNames } }, { header: { kid: this.credentials.keys.activeKeyId, typ: 'nova+sd-jwt' } });
    const entry = this.ledger.append('privacy.sd_jwt_issued', actor, { id, subjectHash: sha256(subject), claimNames: [...claimNames].sort(), issuerJwtHash: issuerJwtHash(token), profile: SD_JWT_PROFILE });
    this.state.credentials.push(this.credentials.createCredentialRecord({ id, type: 'SelectiveDisclosureCredential', subject, format: 'nova+sd-jwt', issuerJwtHash: issuerJwtHash(token), createdAt: timestamp(), auditEntryId: entry.id }));
    this.state.credentialStatuses.push(this.credentials.createStatus(id, { auditEntryId: entry.id }));
    return { id, token, format: 'nova+sd-jwt', profile: SD_JWT_PROFILE, selectivelyDisclosableClaims: claimNames, status: 'active', auditReceipt: this.ledger.receipt(entry) };
  }

  async presentSelectiveDisclosure({ credentialToken, claimNames, audience, purpose, subject }) {
    assert(typeof credentialToken === 'string' && credentialToken.length > 0 && credentialToken.length <= 64_000, 'invalid_sd_jwt', 'A bounded SD-JWT credential is required.');
    assert(Array.isArray(claimNames) && claimNames.length > 0 && claimNames.length <= 100 && claimNames.every(name => typeof name === 'string' && name.length > 0 && name.length <= 160), 'invalid_disclosure_selection', 'One to one hundred bounded claim names are required.');
    assert(new Set(claimNames).size === claimNames.length, 'duplicate_disclosure_selection', 'Duplicate claim names are not accepted.');

    let full;
    let presentation;
    let verified;
    try {
      const verifyOptions = { allowedIssuerAlgorithms: ['EdDSA'], currentDate: this.credentials.now() };
      full = await this.#sdJwt().verify(credentialToken, verifyOptions);
      const available = full.payload?.claims && typeof full.payload.claims === 'object' ? Object.keys(full.payload.claims) : [];
      assert(claimNames.every(name => available.includes(name)), 'claim_not_presentable', 'A selected claim is not present in the SD-JWT.', 400);
      presentation = await this.#sdJwt().present(credentialToken, { claims: Object.fromEntries(claimNames.map(name => [name, true])) });
      verified = await this.#sdJwt().verify(presentation, { ...verifyOptions, requiredClaimKeys: claimNames.map(name => encodePath(['claims', name])) });
    } catch (error) {
      if (error?.code) throw error;
      fail('invalid_sd_jwt', 'SD-JWT verification or disclosure selection failed.', 401, { reason: error?.message || 'verification_failed' });
    }

    validateScope(verified.payload, { audience, purpose, subject }, this.credentials.now());
    assert(verified.payload.iss === this.credentials.keys.issuer, 'untrusted_issuer', 'The SD-JWT issuer is not trusted.', 403);
    const record = this.state.credentials.find(item => item.id === verified.payload.jti && item.format === 'nova+sd-jwt');
    assert(record && record.issuerJwtHash === issuerJwtHash(presentation), 'credential_not_admitted', 'The SD-JWT is not present in the local registry.', 403);
    this.credentials.verifyCredentialRecord(record);
    const status = this.credentials.status(verified.payload.jti);
    assert(status.state === 'active', 'credential_inactive', `Credential is ${status.state}.`, 403);
    assert(this.ledger.verify().valid, 'audit_integrity_failure', 'SD-JWT presentation requires a valid audit ledger.', 503);

    const disclosed = Object.fromEntries(claimNames.map(name => [name, verified.payload.claims[name]]));
    const entry = this.ledger.append('privacy.sd_jwt_presented', subject, { credentialId: verified.payload.jti, claimNames: [...claimNames].sort(), presentationHash: sha256(presentation), audience, purpose });
    return { verified: true, credentialId: verified.payload.jti, subject, disclosed, presentation, format: 'nova+sd-jwt', profile: SD_JWT_PROFILE, holderBinding: false, auditReceipt: this.ledger.receipt(entry) };
  }

  predicateProofCapabilities() {
    return {
      enabled: false,
      status: 'business_zkp_not_configured',
      reason: 'The former custom Schnorr proof has been removed. A maintained predicate-proof provider must be configured before age, qualification, balance-threshold, or eligibility proofs are exposed.',
      requiredProperties: ['predicate_proofs', 'holder_binding', 'revocation', 'schema_governance', 'independent_security_review'],
    };
  }
}
