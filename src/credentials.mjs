import crypto from 'node:crypto';
import { canonical, isPlainObject, randomId, sha256, timestamp } from './canonical.mjs';
import { assert } from './errors.mjs';
import { decodeCompactJwt, publicJwk, signBytes, signCompactJwt, verifyBytes, verifyCompactJwt } from './crypto.mjs';
import { assertJsonSchema } from './sources.mjs';

const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const credentialTypes = new Set(['IdentityCredential', 'DataSourceCredential', 'DataSnapshotCredential', 'AgentOutputCredential', 'PolicyDecisionCredential', 'ActionReceiptCredential']);

export class CredentialService {
  constructor(state, keys, ledger, { now = () => Math.floor(Date.now() / 1000) } = {}) {
    this.state = state;
    this.keys = keys;
    this.ledger = ledger;
    this.now = now;
  }

  registry() {
    const external = this.state.issuers.map(record => this.verifyRegistryRecord(record));
    return [{ id: this.keys.issuer, status: 'active', keys: Object.keys(this.keys.keys).map(keyId => publicJwk(this.keys, keyId)), local: true }, ...external];
  }

  createCredentialRecord(record) {
    const unsigned = structuredClone(record);
    return { ...unsigned, registrySignature: { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(unsigned)) } };
  }

  verifyCredentialRecord(record) {
    assert(record?.registrySignature?.alg === 'EdDSA', 'credential_registry_integrity_failure', 'Credential admission record is not signed.', 503);
    const { registrySignature, ...unsigned } = record;
    assert(verifyBytes(publicJwk(this.keys, registrySignature.keyId), canonical(unsigned), registrySignature.value), 'credential_registry_integrity_failure', 'Credential admission record signature is invalid.', 503);
    return record;
  }

  verifyRegistryRecord(record) {
    assert(record?.registrySignature?.alg === 'EdDSA', 'issuer_registry_integrity_failure', 'Issuer registry record is not signed.', 503);
    const { registrySignature, ...unsigned } = record;
    assert(verifyBytes(publicJwk(this.keys, registrySignature.keyId), canonical(unsigned), registrySignature.value), 'issuer_registry_integrity_failure', 'Issuer registry record signature is invalid.', 503);
    assert(this.ledger.verify().valid, 'audit_integrity_failure', 'Issuer registry verification requires a valid audit ledger.', 503);
    const prefix = `issuer-register:${sha256(record.id)}:`;
    const revisions = this.state.auditEntries.filter(entry => entry.event === 'issuer.registered' && entry.idempotencyKey.startsWith(prefix));
    const latest = revisions.at(-1);
    const projection = { issuerHash: sha256(record.id), keyIds: record.keys.map(key => key.kid), status: record.status, types: record.types };
    assert(latest && latest.id === record.auditEntryId && latest.payloadHash === sha256(projection)
      && record.revision === revisions.length, 'issuer_registry_rollback', 'Issuer registry state is older than the current audit ledger.', 503);
    return record;
  }

  createStatus(credentialId, { source = 'local-issuance', auditEntryId } = {}) {
    const unsigned = { id: randomId('status'), credentialId, state: 'active', source, updatedAt: timestamp(), auditEntryId };
    return { ...unsigned, signature: { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(unsigned)) } };
  }

  #signChallenge(record) {
    const unsigned = structuredClone(record);
    delete unsigned.signature;
    return {
      ...unsigned,
      signature: {
        alg: 'EdDSA',
        keyId: this.keys.activeKeyId,
        value: signBytes(this.keys, canonical(unsigned)),
      },
    };
  }

  #verifyChallengeRecord(record) {
    assert(record?.signature?.alg === 'EdDSA', 'challenge_integrity_failure', 'Challenge state is not signed.', 503);
    const { signature, ...unsigned } = record;
    assert(verifyBytes(publicJwk(this.keys, signature.keyId), canonical(unsigned), signature.value), 'challenge_integrity_failure', 'Challenge state signature is invalid.', 503);
    assert(this.ledger.verify().valid, 'audit_integrity_failure', 'Challenge verification requires a valid audit ledger.', 503);
    const created = this.state.auditEntries.find(entry => entry.id === record.auditEntryId);
    const expectedCreatedPayload = {
      challengeId: record.id,
      kind: record.kind,
      scopeHash: sha256({ audience: record.audience, purpose: record.purpose, subject: record.subject }),
      nonceHash: sha256(record.nonce),
      expiresAt: record.expiresAt,
    };
    assert(created?.event === 'challenge.created' && created.payloadHash === sha256(expectedCreatedPayload), 'challenge_state_rollback', 'Challenge creation state is not bound to the current audit ledger.', 503);
    const consumed = this.state.auditEntries.find(entry => entry.idempotencyKey === `challenge-consumed:${record.id}`);
    if (consumed) {
      assert(['presentation.verified', 'challenge.consumed'].includes(consumed.event)
        && typeof record.consumedAt === 'string'
        && record.consumptionAuditEntryId === consumed.id,
      'challenge_state_rollback', 'Challenge consumption state is older than the current audit ledger.', 503);
    } else {
      assert(record.consumedAt === null && record.consumptionAuditEntryId === null, 'challenge_state_rollback', 'Challenge consumption state has no matching audit event.', 503);
    }
    return record;
  }

  #verifyStatusRecord(status) {
    assert(status?.signature?.alg === 'EdDSA' && typeof status.signature.keyId === 'string' && typeof status.signature.value === 'string', 'credential_status_integrity_failure', 'Credential status is not signed.', 503);
    const { signature, ...unsigned } = status;
    assert(verifyBytes(publicJwk(this.keys, signature.keyId), canonical(unsigned), signature.value), 'credential_status_integrity_failure', 'Credential status signature is invalid.', 503);
    assert(this.ledger.verify().valid, 'audit_integrity_failure', 'Credential status verification requires a valid audit ledger.', 503);
    const allowedStates = ['active', 'suspended', 'revoked'];
    const changeHashes = new Set(allowedStates.map(state => sha256({ credentialId: status.credentialId, state })));
    const changes = this.state.auditEntries.filter(entry => entry.event === 'credential.status_changed' && changeHashes.has(entry.payloadHash));
    const latest = changes.at(-1);
    if (latest) {
      assert(status.auditEntryId === latest.id
        && status.state === allowedStates.find(state => sha256({ credentialId: status.credentialId, state }) === latest.payloadHash),
      'credential_status_rollback', 'Credential status is older than the current audit ledger.', 503);
    } else {
      const initial = this.state.auditEntries.find(entry => entry.id === status.auditEntryId);
      assert(status.state === 'active'
        && ['credential.issued', 'credential.admitted', 'privacy.sd_jwt_issued'].includes(initial?.event),
      'credential_status_rollback', 'Credential status is not bound to its issuance audit event.', 503);
    }
    return status;
  }

  registerIssuer({ id, keys, status = 'active', types = [] }, actor = 'nova:administrator') {
    assert(typeof id === 'string' && id.length > 0 && id.length <= 512, 'invalid_issuer', 'External issuers require a bounded HTTPS identifier.');
    let issuerUrl;
    try { issuerUrl = new URL(id); } catch { assert(false, 'invalid_issuer', 'External issuers require a valid HTTPS identifier.'); }
    assert(issuerUrl.protocol === 'https:' && issuerUrl.hostname && !issuerUrl.username && !issuerUrl.password && !issuerUrl.hash, 'invalid_issuer', 'External issuers require a credential-free HTTPS identifier.');
    assert(['active', 'suspended'].includes(status), 'invalid_issuer_status', 'Issuer status must be active or suspended.');
    assert(Array.isArray(types) && types.length <= credentialTypes.size && new Set(types).size === types.length
      && types.every(type => credentialTypes.has(type)), 'invalid_issuer_types', 'Issuer credential types must be a distinct list of supported types.');
    assert(typeof actor === 'string' && actor.length > 0 && actor.length <= 240, 'invalid_actor', 'A bounded issuer-registration actor is required.');
    assert(Array.isArray(keys) && keys.length > 0 && keys.length <= 8, 'invalid_issuer_keys', 'One to eight issuer keys are required.');
    const seen = new Set();
    const normalizedKeys = keys.map(key => {
      const allowed = new Set(['kty', 'crv', 'x', 'kid', 'use', 'alg']);
      assert(isPlainObject(key) && Object.keys(key).every(name => allowed.has(name))
        && key.kty === 'OKP' && key.crv === 'Ed25519'
        && typeof key.x === 'string' && /^[A-Za-z0-9_-]{43}$/.test(key.x)
        && typeof key.kid === 'string' && key.kid.length > 0 && key.kid.length <= 200
        && (key.use === undefined || key.use === 'sig')
        && (key.alg === undefined || key.alg === 'EdDSA')
        && !seen.has(key.kid), 'invalid_issuer_key', 'Issuer keys must be distinct public-only Ed25519 JWKs.');
      seen.add(key.kid);
      crypto.createPublicKey({ key, format: 'jwk' });
      return { kty: 'OKP', crv: 'Ed25519', x: key.x, kid: key.kid, use: 'sig', alg: 'EdDSA' };
    });
    const existing = this.state.issuers.find(item => item.id === id);
    if (existing) this.verifyRegistryRecord(existing);
    const revision = (existing?.revision || 0) + 1;
    const projection = { issuerHash: sha256(id), keyIds: normalizedKeys.map(key => key.kid), status, types };
    const entry = this.ledger.append('issuer.registered', actor, projection, `issuer-register:${sha256(id)}:${revision}`);
    const unsigned = { id, keys: normalizedKeys, types, status, revision, updatedAt: timestamp(), auditEntryId: entry.id };
    const row = { ...unsigned, registrySignature: { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(unsigned)) } };
    if (existing) Object.assign(existing, row); else this.state.issuers.push(row);
    return { ...row, auditReceipt: this.ledger.receipt(entry), statusFederation: false };
  }

  admit(token, { audience, purpose, subject, actor = 'nova:administrator' } = {}) {
    const preview = decodeCompactJwt(token);
    assert(preview.payload.iss !== this.keys.issuer, 'issuer_conflict', 'Locally issued credentials are already admitted.', 409);
    assert(!this.state.credentials.some(item => item.id === preview.payload.id), 'credential_already_admitted', 'Credential is already admitted.', 409);
    assert(typeof subject === 'string' && subject.length > 0 && subject.length <= 240, 'expected_subject_required', 'Credential admission requires an expected subject.');
    const decoded = verifyCompactJwt(token, { trustedIssuers: this.registry(), audience, subject, typ: 'vc+jwt', now: this.now() });
    const document = decoded.payload;
    assert(document['@context']?.[0] === VC_CONTEXT && document.type?.[0] === 'VerifiableCredential' && document.purpose === purpose, 'invalid_vc_profile', 'The external credential does not match the admitted profile.', 403);
    assert(document.id === document.jti && document.issuer === document.iss && document.credentialSubject?.id === document.sub, 'invalid_vc_binding', 'External credential identifiers are not bound correctly.', 403);
    const type = document.type[1];
    const issuer = this.registry().find(item => item.id === document.iss);
    assert(!issuer.types?.length || issuer.types.includes(type), 'issuer_type_not_allowed', 'Issuer is not registered for this credential type.', 403);
    const entry = this.ledger.append('credential.admitted', actor, { id: document.id, issuerHash: sha256(document.iss), tokenHash: sha256(token) });
    this.state.credentials.push(this.createCredentialRecord({ id: document.id, type, subject: document.sub, token, document, external: true, createdAt: timestamp(), auditEntryId: entry.id }));
    this.state.credentialStatuses.push(this.createStatus(document.id, { source: 'local-admission', auditEntryId: entry.id }));
    return { id: document.id, type, subject: document.sub, status: 'active', external: true, statusFederation: false, auditReceipt: this.ledger.receipt(entry) };
  }

  issue({ type, subject, claims, audience, purpose, jurisdiction = 'GLOBAL', ttl = 300, evidenceRoot = sha256('no-external-evidence'), actor = subject }) {
    assert(credentialTypes.has(type), 'unsupported_credential_type', 'The credential type is not supported.');
    assert(typeof subject === 'string' && subject.length > 0 && subject.length <= 240, 'invalid_subject', 'A bounded subject identifier is required.');
    assert(isPlainObject(claims), 'invalid_credential_claims', 'Credential claims must be a plain JSON object.');
    assert(!Object.hasOwn(claims, 'id'), 'reserved_credential_claim', 'Credential claims cannot replace the credential subject identifier.');
    assertJsonSchema(claims, { type: 'object', additionalProperties: true }, 'invalid_credential_claims');
    assert(typeof audience === 'string' && audience.length > 0 && audience.length <= 240, 'invalid_audience', 'A bounded audience is required.');
    assert(typeof purpose === 'string' && purpose.length > 0 && purpose.length <= 160, 'invalid_purpose', 'A bounded purpose is required.');
    assert(typeof jurisdiction === 'string' && jurisdiction.length > 0 && jurisdiction.length <= 64, 'invalid_jurisdiction', 'A bounded jurisdiction label is required.');
    assert(typeof evidenceRoot === 'string' && /^[0-9a-f]{64}$/.test(evidenceRoot), 'invalid_evidence_root', 'The evidence root must be a lowercase SHA-256 hex digest.');
    assert(typeof actor === 'string' && actor.length > 0 && actor.length <= 240, 'invalid_actor', 'A bounded actor identifier is required.');
    assert(Number.isInteger(ttl) && ttl >= 15 && ttl <= 3600, 'invalid_ttl', 'Credential TTL must be between 15 and 3600 seconds.');
    const id = `urn:uuid:${crypto.randomUUID()}`;
    const now = this.now();
    const document = {
      '@context': [VC_CONTEXT, { '@vocab': `${this.keys.issuer}/vocab#` }],
      id, type: ['VerifiableCredential', type], issuer: this.keys.issuer,
      validFrom: new Date(now * 1000).toISOString(), validUntil: new Date((now + ttl) * 1000).toISOString(),
      credentialSubject: { id: subject, ...claims },
      credentialSchema: { id: `${this.keys.issuer}/schemas/${type}/1`, type: 'JsonSchema' },
      credentialStatus: { id: `${this.keys.issuer}/v1/credentials/${encodeURIComponent(id)}/status`, type: 'NovaCredentialStatus2026' },
      audience, purpose, jurisdiction, evidenceRoot, profile: 'nova-vc-jose-0.1',
    };
    const token = signCompactJwt(this.keys, { ...document, jti: id }, { typ: 'vc+jwt', audience, subject, expiresIn: ttl, now });
    const entry = this.ledger.append('credential.issued', actor, { id, type, tokenHash: sha256(token), evidenceRoot });
    this.state.credentials.push(this.createCredentialRecord({ id, type, subject, token, document, createdAt: timestamp(), auditEntryId: entry.id }));
    this.state.credentialStatuses.push(this.createStatus(id, { auditEntryId: entry.id }));
    return { id, type, token, document, status: 'active', auditReceipt: this.ledger.receipt(entry) };
  }

  status(id) {
    const status = this.state.credentialStatuses.find(item => item.credentialId === id);
    assert(status, 'credential_status_unavailable', 'Credential status is unavailable.', 404);
    return this.#verifyStatusRecord(status);
  }

  changeStatus(id, state, actor) {
    assert(['active', 'suspended', 'revoked'].includes(state), 'invalid_status', 'Credential status is invalid.');
    const status = this.status(id);
    assert(status.state !== 'revoked' || state === 'revoked', 'revocation_is_final', 'A revoked credential cannot be reactivated.', 409);
    status.state = state;
    status.updatedAt = timestamp();
    const entry = this.ledger.append('credential.status_changed', actor, { credentialId: id, state });
    status.auditEntryId = entry.id;
    const { signature: _previous, ...unsigned } = status;
    status.signature = { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(unsigned)) };
    return { ...status, auditReceipt: this.ledger.receipt(entry) };
  }

  verify(token, { audience, purpose, subject, allowUntrustedFixture = false } = {}) {
    assert(typeof audience === 'string' && audience.length > 0, 'expected_audience_required', 'Credential verification requires an expected audience.');
    assert(typeof purpose === 'string' && purpose.length > 0, 'expected_purpose_required', 'Credential verification requires an expected purpose.');
    assert(typeof subject === 'string' && subject.length > 0, 'expected_subject_required', 'Credential verification requires an expected subject.');
    const decoded = verifyCompactJwt(token, { trustedIssuers: this.registry(), audience, subject, typ: 'vc+jwt', now: this.now() });
    const document = decoded.payload;
    assert(document['@context']?.[0] === VC_CONTEXT && document.type?.[0] === 'VerifiableCredential' && credentialTypes.has(document.type?.[1]), 'invalid_vc_profile', 'The credential does not match the NOVA VC profile.', 403);
    assert(document.purpose === purpose, 'purpose_mismatch', 'Credential purpose does not match.', 403);
    assert(document.id === document.jti && document.issuer === document.iss && document.credentialSubject?.id === document.sub, 'invalid_vc_binding', 'Credential identifiers are not bound correctly.', 403);
    const record = this.state.credentials.find(item => item.id === document.id);
    assert(record && sha256(record.token) === sha256(token), 'credential_not_admitted', 'Credential is not present in the local registry.', 403);
    this.verifyCredentialRecord(record);
    const status = this.status(document.id);
    assert(status.state === 'active', 'credential_inactive', `Credential is ${status.state}.`, 403);
    assert(this.ledger.verify().valid, 'audit_integrity_failure', 'Credential verification requires a valid audit ledger.', 503);
    assert(document.credentialSubject?.trustLevel !== 'untrusted-fixture' || allowUntrustedFixture === true, 'untrusted_fixture_credential', 'Fixture credentials are not accepted by the production verification path.', 403);
    return { verified: true, id: document.id, type: document.type[1], subject: document.sub, claims: document.credentialSubject, audience, purpose, status: status.state, expiresAt: document.validUntil };
  }

  createChallenge({ audience, purpose, subject, ttl = 120, kind = 'presentation' }) {
    assert(typeof audience === 'string' && audience.length > 0 && audience.length <= 240, 'invalid_challenge', 'A bounded challenge audience is required.');
    assert(typeof purpose === 'string' && purpose.length > 0 && purpose.length <= 160, 'invalid_challenge', 'A bounded challenge purpose is required.');
    assert(typeof subject === 'string' && subject.length > 0 && subject.length <= 240, 'invalid_challenge', 'A bounded challenge subject is required.');
    assert(kind === 'presentation', 'invalid_challenge_kind', 'Only presentation challenges are supported.');
    assert(Number.isInteger(ttl) && ttl >= 15 && ttl <= 600, 'invalid_challenge_ttl', 'Challenge TTL must be between 15 and 600 seconds.');
    const id = randomId('challenge');
    const nonce = randomId('nonce');
    const expiresAt = this.now() + ttl;
    const entry = this.ledger.append('challenge.created', subject, {
      challengeId: id,
      kind,
      scopeHash: sha256({ audience, purpose, subject }),
      nonceHash: sha256(nonce),
      expiresAt,
    });
    const record = this.#signChallenge({
      id,
      nonce,
      kind,
      audience,
      purpose,
      subject,
      expiresAt,
      consumedAt: null,
      createdAt: timestamp(this.now() * 1000),
      auditEntryId: entry.id,
      consumptionAuditEntryId: null,
    });
    this.state.challenges.push(record);
    return { id: record.id, nonce: record.nonce, audience, purpose, expiresAt: new Date(record.expiresAt * 1000).toISOString() };
  }

  createPresentation({ challengeId, credentialToken, subject }) {
    const challenge = this.#challenge(challengeId, subject, 'presentation', true);
    const credential = this.verify(credentialToken, { audience: challenge.audience, purpose: challenge.purpose, subject });
    const token = signCompactJwt(this.keys, { nonce: challenge.nonce, challengeId, credential: credentialToken, credentialHash: sha256(credentialToken) }, { typ: 'vp+jwt', audience: challenge.audience, subject, expiresIn: Math.max(15, challenge.expiresAt - this.now()), now: this.now() });
    return { presentation: token, credentialId: credential.id };
  }

  verifyPresentation(token, { audience, purpose, subject } = {}) {
    assert(typeof audience === 'string' && audience.length > 0, 'expected_audience_required', 'Presentation verification requires an expected audience.');
    assert(typeof purpose === 'string' && purpose.length > 0, 'expected_purpose_required', 'Presentation verification requires an expected purpose.');
    assert(typeof subject === 'string' && subject.length > 0, 'expected_subject_required', 'Presentation verification requires an expected subject.');
    const decoded = verifyCompactJwt(token, { trustedIssuers: this.registry(), audience, subject, typ: 'vp+jwt', now: this.now() });
    const challenge = this.#challenge(decoded.payload.challengeId, decoded.payload.sub, 'presentation', true);
    assert(challenge.nonce === decoded.payload.nonce && challenge.audience === audience && challenge.purpose === purpose, 'challenge_mismatch', 'Presentation challenge binding failed.', 403);
    assert(sha256(decoded.payload.credential) === decoded.payload.credentialHash, 'credential_binding_failed', 'Presentation credential binding failed.', 403);
    const verified = this.verify(decoded.payload.credential, { audience, purpose, subject: decoded.payload.sub });
    challenge.consumedAt = timestamp(this.now() * 1000);
    const entry = this.ledger.append('presentation.verified', decoded.payload.sub, { challengeId: challenge.id, credentialId: verified.id }, `challenge-consumed:${challenge.id}`);
    challenge.consumptionAuditEntryId = entry.id;
    Object.assign(challenge, this.#signChallenge(challenge));
    return { verified: true, credential: verified, challengeId: challenge.id };
  }

  consumeChallenge(id, subject, kind) {
    const challenge = this.#challenge(id, subject, kind, true);
    challenge.consumedAt = timestamp(this.now() * 1000);
    const entry = this.ledger.append('challenge.consumed', subject, { challengeId: challenge.id, kind }, `challenge-consumed:${challenge.id}`);
    challenge.consumptionAuditEntryId = entry.id;
    Object.assign(challenge, this.#signChallenge(challenge));
    return challenge;
  }

  #challenge(id, subject, kind, mustBeUsable) {
    const challenge = this.state.challenges.find(item => item.id === id && item.subject === subject && item.kind === kind);
    assert(challenge, 'challenge_not_found', 'Challenge was not found.', 404);
    this.#verifyChallengeRecord(challenge);
    if (mustBeUsable) {
      assert(!challenge.consumedAt, 'challenge_replayed', 'Challenge has already been consumed.', 409);
      assert(challenge.expiresAt > this.now(), 'challenge_expired', 'Challenge has expired.', 403);
    }
    return challenge;
  }
}
