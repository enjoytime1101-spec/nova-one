import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createKeyBundle, publicJwk } from '../src/crypto.mjs';
import { JsonStore } from '../src/store.mjs';
import { TrustLedger } from '../src/ledger.mjs';
import { CredentialService } from '../src/credentials.mjs';
import { sha256 } from '../src/canonical.mjs';

async function fixture(now = { value: Math.floor(Date.now() / 1000) }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-credential-'));
  const store = new JsonStore(path.join(directory, 'state.json'));
  const state = store.initialize();
  const keys = createKeyBundle();
  const ledger = new TrustLedger(state, keys);
  const credentials = new CredentialService(state, keys, ledger, { now: () => now.value });
  return { directory, state, keys, ledger, credentials, now };
}

test('credential issue, verify, presentation, replay and status lifecycle', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { audience: 'example-agent', purpose: 'verified-workflow', subject: 'did:example:alice' };
  const issued = f.credentials.issue({ type: 'IdentityCredential', ...scope, claims: { accountActive: true }, jurisdiction: 'AU', evidenceRoot: sha256('evidence') });
  assert.equal(f.credentials.verify(issued.token, scope).verified, true);

  const tampered = `${issued.token.slice(0, -3)}xxx`;
  assert.throws(() => f.credentials.verify(tampered, scope), error => error.code === 'invalid_signature');
  assert.throws(() => f.credentials.verify(issued.token, { ...scope, audience: 'other' }), error => error.code === 'audience_mismatch');

  const challenge = f.credentials.createChallenge(scope);
  const presentation = f.credentials.createPresentation({ challengeId: challenge.id, credentialToken: issued.token, subject: scope.subject });
  assert.equal(f.credentials.verifyPresentation(presentation.presentation, scope).verified, true);
  assert.throws(() => f.credentials.verifyPresentation(presentation.presentation, scope), error => error.code === 'challenge_replayed');

  const consumedChallenge = f.state.challenges.find(item => item.id === challenge.id);
  consumedChallenge.consumedAt = null;
  assert.throws(() => f.credentials.verifyPresentation(presentation.presentation, scope), error => error.code === 'challenge_integrity_failure');

  f.credentials.changeStatus(issued.id, 'suspended', scope.subject);
  assert.throws(() => f.credentials.verify(issued.token, scope), error => error.code === 'credential_inactive');
  f.credentials.changeStatus(issued.id, 'active', scope.subject);
  assert.equal(f.credentials.verify(issued.token, scope).verified, true);
  f.credentials.changeStatus(issued.id, 'revoked', scope.subject);
  assert.throws(() => f.credentials.changeStatus(issued.id, 'active', scope.subject), error => error.code === 'revocation_is_final');
  assert.equal(f.ledger.verify().valid, true);
});

test('expired credentials fail closed', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const input = { type: 'IdentityCredential', audience: 'agent', purpose: 'login', subject: 'did:example:bob', claims: { active: true }, ttl: 15 };
  const issued = f.credentials.issue(input);
  f.now.value += 16;
  assert.throws(() => f.credentials.verify(issued.token, input), error => error.code === 'expired_or_not_yet_valid');
});

test('credential issuance rejects subject-id replacement and non-JSON claim values', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { type: 'IdentityCredential', subject: 'did:example:alice', audience: 'relying-party', purpose: 'authenticate-user' };
  assert.throws(() => f.credentials.issue({ ...scope, claims: { id: 'did:example:mallory' } }), error => error.code === 'reserved_credential_claim');
  assert.throws(() => f.credentials.issue({ ...scope, claims: { invalid: undefined } }), error => error.code === 'invalid_credential_claims');
});

test('registered Ed25519 issuer credentials can be admitted with a fail-closed local status boundary', async t => {
  const target = await fixture();
  const source = await fixture();
  t.after(() => {
    fs.rmSync(target.directory, { recursive: true, force: true });
    fs.rmSync(source.directory, { recursive: true, force: true });
  });
  source.keys.issuer = 'https://issuer.example';
  const scope = { audience: 'relying-party', purpose: 'interop', subject: 'did:example:external' };
  const issued = source.credentials.issue({ type: 'IdentityCredential', ...scope, claims: { verified: true } });
  target.credentials.registerIssuer({ id: source.keys.issuer, keys: [publicJwk(source.keys)], types: ['IdentityCredential'] });
  const admitted = target.credentials.admit(issued.token, scope);
  assert.equal(admitted.external, true);
  assert.equal(admitted.statusFederation, false);
  assert.equal(target.credentials.verify(issued.token, scope).verified, true);
  target.credentials.changeStatus(admitted.id, 'revoked', 'nova:administrator');
  assert.throws(() => target.credentials.verify(issued.token, scope), error => error.code === 'credential_inactive');
});

test('credential verification rejects direct status-record tampering', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { audience: 'relying-party', purpose: 'login', subject: 'did:example:alice' };
  const issued = f.credentials.issue({ type: 'IdentityCredential', ...scope, claims: { verified: true } });
  f.credentials.changeStatus(issued.id, 'revoked', scope.subject);
  const status = f.state.credentialStatuses.find(item => item.credentialId === issued.id);
  status.state = 'active';
  assert.throws(() => f.credentials.verify(issued.token, scope), error => error.code === 'credential_status_integrity_failure');
  assert.equal(f.ledger.verify().valid, true);
});

test('credential verification rejects rollback to an older legitimately signed status record', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { audience: 'service-a', purpose: 'sign-in', subject: 'did:example:alice' };
  const issued = f.credentials.issue({ type: 'IdentityCredential', claims: { role: 'user' }, ...scope });
  const oldActiveStatus = structuredClone(f.state.credentialStatuses.find(item => item.credentialId === issued.id));
  f.credentials.changeStatus(issued.id, 'revoked', 'did:example:administrator');
  Object.assign(f.state.credentialStatuses.find(item => item.credentialId === issued.id), oldActiveStatus);
  assert.throws(() => f.credentials.verify(issued.token, scope), error => error.code === 'credential_status_rollback');
});

test('presentation verification rejects rollback to an older signed unconsumed challenge', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { audience: 'service-a', purpose: 'sign-in', subject: 'did:example:alice' };
  const issued = f.credentials.issue({ type: 'IdentityCredential', claims: { role: 'user' }, ...scope });
  const challenge = f.credentials.createChallenge(scope);
  const oldUnconsumed = structuredClone(f.state.challenges.find(item => item.id === challenge.id));
  const presentation = f.credentials.createPresentation({ challengeId: challenge.id, credentialToken: issued.token, subject: scope.subject });
  f.credentials.verifyPresentation(presentation.presentation, scope);
  Object.assign(f.state.challenges.find(item => item.id === challenge.id), oldUnconsumed);
  assert.throws(() => f.credentials.verifyPresentation(presentation.presentation, scope), error => error.code === 'challenge_state_rollback');
});

test('credential verification rejects direct admission-record tampering', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { audience: 'relying-party', purpose: 'login', subject: 'did:example:alice' };
  const issued = f.credentials.issue({ type: 'IdentityCredential', ...scope, claims: { verified: true } });
  const record = f.state.credentials.find(item => item.id === issued.id);
  record.type = 'PolicyDecisionCredential';
  assert.throws(() => f.credentials.verify(issued.token, scope), error => error.code === 'credential_registry_integrity_failure');
});

test('external issuer registry edits fail before a credential is trusted', async t => {
  const target = await fixture();
  const source = await fixture();
  t.after(() => {
    fs.rmSync(target.directory, { recursive: true, force: true });
    fs.rmSync(source.directory, { recursive: true, force: true });
  });
  source.keys.issuer = 'https://issuer.example';
  target.credentials.registerIssuer({
    id: source.keys.issuer,
    keys: [publicJwk(source.keys)],
    types: ['IdentityCredential'],
  });
  target.state.issuers[0].status = 'suspended';
  assert.throws(() => target.credentials.registry(), error => error.code === 'issuer_registry_integrity_failure');
});

test('external issuer suspension cannot be rolled back to an older signed registry row', async t => {
  const target = await fixture();
  const source = await fixture();
  t.after(() => {
    fs.rmSync(target.directory, { recursive: true, force: true });
    fs.rmSync(source.directory, { recursive: true, force: true });
  });
  source.keys.issuer = 'https://issuer.example';
  const scope = { audience: 'relying-party', purpose: 'interop', subject: 'did:example:external' };
  const issued = source.credentials.issue({ type: 'IdentityCredential', ...scope, claims: { verified: true } });
  const registration = { id: source.keys.issuer, keys: [publicJwk(source.keys)], types: ['IdentityCredential'] };
  target.credentials.registerIssuer({ ...registration, status: 'active' });
  target.credentials.admit(issued.token, scope);
  const oldActive = structuredClone(target.state.issuers[0]);
  target.credentials.registerIssuer({ ...registration, status: 'suspended' });
  assert.throws(() => target.credentials.verify(issued.token, scope), error => error.code === 'untrusted_issuer');
  Object.assign(target.state.issuers[0], oldActive);
  assert.throws(() => target.credentials.verify(issued.token, scope), error => error.code === 'issuer_registry_rollback');
});

test('external issuer registration validates identifier, types and actor', async t => {
  const f = await fixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const key = publicJwk(f.keys);
  assert.throws(() => f.credentials.registerIssuer({ id: 'https://issuer.example#fragment', keys: [key] }), error => error.code === 'invalid_issuer');
  assert.throws(() => f.credentials.registerIssuer({ id: 'https://issuer.example', keys: [key], types: 'IdentityCredential' }), error => error.code === 'invalid_issuer_types');
  assert.throws(() => f.credentials.registerIssuer({ id: 'https://issuer.example', keys: [key], types: ['UnknownCredential'] }), error => error.code === 'invalid_issuer_types');
  assert.throws(() => f.credentials.registerIssuer({ id: 'https://issuer.example', keys: [key] }, ''), error => error.code === 'invalid_actor');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateJwk = { ...privateKey.export({ format: 'jwk' }), kid: 'private-key-must-not-be-stored', use: 'sig', alg: 'EdDSA' };
  assert.throws(() => f.credentials.registerIssuer({ id: 'https://issuer.example', keys: [privateJwk] }), error => error.code === 'invalid_issuer_key');
  assert.equal(JSON.stringify(f.state.issuers).includes('private-key-must-not-be-stored'), false);
});
