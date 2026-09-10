import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createKeyBundle } from '../src/crypto.mjs';
import { CredentialService } from '../src/credentials.mjs';
import { TrustLedger } from '../src/ledger.mjs';
import { PrivacyService } from '../src/privacy.mjs';
import { JsonStore } from '../src/store.mjs';

function setup(initialNow = Math.floor(Date.now() / 1000)) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-privacy-'));
  const state = new JsonStore(path.join(directory, 'state.json')).initialize();
  const keys = createKeyBundle();
  const ledger = new TrustLedger(state, keys);
  let now = initialNow;
  const credentials = new CredentialService(state, keys, ledger, { now: () => now });
  return { directory, state, credentials, privacy: new PrivacyService(state, credentials, ledger), setNow: value => { now = value; } };
}

function replaceJwtHeader(token, changes) {
  const sections = token.split('~');
  const jwt = sections[0].split('.');
  const header = JSON.parse(Buffer.from(jwt[0], 'base64url').toString('utf8'));
  jwt[0] = Buffer.from(JSON.stringify({ ...header, ...changes })).toString('base64url');
  sections[0] = jwt.join('.');
  return sections.join('~');
}

test('RFC 9901 SD-JWT presents only selected claims and stores no raw attributes', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding', jurisdiction: 'AU' };
  const issued = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator', region: 'AU', secretNote: 'never disclose' } });
  assert.equal(issued.profile, 'nova-rfc9901-sd-jwt-0.2');
  assert.equal(JSON.stringify(f.state).includes('never disclose'), false);

  const result = await f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope });
  assert.deepEqual(result.disclosed, { role: 'operator' });
  assert.equal(result.presentation.includes(Buffer.from(JSON.stringify(['never disclose'])).toString('base64url')), false);
  assert.equal(JSON.stringify(result).includes('never disclose'), false);
  assert.equal(JSON.stringify(result).includes('region'), false);

  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['missing'], ...scope }),
    error => error.code === 'claim_not_presentable',
  );
});

test('RFC 9901 SD-JWT rejects tampered disclosures and wrong scope', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding' };
  const issued = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator' } });
  const parts = issued.token.split('~');
  const disclosure = Buffer.from(parts[1], 'base64url');
  disclosure[2] ^= 0xff;
  parts[1] = disclosure.toString('base64url');
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: parts.join('~'), claimNames: ['role'], ...scope }),
    error => error.code === 'invalid_sd_jwt',
  );
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope, audience: 'wrong' }),
    error => error.code === 'audience_mismatch',
  );
});

test('business predicate proof capability is explicitly disabled', t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  assert.deepEqual(f.privacy.predicateProofCapabilities(), {
    enabled: false,
    status: 'business_zkp_not_configured',
    reason: 'The former custom Schnorr proof has been removed. A maintained predicate-proof provider must be configured before age, qualification, balance-threshold, or eligibility proofs are exposed.',
    requiredProperties: ['predicate_proofs', 'holder_binding', 'revocation', 'schema_governance', 'independent_security_review'],
  });
});

test('selective-disclosure issuance rejects non-JSON claim values', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  await assert.rejects(
    f.privacy.issueSelectiveDisclosure({
      subject: 'did:example:holder',
      audience: 'agent',
      purpose: 'onboarding',
      claims: { invalid: undefined },
    }),
    error => error.code === 'invalid_disclosure_claims',
  );
});

test('RFC 9901 path encoding supports dots and tildes in selective claim names', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding' };
  const issued = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { 'a.b': 'dot', 'a~b': 'tilde' } });
  const result = await f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['a.b', 'a~b'], ...scope });
  assert.deepEqual(result.disclosed, { 'a.b': 'dot', 'a~b': 'tilde' });
});

test('RFC 9901 verification rejects unreferenced disclosures', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding' };
  const original = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator' } });
  const unrelated = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { injected: 'not referenced' } });
  const originalParts = original.token.split('~');
  const unrelatedDisclosure = unrelated.token.split('~')[1];
  originalParts.splice(originalParts.length - 1, 0, unrelatedDisclosure);
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: originalParts.join('~'), claimNames: ['role'], ...scope }),
    error => error.code === 'invalid_sd_jwt',
  );
});

test('RFC 9901 verification rejects header downgrade, expiry and every exact scope mismatch', async t => {
  const issuedAt = 1_800_000_000;
  const f = setup(issuedAt);
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding' };
  const issued = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator' }, ttl: 15 });
  for (const changes of [{ alg: 'none' }, { typ: 'sd-jwt' }]) {
    await assert.rejects(
      f.privacy.presentSelectiveDisclosure({ credentialToken: replaceJwtHeader(issued.token, changes), claimNames: ['role'], ...scope }),
      error => ['invalid_sd_jwt_header', 'invalid_sd_jwt'].includes(error.code),
    );
  }
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope, purpose: 'other' }),
    error => error.code === 'purpose_mismatch',
  );
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope, subject: 'did:example:other' }),
    error => error.code === 'subject_mismatch',
  );
  f.setNow(issuedAt + 15);
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope }),
    error => ['expired_or_not_yet_valid', 'invalid_sd_jwt'].includes(error.code),
  );
});

test('RFC 9901 local admission and status projections reject tamper and signed rollback', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding' };
  const issued = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator' } });
  const record = f.state.credentials.find(item => item.id === issued.id);
  record.createdAt = '2000-01-01T00:00:00.000Z';
  await assert.rejects(
    f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope }),
    error => error.code === 'credential_registry_integrity_failure',
  );

  const clean = setup();
  t.after(() => fs.rmSync(clean.directory, { recursive: true, force: true }));
  const current = await clean.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator' } });
  const oldStatus = structuredClone(clean.state.credentialStatuses.find(item => item.credentialId === current.id));
  clean.credentials.changeStatus(current.id, 'revoked', 'nova:administrator');
  clean.state.credentialStatuses[0] = oldStatus;
  await assert.rejects(
    clean.privacy.presentSelectiveDisclosure({ credentialToken: current.token, claimNames: ['role'], ...scope }),
    error => error.code === 'credential_status_rollback',
  );
});

test('RFC 9901 holder token is replayable until holder binding is implemented', async t => {
  const f = setup();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const scope = { subject: 'did:example:holder', audience: 'agent', purpose: 'onboarding' };
  const issued = await f.privacy.issueSelectiveDisclosure({ ...scope, claims: { role: 'operator' } });
  const first = await f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope });
  const replay = await f.privacy.presentSelectiveDisclosure({ credentialToken: issued.token, claimNames: ['role'], ...scope });
  assert.equal(first.holderBinding, false);
  assert.equal(replay.holderBinding, false);
  assert.notEqual(first.auditReceipt.entry.id, replay.auditReceipt.entry.id);
});
