import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { createNovaToolExecutor, NOVA_TOOL_CONTRACTS } from '../agent-tools/index.mjs';
import { createHttpHandler, startNovaHttpServer } from '../src/http.mjs';
import { createNovaService } from '../src/service.mjs';
import { FixtureSourceAdapter } from '../src/sources.mjs';

function setup(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-tooling-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const service = createNovaService({ home });
  const initialized = service.initialize({ issuer: 'https://tooling.test/nova' });
  return { service, token: initialized.apiToken };
}

async function request(handler, { method = 'POST', url, token, body } = {}) {
  const encoded = body === undefined ? null : Buffer.from(JSON.stringify(body));
  const headers = {
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    ...(encoded ? { 'content-type': 'application/json', 'content-length': String(encoded.length) } : {}),
  };
  const input = Readable.from(encoded ? [encoded] : []);
  input.method = method;
  input.url = url;
  input.headers = headers;
  let status;
  let responseHeaders;
  const output = [];
  const response = {
    writeHead(value, values) { status = value; responseHeaders = values; },
    end(value) { if (value) output.push(Buffer.from(value)); },
  };
  await handler(input, response);
  const raw = Buffer.concat(output).toString('utf8');
  return { status, headers: responseHeaders, body: raw ? JSON.parse(raw) : null };
}

const scope = {
  subject: 'did:example:privacy-holder',
  audience: 'tooling-test',
  purpose: 'prove-minimal-facts',
};

test('initialisation rejects structurally weak caller-supplied bearer tokens', t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-token-policy-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const service = createNovaService({ home });
  assert.throws(
    () => service.initialize({ issuer: 'https://tooling.test/nova', apiToken: 'a'.repeat(64) }),
    error => error.code === 'weak_api_token',
  );
  assert.throws(
    () => service.initialize({ issuer: 'http://tooling.test/nova' }),
    error => error.code === 'invalid_issuer',
  );
});

test('CLI entrypoint runs when invoked through an npm-style symlink', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-cli-link-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const link = path.join(directory, 'nova-one');
  fs.symlinkSync(fileURLToPath(new URL('../bin/nova-one.mjs', import.meta.url)), link);
  const result = spawnSync(link, ['help'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /nova-one - local verifiable trust infrastructure/);
});

test('agent tools enforce strict top-level schemas and execute privacy and presentation flows', async t => {
  const { service } = setup(t);
  const agent = createNovaToolExecutor({ service });
  assert.ok(NOVA_TOOL_CONTRACTS.length >= 13);
  for (const contract of NOVA_TOOL_CONTRACTS) {
    assert.equal(contract.inputSchema.type, 'object');
    assert.equal(contract.inputSchema.additionalProperties, false, `${contract.name} must reject unknown top-level input`);
  }
  await assert.rejects(agent.callTool('nova_create_zkp_key', {}), error => error.code === 'unknown_tool');

  const selective = await agent.callTool('nova_issue_selective_disclosure', {
    ...scope,
    claims: { role: 'operator', region: 'AU', privateNote: 'not presented' },
  });
  const disclosed = await agent.callTool('nova_present_selective_disclosure', {
    ...scope,
    credentialToken: selective.token,
    claimNames: ['role'],
  });
  assert.deepEqual(disclosed.disclosed, { role: 'operator' });
  assert.equal(JSON.stringify(service.store.read()).includes('not presented'), false);

  const proofStatus = await agent.callTool('nova_predicate_proof_capabilities', {});
  assert.equal(proofStatus.enabled, false);
  assert.equal(proofStatus.status, 'business_zkp_not_configured');

  const credential = await agent.callTool('nova_issue_credential', {
    type: 'IdentityCredential', ...scope, claims: { role: 'operator' },
  });
  const challengeForPresentation = await agent.callTool('nova_create_presentation_challenge', scope);
  const presentation = await agent.callTool('nova_create_presentation', {
    challengeId: challengeForPresentation.id,
    credentialToken: credential.token,
    subject: scope.subject,
  });
  const presentationResult = await agent.callTool('nova_verify_presentation', {
    token: presentation.presentation,
    ...scope,
  });
  assert.equal(presentationResult.verified, true);
  await assert.rejects(
    agent.callTool('nova_verify_presentation', { token: presentation.presentation, ...scope }),
    error => error.code === 'challenge_replayed',
  );
});

test('HTTP JSON API executes privacy and presentation flows with bearer protection', async t => {
  const { service, token } = setup(t);
  const handler = createHttpHandler({ service, bodyLimit: 128 * 1024 });
  const unauthorized = await request(handler, { method: 'POST', url: '/v1/privacy/zkp/keys', body: {} });
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.body.error, 'authorization_required');
  const weakAuthorization = await request(handler, { method: 'GET', url: '/v1/status', token: 'a'.repeat(64) });
  assert.equal(weakAuthorization.status, 401);
  assert.equal(weakAuthorization.body.error, 'invalid_token');

  const issued = await request(handler, {
    url: '/v1/privacy/selective-disclosures/issue', token,
    body: { ...scope, claims: { role: 'operator', privateNote: 'not presented over HTTP' } },
  });
  assert.equal(issued.status, 200);
  const presented = await request(handler, {
    url: '/v1/privacy/selective-disclosures/present', token,
    body: { ...scope, credentialToken: issued.body.result.token, claimNames: ['role'] },
  });
  assert.equal(presented.status, 200);
  assert.deepEqual(presented.body.result.disclosed, { role: 'operator' });

  const proofStatus = await request(handler, { method: 'GET', url: '/v1/privacy/predicate-proofs/capabilities', token });
  assert.equal(proofStatus.status, 200);
  assert.equal(proofStatus.body.result.enabled, false);
  const removedProof = await request(handler, { url: '/v1/privacy/zkp/keys', token, body: {} });
  assert.equal(removedProof.status, 410);
  assert.equal(removedProof.body.error, 'experimental_proof_disabled');

  const identity = await request(handler, {
    url: '/v1/credentials/issue', token,
    body: { type: 'IdentityCredential', ...scope, claims: { role: 'operator' } },
  });
  const presentationChallenge = await request(handler, {
    url: '/v1/credentials/presentations/challenges', token, body: scope,
  });
  const presentation = await request(handler, {
    url: '/v1/credentials/presentations/create', token,
    body: {
      challengeId: presentationChallenge.body.result.id,
      credentialToken: identity.body.result.token,
      subject: scope.subject,
    },
  });
  const verifiedPresentation = await request(handler, {
    url: '/v1/credentials/presentations/verify', token,
    body: { token: presentation.body.result.presentation, ...scope },
  });
  assert.equal(verifiedPresentation.status, 200);
  assert.equal(verifiedPresentation.body.result.verified, true);
  const replay = await request(handler, {
    url: '/v1/credentials/presentations/verify', token,
    body: { token: presentation.body.result.presentation, ...scope },
  });
  assert.equal(replay.status, 409);
  assert.equal(replay.body.error, 'challenge_replayed');
});

test('HTTP production boundary enforces tool schemas, scope and fixture isolation', async t => {
  const { service, token } = setup(t);
  const handler = createHttpHandler({ service, bodyLimit: 128 * 1024 });

  const invalidTool = await request(handler, {
    url: '/v1/tools/call', token,
    body: { name: 'nova_predicate_proof_capabilities', input: { unexpected: true } },
  });
  assert.equal(invalidTool.status, 422);
  assert.equal(invalidTool.body.error, 'tool_input_invalid');

  const issued = await request(handler, {
    url: '/v1/credentials/issue', token,
    body: { type: 'IdentityCredential', ...scope, claims: { active: true } },
  });
  const missingScope = await request(handler, {
    url: '/v1/credentials/verify', token,
    body: { token: issued.body.result.token, audience: scope.audience, purpose: scope.purpose },
  });
  assert.equal(missingScope.status, 400);
  assert.equal(missingScope.body.error, 'expected_subject_required');

  const selfCertifiedAgentOutput = await request(handler, {
    url: '/v1/credentials/issue', token,
    body: {
      type: 'AgentOutputCredential',
      ...scope,
      claims: { trustLevel: 'source-backed', outputHash: 'self-asserted' },
    },
  });
  assert.equal(selfCertifiedAgentOutput.status, 403);
  assert.equal(selfCertifiedAgentOutput.body.error, 'reserved_credential_type');

  const fixtureResult = await service.runDemo(scope);
  const fixtureOverrideAttempt = await request(handler, {
    url: '/v1/credentials/verify', token,
    body: {
      token: fixtureResult.workflow.agentCredential.token,
      ...scope,
      allowUntrustedFixture: true,
    },
  });
  assert.equal(fixtureOverrideAttempt.status, 403);
  assert.equal(fixtureOverrideAttempt.body.error, 'untrusted_fixture_credential');

  const directFixture = await request(handler, {
    url: '/v1/workflows/run', token,
    body: { ...scope, claims: { selfAsserted: true } },
  });
  assert.equal(directFixture.status, 403);
  assert.equal(directFixture.body.error, 'fixture_workflow_forbidden');

  const toolFixture = await request(handler, {
    url: '/v1/tools/call', token,
    body: { name: 'nova_run_workflow', input: { ...scope, claims: { selfAsserted: true } } },
  });
  assert.equal(toolFixture.status, 403);
  assert.equal(toolFixture.body.error, 'fixture_workflow_forbidden');

  const demo = await request(handler, { url: '/v1/demo', token, body: {} });
  assert.equal(demo.status, 403);
  assert.equal(demo.body.error, 'fixture_workflow_forbidden');
});

test('HTTP production workflow rejects a configured fixture adapter', async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-http-fixture-adapter-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const fixtureSource = new FixtureSourceAdapter({ id: 'configured-fixture', payload: { claims: { rate: 0.25 } } });
  const externalAgent = {
    id: 'configured-external-agent', kind: 'external', contract: 'nova-agent-adapter-0.1',
    async generate() { throw new Error('must not run'); },
  };
  const service = createNovaService({ home, allowNetwork: true, allowModel: true, network: [fixtureSource], model: externalAgent });
  const { apiToken } = service.initialize({ issuer: 'https://tooling.test/nova' });
  const handler = createHttpHandler({ service, bodyLimit: 128 * 1024 });
  const response = await request(handler, {
    url: '/v1/workflows/run', token: apiToken,
    body: {
      ...scope,
      sourceIds: ['configured-fixture'], claims: ['rate'],
      authorization: { approvedBy: scope.subject, claims: ['rate'] },
    },
  });
  assert.equal(response.status, 403);
  assert.equal(response.body.error, 'fixture_source_forbidden');
});

test('built-in plaintext server rejects non-loopback bind addresses before listen', async () => {
  await assert.rejects(
    startNovaHttpServer({ host: '0.0.0.0', port: 0 }),
    error => error.code === 'loopback_host_required',
  );
});
