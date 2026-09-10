import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createKeyBundle, loadKeyBundle, publicJwk } from '../src/crypto.mjs';
import { JsonStore } from '../src/store.mjs';
import { WorkflowEngine } from '../src/workflow.mjs';
import { DeterministicAgentAdapter } from '../src/agent.mjs';
import { verifyActionReceipt } from '../src/actions.mjs';
import { createNovaService } from '../src/service.mjs';
import { createSignedSourceEnvelope, FixtureSourceAdapter } from '../src/sources.mjs';

function directFixture(options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-workflow-'));
  const state = new JsonStore(path.join(directory, 'state.json')).initialize();
  const keys = createKeyBundle({ issuer: 'https://issuer.example' });
  return { directory, state, keys, engine: new WorkflowEngine(state, keys, options) };
}

function sourceSchema() {
  return {
    type: 'object', required: ['claims'], additionalProperties: false,
    properties: {
      claims: {
        type: 'object', required: ['rate'], additionalProperties: false,
        properties: { rate: { type: 'number', minimum: 0 } },
      },
    },
  };
}

function registerPair(engine, left = 0.25, right = left, sourceOptions = {}) {
  engine.sources.registerFixture({ id: 'source-a', payload: { claims: { rate: left } }, schema: sourceSchema(), ...sourceOptions }, { independenceKey: 'publisher-a' });
  engine.sources.registerFixture({ id: 'source-b', payload: { claims: { rate: right } }, schema: sourceSchema(), ...sourceOptions }, { independenceKey: 'publisher-b' });
}

function authorize(engine) {
  return engine.contexts.authorize({ subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision', claims: ['rate'], approvedBy: 'did:example:alice' });
}

test('independent service runs a full two-source workflow and persists a signed low-risk action receipt', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-service-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const service = createNovaService({ home: directory });
  service.initialize({ issuer: 'https://issuer.example', apiToken: 'test-token-abcdefghijklmnopqrstuvwxyz-123456' });
  const result = await service.runWorkflow({
    subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision',
    claims: { rate: 0.25 },
    action: { type: 'record.append', parameters: { record: { decision: 'observe', rate: 0.25 } } },
    actionExecution: { idempotencyKey: 'rate-decision-001' },
  });
  assert.equal(result.mode, 'fixture');
  assert.equal(result.context.claims[0].independentSourceCount, 2);
  assert.equal(result.agent.output.claims[0].value, 0.25);
  assert.equal(result.action.action.status, 'completed');
  assert.equal(verifyActionReceipt(result.action.receipt, publicJwk(loadKeyBundle(service.paths.keys))).verified, true);
  assert.throws(() => service.verifyCredential({ token: result.agentCredential.token, audience: 'decision-agent', purpose: 'verified-rate-decision', subject: 'did:example:alice' }), error => error.code === 'untrusted_fixture_credential');
  const persisted = service.status();
  assert.equal(persisted.counts.snapshots, 2);
  assert.equal(persisted.counts.contexts, 1);
  assert.equal(persisted.counts.receipts, 1);
  assert.equal(persisted.ledger.valid, true);
});

test('workflow rejects conflicting independent evidence and agent-modified facts', async t => {
  const conflict = directFixture();
  const hallucination = directFixture();
  t.after(() => {
    fs.rmSync(conflict.directory, { recursive: true, force: true });
    fs.rmSync(hallucination.directory, { recursive: true, force: true });
  });
  registerPair(conflict.engine, 0.25, 0.5);
  const conflictGrant = authorize(conflict.engine);
  await assert.rejects(conflict.engine.run({ sourceIds: ['source-a', 'source-b'], claims: ['rate'], authorizationId: conflictGrant.id, subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision' }), error => error.code === 'evidence_conflict');

  registerPair(hallucination.engine);
  const hallucinationGrant = authorize(hallucination.engine);
  const adapter = new DeterministicAgentAdapter({ responder: ({ context }) => {
    const supported = context.claims[0];
    return {
      profile: 'nova-agent-output-0.1', contextId: context.id, summary: 'Attempted fact rewrite.',
      claims: [{ id: 'claim-rate', name: 'rate', statement: 'Unsupported rate.', value: 999, confidence: 1, evidence: supported.evidence.map(item => ({ snapshotId: item.snapshotId, sourceId: item.sourceId, payloadHash: item.payloadHash })) }],
      proposedActions: [],
    };
  } });
  await assert.rejects(hallucination.engine.run({ sourceIds: ['source-a', 'source-b'], claims: ['rate'], authorizationId: hallucinationGrant.id, subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision', agentAdapter: adapter }), error => error.code === 'agent_claim_value_mismatch');
});

test('expired source evidence and revoked context authorization fail closed', async t => {
  const clock = Date.now();
  const stale = directFixture({ now: () => clock });
  const revoked = directFixture({ now: () => clock });
  t.after(() => {
    fs.rmSync(stale.directory, { recursive: true, force: true });
    fs.rmSync(revoked.directory, { recursive: true, force: true });
  });
  registerPair(stale.engine, 0.25, 0.25, { now: () => clock - 100_000, ttlMs: 1_000 });
  const staleGrant = authorize(stale.engine);
  await assert.rejects(stale.engine.run({ sourceIds: ['source-a', 'source-b'], claims: ['rate'], authorizationId: staleGrant.id, subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision' }), error => error.code === 'source_expired');

  registerPair(revoked.engine);
  const revokedGrant = authorize(revoked.engine);
  revoked.engine.contexts.revokeAuthorization(revokedGrant.id, { actor: 'did:example:alice' });
  await assert.rejects(revoked.engine.run({ sourceIds: ['source-a', 'source-b'], claims: ['rate'], authorizationId: revokedGrant.id, subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision' }), error => error.code === 'authorization_inactive');
});

test('external actions remain fail-closed without a durable action backend', async t => {
  const target = 'https://webhook.example/action';
  const f = directFixture({ action: {
    externalEnabled: true,
    webhookAllowlist: [target],
    lookup: async () => [{ address: '127.0.0.1', family: 4 }],
  } });
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const request = { actor: 'did:example:alice', target, payload: { command: 'update' }, idempotencyKey: 'external-action-001' };
  assert.equal(f.engine.actions.externalEnabled, false);
  assert.equal(f.engine.actions.externalRequested, true);
  assert.throws(
    () => f.engine.actions.authorizeWebhook({ ...request, approvedBy: 'did:example:approver', humanApproval: true }),
    error => error.code === 'durable_action_backend_required',
  );
  await assert.rejects(
    f.engine.actions.execute({ type: 'webhook.dispatch', parameters: { target: request.target, payload: request.payload }, actor: request.actor, idempotencyKey: request.idempotencyKey }),
    error => error.code === 'durable_action_backend_required',
  );
});

test('local action replay detects stored result tampering', async t => {
  const f = directFixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const input = {
    type: 'record.append',
    parameters: { record: { decision: 'observe', rate: 0.25 } },
    actor: 'did:example:alice',
    idempotencyKey: 'tamper-check-001',
  };
  await f.engine.actions.execute(input);
  f.state.notes[0].record.rate = 999;
  await assert.rejects(
    f.engine.actions.execute(input),
    error => error.code === 'action_result_integrity_failure',
  );
});

test('action kill switch prevents local action execution', async t => {
  const f = directFixture();
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  f.engine.actions.setKillSwitch(true, { actor: 'did:example:operator', reason: 'incident containment' });
  await assert.rejects(
    f.engine.actions.execute({
      type: 'record.append', parameters: { record: { decision: 'must-not-run' } },
      actor: 'did:example:alice', idempotencyKey: 'kill-switch-check-001',
    }),
    error => error.code === 'action_kill_switch_enabled',
  );
  assert.equal(f.state.notes.length, 0);
});

test('one fixture source taints a mixed-source workflow', async t => {
  const externalKeys = createKeyBundle({ issuer: 'https://external-source.example' });
  const external = {
    id: 'external-source', kind: 'external', schema: sourceSchema(),
    publicKey: publicJwk(externalKeys), keyId: externalKeys.activeKeyId,
    async fetch() {
      return createSignedSourceEnvelope({ claims: { rate: 0.25 } }, { sourceId: this.id, keyBundle: externalKeys });
    },
  };
  const fixtureAdapter = new FixtureSourceAdapter({ id: 'fixture-source', payload: { claims: { rate: 0.25 } }, schema: sourceSchema() });
  const f = directFixture({ sourceAdapters: [
    { adapter: external, metadata: { independenceKey: 'external-publisher' } },
    { adapter: fixtureAdapter, metadata: { independenceKey: 'fixture-publisher' } },
  ] });
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const grant = authorize(f.engine);
  const result = await f.engine.run({ sourceIds: ['external-source', 'fixture-source'], claims: ['rate'], authorizationId: grant.id, subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision' });
  assert.equal(result.mode, 'fixture');
  assert.equal(result.agentCredential.document.credentialSubject.trustLevel, 'untrusted-fixture');
});

test('a fixture agent taints a workflow even when every source is external', async t => {
  const adapters = ['external-a', 'external-b'].map(id => {
    const keys = createKeyBundle({ issuer: `https://${id}.example` });
    return {
      adapter: {
        id, kind: 'external', schema: sourceSchema(), publicKey: publicJwk(keys), keyId: keys.activeKeyId,
        async fetch() { return createSignedSourceEnvelope({ claims: { rate: 0.25 } }, { sourceId: id, keyBundle: keys }); },
      },
      metadata: { independenceKey: `${id}-publisher` },
    };
  });
  const f = directFixture({ sourceAdapters: adapters });
  t.after(() => fs.rmSync(f.directory, { recursive: true, force: true }));
  const grant = authorize(f.engine);
  const result = await f.engine.run({ sourceIds: ['external-a', 'external-b'], claims: ['rate'], authorizationId: grant.id, subject: 'did:example:alice', audience: 'decision-agent', purpose: 'verified-rate-decision' });
  assert.equal(result.mode, 'fixture');
  assert.equal(result.agentCredential.document.credentialSubject.trustLevel, 'untrusted-fixture');
});
