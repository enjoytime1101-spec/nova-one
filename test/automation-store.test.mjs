import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { JsonStore } from '../src/store.mjs';
import { createNovaService } from '../src/service.mjs';
import { loadKeyBundle } from '../src/crypto.mjs';
import { TrustLedger } from '../src/ledger.mjs';

function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-automation-store-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir;
}
function child(code) {
  return new Promise((resolve, reject) => {
    const processChild = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = ''; processChild.stderr.on('data', chunk => { stderr += chunk; });
    processChild.on('error', reject); processChild.on('close', status => status === 0 ? resolve() : reject(new Error(stderr || `Child exited ${status}`)));
  });
}

test('distinct store instances and processes serialize without lost updates', async t => {
  const file = path.join(temporary(t), 'state.json'); const store = new JsonStore(file); store.initialize();
  await Promise.all(Array.from({ length: 12 }, (_, i) => new JsonStore(file).transaction(async state => {
    const value = state.meta.counter || 0; await new Promise(resolve => setTimeout(resolve, i % 3)); state.meta.counter = value + 1;
  })));
  assert.equal(store.read().meta.counter, 12);
  const moduleUrl = new URL('../src/store.mjs', import.meta.url).href;
  await Promise.all(Array.from({ length: 4 }, () => child(`import { JsonStore } from ${JSON.stringify(moduleUrl)}; const store = new JsonStore(${JSON.stringify(file)}); for (let i=0;i<4;i++) await store.transaction(async s => { const n=s.meta.counter; await new Promise(r=>setTimeout(r,4)); s.meta.counter=n+1; });`)));
  assert.equal(store.read().meta.counter, 28); assert.equal(fs.existsSync(store.lockFile), false);
});

test('busy or abandoned locks fail closed instead of stealing ownership', async t => {
  const file = path.join(temporary(t), 'state.json'); const store = new JsonStore(file, { lockTimeoutMs: 10, lockRetryMs: 2 }); store.initialize();
  const before = fs.readFileSync(file, 'utf8'); const owner = '{"pid":99999999,"nonce":"abandoned-test"}'; fs.writeFileSync(store.lockFile, owner);
  await assert.rejects(store.transaction(state => { state.meta.partial = true; }), error => error.code === 'store_busy');
  assert.equal(fs.readFileSync(file, 'utf8'), before); assert.equal(fs.readFileSync(store.lockFile, 'utf8'), owner);
  fs.unlinkSync(store.lockFile); await store.transaction(state => { state.meta.recovered = true; }); assert.equal(store.read().meta.recovered, true);
});

test('failed file commit preserves original state, cleans temp files and releases lock', async t => {
  const dir = temporary(t); const file = path.join(dir, 'state.json'); const store = new JsonStore(file); store.initialize(); const before = fs.readFileSync(file, 'utf8');
  const rename = fs.renameSync; fs.renameSync = (source, destination) => { if (destination === file) throw Object.assign(new Error('injected rename failure'), { code: 'EIO' }); return rename(source, destination); };
  try { await assert.rejects(store.transaction(state => { state.meta.partial = true; }), error => error.code === 'EIO'); } finally { fs.renameSync = rename; }
  assert.equal(fs.readFileSync(file, 'utf8'), before); assert.deepEqual(fs.readdirSync(dir), ['state.json']);
  await store.transaction(state => { state.meta.retried = true; }); assert.equal(store.read().meta.retried, true);
});

test('workflow rejection persists signed failure evidence without partial business state', async t => {
  const service = createNovaService({ home: temporary(t) }); service.initialize();
  const spec = { subject: 'did:example:alice', audience: 'local-review', purpose: 'review-rate', claims: ['rate'], authorization: { approvedBy: 'did:example:alice', claims: ['rate'] }, fixtures: [
    { id: 'a', independenceKey: 'publisher-a', payload: { claims: { rate: 1 } } }, { id: 'b', independenceKey: 'publisher-b', payload: { claims: { rate: 2 } } },
  ], action: { type: 'record.append', parameters: { record: { shouldNotExist: true } } }, actionExecution: { idempotencyKey: 'failed-workflow-001' } };
  let rejected; await assert.rejects(service.runWorkflow(spec), error => { rejected = error; return error.code === 'evidence_conflict'; });
  const state = service.store.read();
  for (const name of ['sources', 'snapshots', 'contexts', 'claimAudits', 'authorizations', 'credentials', 'actions', 'notes', 'receipts']) assert.equal(state[name].length, 0, name);
  assert.equal(state.auditEntries.length, 1); assert.equal(state.auditEntries[0].event, 'security.workflow_failed');
  assert.equal(rejected.failureEvidence.payload.reason, 'evidence_conflict'); assert.equal(rejected.failureEvidence.auditReceipt.entry.id, state.auditEntries[0].id);
  assert.equal(new TrustLedger(state, loadKeyBundle(service.paths.keys)).verify().valid, true);
  spec.fixtures[1].payload.claims.rate = 1; await service.runWorkflow(spec); assert.equal(service.store.read().actions.length, 1);
});

test('failure-audit signing failure is explicit and never commits partial state', async t => {
  const file = path.join(temporary(t), 'state.json'); const store = new JsonStore(file); store.initialize(); const before = fs.readFileSync(file, 'utf8');
  await assert.rejects(store.transaction(state => { state.notes.push({ partial: true }); throw Object.assign(new Error('failed'), { code: 'business_failed' }); }, { onFailure: () => { throw new Error('signer unavailable'); } }), error => error.code === 'failure_evidence_unavailable');
  assert.equal(fs.readFileSync(file, 'utf8'), before); assert.equal(fs.existsSync(store.lockFile), false);
});

test('a genuinely unavailable signing key prevents workflow and failure-evidence commits', async t => {
  const service = createNovaService({ home: temporary(t) }); service.initialize();
  const before = fs.readFileSync(service.paths.state, 'utf8'); const originalKeys = fs.readFileSync(service.paths.keys, 'utf8');
  const keys = JSON.parse(originalKeys); delete keys.keys[keys.activeKeyId].privateKeyPem; fs.writeFileSync(service.paths.keys, JSON.stringify(keys));
  try {
    await assert.rejects(service.runWorkflow({ subject: 'did:example:alice', audience: 'local-review', purpose: 'review-rate', claims: { rate: 1 } }), error => error.code === 'failure_evidence_unavailable' && error.details.operationCode === 'signer_not_configured' && error.details.evidenceCode === 'signer_not_configured');
    assert.equal(fs.readFileSync(service.paths.state, 'utf8'), before); assert.equal(fs.existsSync(service.store.lockFile), false);
  } finally { fs.writeFileSync(service.paths.keys, originalKeys, { mode: 0o600 }); }
  await service.runWorkflow({ subject: 'did:example:alice', audience: 'local-review', purpose: 'review-rate', claims: { rate: 1 } });
  assert.equal(service.status().ledger.valid, true);
});
