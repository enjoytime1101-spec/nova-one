import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createKeyBundle } from '../src/crypto.mjs';
import { JsonStore } from '../src/store.mjs';
import { TrustLedger } from '../src/ledger.mjs';

test('signed checkpoints can be bound to an external witness receipt through an adapter', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-witness-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const state = new JsonStore(path.join(directory, 'state.json')).initialize();
  const ledger = new TrustLedger(state, createKeyBundle());
  ledger.append('example.created', 'did:example:alice', { value: 1 });
  const witnessed = await ledger.anchorLatest({
    async publish(checkpoint) {
      return { receiptId: 'fixture-receipt-1', checkpointRoot: checkpoint.root, provider: 'isolated-fixture', witnessedAt: new Date().toISOString(), proof: { offline: true } };
    },
  });
  assert.equal(witnessed.checkpointRoot, state.checkpoints[0].root);
  assert.equal(state.witnessReceipts.length, 1);
  assert.equal(ledger.verify().valid, true);
});

test('mismatched witness roots fail closed', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'nova-witness-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const state = new JsonStore(path.join(directory, 'state.json')).initialize();
  const ledger = new TrustLedger(state, createKeyBundle());
  ledger.append('example.created', 'did:example:alice', { value: 1 });
  await assert.rejects(ledger.anchorLatest({ async publish() { return { receiptId: 'bad', checkpointRoot: '0'.repeat(64), provider: 'fixture', witnessedAt: new Date().toISOString() }; } }), error => error.code === 'invalid_witness_receipt');
});
