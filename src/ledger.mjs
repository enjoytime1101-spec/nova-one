import { canonical, randomId, sha256, timestamp } from './canonical.mjs';
import { assert } from './errors.mjs';
import { signBytes, verifyBytes, publicJwk } from './crypto.mjs';

function leaf(hash) { return sha256(`\u0000${hash}`); }
function parent(left, right) { return sha256(`\u0001${left}${right}`); }

export function merkle(hashes, target = 0) {
  if (!hashes.length) return { root: sha256(''), proof: [] };
  let level = hashes.map(leaf);
  let cursor = target;
  const proof = [];
  while (level.length > 1) {
    const sibling = cursor ^ 1;
    proof.push({ left: sibling < cursor, hash: level[sibling] || level[cursor] });
    const next = [];
    for (let index = 0; index < level.length; index += 2) next.push(parent(level[index], level[index + 1] || level[index]));
    level = next;
    cursor = Math.floor(cursor / 2);
  }
  return { root: level[0], proof };
}

export function verifyInclusion(hash, proof, root) {
  return proof.reduce((value, step) => step.left ? parent(step.hash, value) : parent(value, step.hash), leaf(hash)) === root;
}

export class TrustLedger {
  constructor(state, keyBundle) {
    this.state = state;
    this.keys = keyBundle;
  }

  verify() {
    let previous = '0'.repeat(64);
    for (const [index, entry] of this.state.auditEntries.entries()) {
      const { hash, ...unsigned } = entry;
      if (unsigned.sequence !== index + 1 || unsigned.previous !== previous || sha256(unsigned) !== hash) return { valid: false, reason: 'hash_chain', checked: index };
      previous = hash;
    }
    for (const checkpoint of this.state.checkpoints) {
      const { signature, ...unsigned } = checkpoint;
      const hashes = this.state.auditEntries.slice(0, checkpoint.size).map(entry => entry.hash);
      const key = publicJwk(this.keys, checkpoint.keyId);
      if (merkle(hashes).root !== checkpoint.root || !verifyBytes(key, canonical(unsigned), signature)) return { valid: false, reason: 'checkpoint_signature', checked: checkpoint.size };
    }
    if (this.state.auditEntries.length && this.state.checkpoints.at(-1)?.size !== this.state.auditEntries.length) return { valid: false, reason: 'uncheckpointed_tail' };
    return { valid: true, checked: this.state.auditEntries.length, head: previous };
  }

  append(event, actor, payload, idempotencyKey = randomId('idem')) {
    assert(this.verify().valid, 'audit_integrity_failure', 'The audit ledger failed integrity verification.', 503);
    const payloadHash = sha256(payload);
    const existing = this.state.auditEntries.find(entry => entry.idempotencyKey === idempotencyKey);
    if (existing) {
      assert(existing.event === event && existing.actor === actor && existing.payloadHash === payloadHash, 'idempotency_conflict', 'The idempotency key was reused with different content.', 409);
      return existing;
    }
    const unsigned = {
      id: randomId('audit'), sequence: this.state.auditEntries.length + 1,
      previous: this.state.auditEntries.at(-1)?.hash || '0'.repeat(64),
      event, actor, payloadHash, idempotencyKey, at: timestamp(), keyId: this.keys.activeKeyId,
    };
    const entry = { ...unsigned, hash: sha256(unsigned) };
    const checkpointUnsigned = {
      id: randomId('checkpoint'), size: unsigned.sequence,
      root: merkle([...this.state.auditEntries.map(item => item.hash), entry.hash]).root,
      at: timestamp(), keyId: this.keys.activeKeyId,
    };
    const checkpoint = { ...checkpointUnsigned, signature: signBytes(this.keys, canonical(checkpointUnsigned)) };
    this.state.auditEntries.push(entry);
    this.state.checkpoints.push(checkpoint);
    return entry;
  }

  receipt(entry) {
    const checkpoint = this.state.checkpoints.find(item => item.size >= entry.sequence);
    assert(checkpoint, 'checkpoint_missing', 'The audit entry does not have a signed checkpoint.', 503);
    return { entry, checkpoint, proof: merkle(this.state.auditEntries.slice(0, checkpoint.size).map(item => item.hash), entry.sequence - 1).proof };
  }

  async anchorLatest(adapter, actor = 'nova:operator') {
    assert(adapter?.publish && typeof adapter.publish === 'function', 'witness_adapter_required', 'A witness adapter with publish() is required.', 503);
    assert(this.verify().valid, 'audit_integrity_failure', 'The audit ledger failed integrity verification.', 503);
    const checkpoint = this.state.checkpoints.at(-1);
    assert(checkpoint, 'checkpoint_missing', 'There is no signed checkpoint to witness.', 404);
    const result = await adapter.publish(structuredClone(checkpoint));
    assert(result && typeof result.receiptId === 'string' && result.checkpointRoot === checkpoint.root && typeof result.provider === 'string' && typeof result.witnessedAt === 'string', 'invalid_witness_receipt', 'The witness returned an invalid or mismatched receipt.', 502);
    const record = { ...structuredClone(result), checkpointId: checkpoint.id, checkpointSize: checkpoint.size, receivedAt: timestamp() };
    const entry = this.append('checkpoint.witnessed', actor, { receiptId: record.receiptId, checkpointRoot: record.checkpointRoot, provider: record.provider, witnessedAt: record.witnessedAt });
    record.auditEntryId = entry.id;
    this.state.witnessReceipts ||= [];
    this.state.witnessReceipts.push(record);
    return { ...record, auditReceipt: this.receipt(entry) };
  }
}
