import { canonical, isPlainObject, randomId, sha256, timestamp } from './canonical.mjs';
import { assert } from './errors.mjs';
import { publicJwk, signBytes, verifyBytes } from './crypto.mjs';
import { assertJsonSchema } from './sources.mjs';

export const ACTION_TYPES = Object.freeze({
  'record.append': { risk: 'low', external: false, automation: 'allowed' },
  'webhook.dispatch': { risk: 'high', external: true, automation: 'human-approval-required' },
});

function bounded(value, code, message, max = 240) {
  assert(typeof value === 'string' && value.length > 0 && value.length <= max, code, message);
  return value;
}

function actionHash({ type, target = null, payload, idempotencyKey }) {
  return sha256({ type, target, payload, idempotencyKey });
}

export function verifyActionReceipt(receipt, publicKey) {
  assert(isPlainObject(receipt) && receipt.profile === 'nova-action-receipt-0.1', 'invalid_action_receipt', 'The action receipt profile is invalid.');
  const { signature, ...unsigned } = receipt;
  assert(signature?.alg === 'EdDSA' && typeof signature.keyId === 'string' && typeof signature.value === 'string', 'invalid_action_receipt', 'The action receipt signature metadata is invalid.');
  assert(verifyBytes(publicKey, canonical(unsigned), signature.value), 'invalid_action_receipt_signature', 'The action receipt signature is invalid.', 403);
  return { verified: true, actionId: receipt.actionId, status: receipt.status, receiptHash: sha256(receipt) };
}

export class ActionService {
  constructor(state, keys, ledger, {
    now = () => Date.now(),
    externalEnabled = false,
    webhookAllowlist = [],
    webhookHeaders = {},
    timeoutMs = 5_000,
    maxBytes = 1_000_000,
    lookup,
  } = {}) {
    assert(state && Array.isArray(state.actions) && Array.isArray(state.receipts) && Array.isArray(state.notes) && Array.isArray(state.authorizations), 'invalid_state', 'ActionService requires initialized state.');
    assert(keys?.activeKeyId, 'signer_not_configured', 'ActionService requires a signing key bundle.', 503);
    assert(ledger?.append, 'ledger_required', 'ActionService requires a TrustLedger.');
    this.state = state; this.keys = keys; this.ledger = ledger; this.now = now;
    // The JSON store cannot provide a crash-safe transactional outbox. Keep
    // external side effects technically disabled until a durable action backend
    // can persist authorization consumption before dispatch and reconcile after.
    Object.defineProperty(this, 'externalEnabled', { value: false, writable: false, enumerable: true });
    this.externalRequested = externalEnabled === true;
    this.disabledExternalConfiguration = Object.freeze({
      allowlistEntries: webhookAllowlist.length,
      headerCount: Object.keys(webhookHeaders).length,
      timeoutMs,
      maxBytes,
      customLookupRequested: typeof lookup === 'function',
    });
    if (typeof this.state.meta.actionKillSwitch !== 'boolean') this.state.meta.actionKillSwitch = false;
  }

  setKillSwitch(enabled, { actor, reason = '' } = {}) {
    assert(typeof enabled === 'boolean', 'invalid_kill_switch', 'Kill switch state must be boolean.');
    bounded(actor, 'actor_required', 'An actor is required to change the kill switch.');
    assert(typeof reason === 'string' && reason.length <= 1_000, 'invalid_reason', 'The kill switch reason is too long.');
    const entry = this.ledger.append(enabled ? 'security.action_kill_switch_enabled' : 'security.action_kill_switch_disabled', actor, { enabled, reasonHash: sha256(reason) });
    this.state.meta.actionKillSwitch = enabled;
    this.state.meta.actionKillSwitchChangedAt = timestamp(this.now());
    return { enabled, changedAt: this.state.meta.actionKillSwitchChangedAt, auditReceipt: this.ledger.receipt(entry) };
  }

  authorizeWebhook() {
    assert(false, 'durable_action_backend_required', 'External webhook authorization is disabled until a durable outbox and independently authenticated approval provider are configured.', 503);
  }

  async execute({ type, parameters, actor, idempotencyKey, authorizationToken, signal } = {}) {
    assert(ACTION_TYPES[type], 'unsupported_action', 'The requested action type is unsupported.');
    bounded(actor, 'actor_required', 'An action actor is required.');
    bounded(idempotencyKey, 'idempotency_key_required', 'A bounded idempotency key is required.', 200);
    assert(isPlainObject(parameters), 'invalid_action_parameters', 'Action parameters must be a plain object.');
    assert(this.state.meta.actionKillSwitch !== true, 'action_kill_switch_enabled', 'Action execution is disabled by the kill switch.', 503);
    if (type === 'record.append') return this.#appendRecord({ parameters, actor, idempotencyKey });
    return await this.#dispatchWebhook({ parameters, actor, idempotencyKey, authorizationToken, signal });
  }

  #existing(idempotencyKey, requestHash, actor) {
    const existing = this.state.actions.find(action => action.idempotencyKey === idempotencyKey);
    if (!existing) return null;
    assert(existing.requestHash === requestHash, 'idempotency_conflict', 'The action idempotency key was reused for different content.', 409);
    const receipt = this.state.receipts.find(item => item.actionId === existing.id);
    assert(receipt, 'action_receipt_missing', 'The prior action is missing its signed receipt.', 503);
    verifyActionReceipt(receipt, publicJwk(this.keys, receipt.signature.keyId));
    assert(
      receipt.requestHash === existing.requestHash
        && receipt.actionType === existing.type
        && receipt.status === existing.status
        && receipt.actor === existing.actor
        && receipt.actor === actor
        && receipt.idempotencyKeyHash === sha256(existing.idempotencyKey),
      'action_receipt_binding_failed',
      'The prior action does not match its signed receipt.',
      503,
    );
    if (existing.type === 'record.append') {
      const note = this.state.notes.find(item => item.actionId === existing.id && item.id === receipt.result?.recordId);
      assert(note && sha256(note.record) === receipt.result?.recordHash, 'action_result_integrity_failure', 'The stored action result does not match its signed receipt.', 503);
    }
    return { action: structuredClone(existing), receipt: structuredClone(receipt), replayed: true };
  }

  #appendRecord({ parameters, actor, idempotencyKey }) {
    const keys = Object.keys(parameters);
    assert(keys.length === 1 && keys[0] === 'record', 'invalid_record_action', 'record.append accepts only a record parameter.');
    assert(isPlainObject(parameters.record), 'invalid_record', 'The local record must be a plain object.');
    assertJsonSchema(parameters.record, true, 'invalid_record');
    assert(Buffer.byteLength(canonical(parameters.record)) <= 256_000, 'record_too_large', 'The local record exceeds 256000 bytes.', 413);
    const requestHash = actionHash({ type: 'record.append', payload: parameters.record, idempotencyKey });
    const existing = this.#existing(idempotencyKey, requestHash, actor);
    if (existing) return existing;
    const action = {
      id: randomId('action'), type: 'record.append', risk: 'low', mode: 'local', actor,
      idempotencyKey, requestHash, status: 'completed', createdAt: timestamp(this.now()), completedAt: timestamp(this.now()),
    };
    const note = { id: randomId('record'), actionId: action.id, record: structuredClone(parameters.record), createdAt: action.completedAt };
    this.state.notes.push(note);
    this.state.actions.push(action);
    const entry = this.ledger.append('action.record_appended', actor, { actionId: action.id, recordId: note.id, requestHash, idempotencyKeyHash: sha256(idempotencyKey) }, `action:${sha256(idempotencyKey)}`);
    action.auditEntryId = entry.id;
    const receipt = this.#receipt(action, { recordId: note.id, recordHash: sha256(note.record) });
    this.state.receipts.push(receipt);
    return { action: structuredClone(action), receipt: structuredClone(receipt), replayed: false, auditReceipt: this.ledger.receipt(entry) };
  }

  async #dispatchWebhook() {
    assert(false, 'durable_action_backend_required', 'External webhook execution is disabled until a durable outbox and upstream idempotency reconciliation are configured.', 503);
  }

  #receipt(action, result) {
    const unsigned = {
      profile: 'nova-action-receipt-0.1', id: randomId('receipt'), actionId: action.id,
      actionType: action.type, risk: action.risk, mode: action.mode, status: action.status,
      actor: action.actor, idempotencyKeyHash: sha256(action.idempotencyKey),
      requestHash: action.requestHash, result, issuedAt: timestamp(this.now()), issuer: this.keys.issuer,
    };
    return { ...unsigned, signature: { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(unsigned)) } };
  }
}
