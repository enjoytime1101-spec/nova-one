import { verifyActionReceipt } from '../src/actions.mjs';
import { sha256 } from '../src/canonical.mjs';
import { loadKeyBundle, publicJwk } from '../src/crypto.mjs';
import { assert } from '../src/errors.mjs';
import { TrustLedger } from '../src/ledger.mjs';
import { createNovaService } from '../src/service.mjs';
import { assertJsonSchema } from '../src/sources.mjs';

const bounded = { type: 'string', minLength: 1, maxLength: 512 };
export const MCP_RECEIPT_TOOL = Object.freeze({
  name: 'nova_verify_action_receipt',
  description: 'Read-only verification of a locally admitted action receipt, expected bindings, stored result and audit chain using the operator-selected NOVA_HOME issuer keys. Never re-executes the action.',
  inputSchema: {
    type: 'object', additionalProperties: false,
    required: ['receipt', 'expectedIssuer', 'expectedKeyId', 'expectedActionId', 'expectedRequestHash', 'expectedActor'],
    properties: {
      receipt: { type: 'object', additionalProperties: true },
      expectedIssuer: bounded, expectedKeyId: bounded,
      expectedActionId: bounded, expectedActor: bounded,
      expectedRequestHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
    },
  },
});

export function verifyLocalActionReceipt(home, input) {
  assertJsonSchema(input, MCP_RECEIPT_TOOL.inputSchema, 'tool_input_invalid');
  const service = createNovaService({ home });
  assert(service.isInitialized(), 'nova_not_initialized', 'Initialize the operator-selected NOVA_HOME before receipt verification.', 503);
  const state = service.store.read();
  const keys = loadKeyBundle(service.paths.keys);
  const ledger = new TrustLedger(state, keys);
  assert(ledger.verify().valid, 'audit_integrity_failure', 'The local audit ledger failed verification.', 503);
  const receipt = input.receipt;
  assert(input.expectedIssuer === keys.issuer && receipt.issuer === input.expectedIssuer
    && receipt.signature?.keyId === input.expectedKeyId,
  'action_receipt_trust_mismatch', 'The expected issuer/key must match the receipt and the configured local trust store.', 403);
  const verification = verifyActionReceipt(receipt, publicJwk(keys, input.expectedKeyId));
  assert(receipt.actionId === input.expectedActionId && receipt.requestHash === input.expectedRequestHash
    && receipt.actor === input.expectedActor,
  'action_receipt_binding_failed', 'The receipt does not match the independently expected action, request, and actor.', 403);
  const admitted = state.receipts.find(candidate => candidate.id === receipt.id);
  const action = state.actions.find(candidate => candidate.id === input.expectedActionId);
  assert(admitted && sha256(admitted) === sha256(receipt) && action
    && action.requestHash === input.expectedRequestHash && action.actor === input.expectedActor
    && action.type === receipt.actionType && action.status === receipt.status
    && sha256(action.idempotencyKey) === receipt.idempotencyKeyHash,
  'action_receipt_not_admitted', 'The receipt must match an admitted local action and its stored receipt.', 403);
  assert(action.type === 'record.append' && receipt.mode === 'local' && receipt.status === 'completed',
    'unsupported_receipt_execution', 'This verifier confirms completed local record.append actions only.', 403);
  const note = state.notes.find(candidate => candidate.actionId === action.id && candidate.id === receipt.result?.recordId);
  assert(note && sha256(note.record) === receipt.result?.recordHash,
    'action_result_integrity_failure', 'The stored local result does not match the signed receipt.', 503);
  const entry = state.auditEntries.find(candidate => candidate.id === action.auditEntryId);
  const payload = { actionId: action.id, recordId: note.id, requestHash: action.requestHash, idempotencyKeyHash: sha256(action.idempotencyKey) };
  assert(entry?.event === 'action.record_appended' && entry.actor === action.actor && entry.payloadHash === sha256(payload),
    'action_audit_binding_failed', 'The action does not match its verified audit entry.', 503);
  return {
    ...verification, issuer: keys.issuer, keyId: input.expectedKeyId,
    requestHash: action.requestHash, actor: action.actor,
    trustSource: 'operator-selected NOVA_HOME', localAdmissionVerified: true,
    localRecordVerified: true, auditVerified: true, externalExecutionVerified: false,
  };
}
