import fs from 'node:fs';
import { canonical, isPlainObject, randomId, sha256 } from '../src/canonical.mjs';
import { assert, publicError } from '../src/errors.mjs';
import { loadKeyBundle, publicJwk, verifyBytes, verifyCompactJwt } from '../src/crypto.mjs';
import { verifyInclusion, TrustLedger } from '../src/ledger.mjs';
import { assertJsonSchema } from '../src/sources.mjs';
import { validateAgentOutput } from '../src/agent.mjs';
import { verifyActionReceipt } from '../src/actions.mjs';

export const TASK_PROFILE = 'nova-automation-task-0.1';
export const REPORT_PROFILE = 'nova-automation-report-0.1';
const text = maxLength => ({ type: 'string', minLength: 1, maxLength });
const scope = { subject: text(240), actor: text(240), audience: text(240), purpose: text(160) };
export const TASK_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['profile', 'id', 'revision', 'policy', 'workflow'],
  properties: {
    profile: { const: TASK_PROFILE }, id: text(160), revision: { type: 'integer', minimum: 1, maximum: 1_000_000 },
    policy: { type: 'object', additionalProperties: false, required: ['id', 'revision', 'minIndependentSources', 'maxAgeMs', 'allowedActions'], properties: {
      id: text(160), revision: { type: 'integer', minimum: 1, maximum: 1_000_000 }, minIndependentSources: { type: 'integer', minimum: 2, maximum: 10 },
      maxAgeMs: { type: 'integer', minimum: 1000, maximum: 86400000 }, allowedActions: { type: 'array', maxItems: 1, items: { const: 'record.append' } },
    } },
    workflow: { type: 'object', additionalProperties: false, required: ['subject', 'audience', 'purpose', 'fixtures', 'claims'], properties: {
      ...scope, prompt: { type: 'string', maxLength: 16000 },
      claims: { type: 'array', minItems: 1, maxItems: 100, items: text(160) },
      fixtures: { type: 'array', minItems: 2, maxItems: 32, items: { type: 'object', additionalProperties: false, required: ['id', 'independenceKey', 'payload'], properties: {
        id: text(160), independenceKey: text(160), label: text(240), payload: { type: 'object' }, schema: {},
      } } },
      action: { type: 'object', additionalProperties: false, required: ['type', 'parameters'], properties: {
        type: { const: 'record.append' }, parameters: { type: 'object', additionalProperties: false, required: ['record'], properties: { record: { type: 'object' } } },
      } },
    } },
  },
};

export function validateTask(task) {
  assertJsonSchema(task, TASK_SCHEMA, 'invalid_automation_task');
  assert(new Set(task.workflow.fixtures.map(f => f.id)).size === task.workflow.fixtures.length, 'duplicate_fixture_id', 'Task fixture IDs must be unique.');
  assert(!task.workflow.action || task.policy.allowedActions.includes(task.workflow.action.type), 'action_not_allowed_by_policy', 'The task policy does not allow the requested local action.', 403);
  return task;
}
export function readAutomationJson(file) {
  assert(typeof file === 'string' && file.length > 0 && file.length <= 4096, 'input_file_required', 'An explicit JSON file is required.');
  const stat = fs.statSync(file);
  assert(stat.isFile() && stat.size <= 1_048_576, 'input_file_too_large', 'Automation input must be a JSON file of at most 1048576 bytes.', 413);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
function runIdentity(task, runKey) {
  assert(typeof runKey === 'string' && runKey.length > 0 && runKey.length <= 160, 'run_key_required', 'An explicit bounded run key is required for execution and execution-report verification.');
  return {
    taskId: task.id, revision: task.revision, taskHash: sha256(task), policyHash: sha256(task.policy), runKey,
  };
}
function plannedRecord(task, runKey) {
  return { automation: runIdentity(task, runKey), value: task.workflow.action.parameters.record };
}
function actionKey(task, runKey) { return `automation:${sha256({ taskId: task.id, revision: task.revision, subject: task.workflow.subject, runKey })}`; }
function verifyAudit(receipt, keys, payload) {
  assert(isPlainObject(receipt) && isPlainObject(receipt.entry) && isPlainObject(receipt.checkpoint) && Array.isArray(receipt.proof) && receipt.proof.length <= 64, 'invalid_automation_receipt', 'The automation audit receipt is malformed.');
  const { hash, ...entry } = receipt.entry; const { signature, ...checkpoint } = receipt.checkpoint;
  assert(entry.sequence >= 1 && entry.sequence <= checkpoint.size && sha256(entry) === hash && sha256(payload) === entry.payloadHash
    && verifyInclusion(hash, receipt.proof, checkpoint.root)
    && verifyBytes(publicJwk(keys, checkpoint.keyId), canonical(checkpoint), signature), 'automation_receipt_invalid', 'The automation receipt signature, inclusion or expected payload binding is invalid.', 409);
}

// Verification never invokes a workflow, adapter or action. The expected task and
// execution key come from the caller, rather than from the untrusted report.
export function verifyAutomationReport({ service, report, task, runKey } = {}) {
  validateTask(task);
  assert(report?.profile === REPORT_PROFILE && ['dry-run', 'execute'].includes(report.mode), 'invalid_automation_report', 'The automation report profile or mode is invalid.');
  const expected = runIdentity(task, runKey ?? (report.mode === 'dry-run' ? 'preview' : undefined));
  assert(canonical(report.task) === canonical(expected) && report.trustLevel === 'untrusted-fixture', 'automation_context_mismatch', 'The report does not match the expected task, policy, execution key or reference trust level.', 409);
  const keys = loadKeyBundle(service.paths.keys);
  const binding = report.trace?.binding;
  assert(isPlainObject(binding), 'automation_context_mismatch', 'The signed automation trace is required.', 409);
  for (const [name, value] of Object.entries(expected)) assert(binding[name] === value, 'automation_context_mismatch', 'The signed trace does not match the expected task context.', 409);
  assert(binding.mode === report.mode && binding.fixture === true && binding.workflowId === report.workflowId, 'automation_context_mismatch', 'The signed trace mode or workflow binding is invalid.', 409);
  const actor = task.workflow.actor || task.workflow.subject;
  assert(report.trace.auditReceipt?.entry?.event === 'automation.completed' && report.trace.auditReceipt.entry.actor === actor, 'automation_context_mismatch', 'The audit event or actor is not the expected automation completion.', 409);
  verifyAudit(report.trace.auditReceipt, keys, binding);
  assert(isPlainObject(report.output) && sha256(report.output) === binding.outputHash, 'automation_output_mismatch', 'The displayed Agent output does not match the signed output hash.', 409);
  const executed = report.mode === 'execute' && Boolean(task.workflow.action);
  assert(report.actionExecuted === executed, 'automation_action_mismatch', 'The action outcome does not match the requested execution mode.', 409);
  if (executed) {
    const receipt = report.actionReceipt; verifyActionReceipt(receipt, publicJwk(keys, receipt?.signature?.keyId));
    const key = actionKey(task, expected.runKey); const record = plannedRecord(task, expected.runKey);
    assert(receipt.actionType === 'record.append' && receipt.status === 'completed' && receipt.mode === 'local' && receipt.actor === actor
      && receipt.idempotencyKeyHash === sha256(key) && receipt.requestHash === sha256({ type: 'record.append', target: null, payload: record, idempotencyKey: key })
      && receipt.result?.recordHash === sha256(record) && binding.actionId === receipt.actionId && binding.actionReceiptHash === sha256(receipt), 'automation_action_mismatch', 'The signed local action receipt is not bound to this task, policy, actor and execution key.', 409);
  } else assert(report.actionReceipt === null && binding.actionId === null && binding.actionReceiptHash === null, 'automation_action_mismatch', 'A dry run or action-free task cannot carry an executed action receipt.', 409);
  if (report.mode === 'execute') {
    const state = service.store.read();
    assert(new TrustLedger(state, keys).verify().valid, 'audit_integrity_failure', 'The persisted ledger is invalid.', 503);
    assert(state.auditEntries.some(e => canonical(e) === canonical(report.trace.auditReceipt.entry)) && state.checkpoints.some(c => canonical(c) === canonical(report.trace.auditReceipt.checkpoint)), 'automation_receipt_not_admitted', 'The execution receipt is not present in this NOVA home.', 409);
    if (executed) {
      const r = report.actionReceipt;
      assert(state.receipts.some(x => canonical(x) === canonical(r)) && state.notes.some(x => x.id === r.result.recordId && x.actionId === r.actionId && sha256(x.record) === r.result.recordHash), 'automation_result_not_admitted', 'The stored local result does not match the signed action receipt.', 409);
    }
  }
  return { verified: true, mode: report.mode, actionExecuted: executed, taskHash: expected.taskHash, policyHash: expected.policyHash, runKey: expected.runKey, persisted: report.mode === 'execute', trustLevel: 'untrusted-fixture', scope: 'local-reference-receipt', independentWitness: false };
}

export async function runAutomation({ service, task, execute = false, runKey } = {}) {
  validateTask(task);
  assert(service && !service.capabilities.network && !service.capabilities.model && !service.capabilities.executor, 'automation_external_disabled', 'The reference automation runner requires all external capabilities to remain disabled.', 403);
  assert(typeof execute === 'boolean', 'invalid_execution_mode', 'execute must be a boolean.');
  const identity = runIdentity(task, runKey ?? (execute ? undefined : 'preview'));
  const namespace = randomId('automation');
  const workflow = structuredClone(task.workflow);
  // Fixture keys are ephemeral. Namespace each attempt without pretending these
  // two local fixtures are independent external publishers.
  workflow.fixtures = workflow.fixtures.map((fixture, i) => ({ ...fixture, id: `${namespace}-${i}` }));
  workflow.actor ||= workflow.subject;
  workflow.authorization = { approvedBy: workflow.actor, claims: workflow.claims };
  workflow.minIndependentSources = task.policy.minIndependentSources;
  workflow.maxAgeMs = task.policy.maxAgeMs;
  if (workflow.action) {
    workflow.action.parameters.record = plannedRecord(task, identity.runKey);
    workflow.actionExecution = { idempotencyKey: actionKey(task, identity.runKey) };
  }
  const result = await service.runWorkflow(workflow, { dryRun: !execute, auditBinding: identity });
  assert(result.mode === 'fixture', 'automation_trust_boundary', 'The reference runner must not upgrade fixture evidence.', 409);
  validateAgentOutput(result.agent.output, result.context);
  const keys = loadKeyBundle(service.paths.keys);
  const decoded = verifyCompactJwt(result.agentCredential.token, { trustedIssuers: [{ id: keys.issuer, keys: Object.keys(keys.keys).map(id => publicJwk(keys, id)) }], audience: workflow.audience, subject: workflow.subject, typ: 'vc+jwt' });
  assert(decoded.payload.purpose === workflow.purpose && decoded.payload.evidenceRoot === result.context.evidenceRoot && decoded.payload.credentialSubject?.outputHash === result.agent.outputHash && decoded.payload.credentialSubject.trustLevel === 'untrusted-fixture', 'automation_output_mismatch', 'The Agent credential is not bound to the verified workflow output.', 409);
  const report = { profile: REPORT_PROFILE, task: identity, mode: execute ? 'execute' : 'dry-run', workflowId: result.workflowId, output: result.agent.output, trustLevel: 'untrusted-fixture', actionExecuted: Boolean(result.action), actionReceipt: result.action?.receipt || null, trace: result.automation };
  return { ...report, verification: verifyAutomationReport({ service, report, task, runKey: identity.runKey }) };
}

export function automationFailure(error) {
  const exposed = publicError(error);
  return { profile: REPORT_PROFILE, ok: false, error: exposed.body.error, message: exposed.body.message, ...(error?.failureEvidence ? { failureEvidence: error.failureEvidence } : {}) };
}
