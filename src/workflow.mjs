import { isPlainObject, randomId, sha256 } from './canonical.mjs';
import { assert } from './errors.mjs';
import { TrustLedger } from './ledger.mjs';
import { CredentialService } from './credentials.mjs';
import { SourceService } from './sources.mjs';
import { EvidenceContextService } from './context.mjs';
import { AgentService, DeterministicAgentAdapter } from './agent.mjs';
import { ActionService } from './actions.mjs';

/**
 * End-to-end orchestration: signed sources -> minimal authorized context ->
 * evidence-bound agent output -> optional policy-controlled action.
 */
export class WorkflowEngine {
  constructor(state, keyBundle, {
    now = () => Date.now(),
    ledger,
    credentials,
    privacy,
    source = {},
    context = {},
    agent = {},
    action = {},
    sourceAdapters = [],
    agentAdapter,
  } = {}) {
    assert(state?.version === 1, 'invalid_state', 'WorkflowEngine requires initialized version 1 state.');
    assert(keyBundle?.activeKeyId, 'signer_not_configured', 'WorkflowEngine requires a signing key bundle.', 503);
    this.state = state; this.keys = keyBundle; this.now = now;
    this.ledger = ledger || new TrustLedger(state, keyBundle);
    this.credentials = credentials || new CredentialService(state, keyBundle, this.ledger, { now: () => Math.floor(now() / 1000) });
    this.privacy = privacy;
    this.sources = new SourceService(state, this.ledger, { now, ...source });
    this.contexts = new EvidenceContextService(state, this.ledger, { now, ...context });
    this.agents = new AgentService(state, this.ledger, { now, ...agent });
    this.actions = new ActionService(state, keyBundle, this.ledger, { now, ...action });
    this.defaultAgentAdapter = agentAdapter;
    for (const item of sourceAdapters) {
      const adapter = item?.adapter || item;
      const metadata = item?.adapter ? item.metadata : undefined;
      this.sources.register(adapter, metadata);
    }
  }

  async run({
    sourceIds = [],
    sourceInputs = {},
    claims,
    authorizationId,
    authorization,
    subject,
    audience,
    purpose,
    actor = subject,
    agentAdapter = this.defaultAgentAdapter || new DeterministicAgentAdapter(),
    prompt = '',
    action,
    proposedActionIndex,
    actionExecution = {},
    issueAgentCredential = true,
    credentialTtl = 300,
    minIndependentSources,
    maxAgeMs,
    allowConflicts = false,
    signal,
  } = {}) {
    assert(Array.isArray(sourceIds) && sourceIds.length <= 100, 'workflow_sources_required', 'A bounded source ID list is required.');
    const resolvedSubject = subject || actor || 'urn:nova:local-user';
    const resolvedActor = actor || resolvedSubject;
    const resolvedAudience = audience || 'nova:workflow';
    assert(typeof resolvedActor === 'string' && resolvedActor.length > 0 && resolvedActor.length <= 240, 'actor_required', 'A workflow actor is required.');
    assert(typeof purpose === 'string' && purpose.length > 0 && purpose.length <= 160, 'context_purpose_required', 'A workflow purpose is required.');
    assert(action === undefined || proposedActionIndex === undefined, 'ambiguous_workflow_action', 'Specify either an explicit action or a proposed-action index, not both.');
    const workflowId = randomId('workflow');
    const fixtureClaims = isPlainObject(claims) ? claims : null;
    let selectedSourceIds = [...sourceIds];
    let requestedClaims = fixtureClaims ? Object.keys(fixtureClaims) : claims;
    if (selectedSourceIds.length === 0) {
      assert(fixtureClaims && Object.keys(fixtureClaims).length > 0, 'workflow_sources_required', 'Provide registered source IDs or a non-empty claims object for the isolated fixture path.');
      selectedSourceIds = [`fixture-a:${workflowId}`, `fixture-b:${workflowId}`];
      this.sources.registerFixture({ id: selectedSourceIds[0], payload: { claims: fixtureClaims } }, { label: 'Isolated fixture A', independenceKey: `fixture-publisher-a:${workflowId}` });
      this.sources.registerFixture({ id: selectedSourceIds[1], payload: { claims: fixtureClaims } }, { label: 'Isolated fixture B', independenceKey: `fixture-publisher-b:${workflowId}` });
    }
    let resolvedAuthorizationId = authorizationId || authorization?.id;
    if (!resolvedAuthorizationId) {
      assert(fixtureClaims || authorization?.approvedBy, 'explicit_context_authorization_required', 'External evidence requires an explicit recorded authorization or approver.', 403);
      const grant = this.contexts.authorize({
        subject: resolvedSubject, audience: resolvedAudience, purpose,
        claims: requestedClaims, approvedBy: authorization?.approvedBy || resolvedActor,
        ttlMs: authorization?.ttlMs,
      });
      resolvedAuthorizationId = grant.id;
    }
    this.ledger.append('workflow.started', resolvedActor, { workflowId, sourceIds: selectedSourceIds, claims: requestedClaims || null, subject: resolvedSubject, audience: resolvedAudience, purpose });
    try {
      const snapshots = [];
      // Sequential collection makes fixture/audit order reproducible and avoids shared-state races.
      for (const sourceId of selectedSourceIds) {
        snapshots.push(await this.sources.collect(sourceId, { actor: resolvedActor, input: sourceInputs[sourceId] }));
      }
      const context = this.contexts.build({
        snapshotIds: snapshots.map(item => item.id), claims: requestedClaims, authorizationId: resolvedAuthorizationId,
        subject: resolvedSubject, audience: resolvedAudience, purpose, actor: resolvedActor, minIndependentSources, maxAgeMs, allowConflicts,
      });
      const agentResult = await this.agents.run({ adapter: agentAdapter, context, prompt, actor: resolvedActor, signal });
      // A single fixture source or a fixture agent taints the whole derived output.
      // Mixed evidence must never be upgraded merely because one source is external.
      const fixtureMode = snapshots.some(item => item.sourceKind === 'fixture') || agentResult.adapter.kind === 'fixture';
      let agentCredential = null;
      if (issueAgentCredential) {
        agentCredential = this.credentials.issue({
          type: 'AgentOutputCredential', subject: resolvedSubject, audience: resolvedAudience, purpose, ttl: credentialTtl,
          evidenceRoot: context.evidenceRoot, actor: resolvedActor,
          claims: {
            workflowId, contextId: context.id, outputHash: agentResult.outputHash,
            trustLevel: fixtureMode ? 'untrusted-fixture' : 'source-backed',
            claimBindings: agentResult.output.claims.map(claim => ({
              name: claim.name, valueHash: sha256(claim.value),
              snapshotIds: claim.evidence.map(item => item.snapshotId),
            })),
          },
        });
      }

      let selectedAction = action;
      if (proposedActionIndex !== undefined) {
        assert(Number.isInteger(proposedActionIndex) && proposedActionIndex >= 0, 'invalid_proposed_action_index', 'The proposed-action index is invalid.');
        selectedAction = agentResult.output.proposedActions[proposedActionIndex];
        assert(selectedAction, 'proposed_action_not_found', 'The selected proposed action does not exist.', 404);
      }
      let actionResult = null;
      if (selectedAction) {
        assert(typeof selectedAction.type === 'string' && selectedAction.parameters, 'invalid_workflow_action', 'A workflow action type and parameters are required.');
        assert(isPlainObject(actionExecution), 'invalid_action_execution', 'Caller-supplied action execution metadata must be an object.');
        // Execution authority is supplied out-of-band. An agent proposal can never mint it.
        const idempotencyKey = actionExecution.idempotencyKey || (proposedActionIndex === undefined ? selectedAction.idempotencyKey : undefined);
        const authorizationToken = actionExecution.authorizationToken || (proposedActionIndex === undefined ? selectedAction.authorizationToken : undefined);
        assert(typeof idempotencyKey === 'string' && idempotencyKey.length > 0, 'idempotency_key_required', 'Workflow actions require an explicit idempotency key.');
        actionResult = await this.actions.execute({
          type: selectedAction.type, parameters: selectedAction.parameters,
          actor: resolvedActor, idempotencyKey, authorizationToken, signal,
        });
      }
      const completion = this.ledger.append('workflow.completed', resolvedActor, {
        workflowId, snapshotIds: snapshots.map(item => item.id), contextId: context.id,
        outputHash: agentResult.outputHash, agentCredentialId: agentCredential?.id || null,
        actionId: actionResult?.action.id || null,
      });
      return {
        workflowId, mode: fixtureMode ? 'fixture' : 'external-capable',
        snapshots, context, agent: agentResult, agentCredential, action: actionResult,
        auditReceipt: this.ledger.receipt(completion),
      };
    } catch (error) {
      this.ledger.append('security.workflow_failed', resolvedActor, { workflowId, reason: error.code || 'workflow_failed' });
      throw error;
    }
  }
}

export function createWorkflowEngine(state, keyBundle, ledger, credentials, privacy, options = {}) {
  const sourceAdapters = [];
  const externalSources = options.externalSources;
  if (Array.isArray(externalSources)) sourceAdapters.push(...externalSources);
  else if (externalSources?.id && externalSources?.fetch) sourceAdapters.push(externalSources);
  else if (isPlainObject(externalSources)) sourceAdapters.push(...Object.values(externalSources).filter(item => item?.id && item?.fetch));
  const selectedAgent = options.externalAgents?.contract ? options.externalAgents : undefined;
  const executorConfig = isPlainObject(options.externalActions) ? options.externalActions : {};
  return new WorkflowEngine(state, keyBundle, {
    ledger, credentials, privacy, sourceAdapters, agentAdapter: selectedAgent,
    action: {
      ...executorConfig,
      externalEnabled: options.allowExecutor === true && executorConfig.externalEnabled === true,
    },
  });
}
