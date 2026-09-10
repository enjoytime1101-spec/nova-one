import { canonical, isPlainObject, randomId, sha256, timestamp } from './canonical.mjs';
import { assert } from './errors.mjs';
import { assertJsonSchema, requestStrictJson } from './sources.mjs';

export const AGENT_ADAPTER_CONTRACT = 'nova-agent-adapter-0.1';

export const AGENT_OUTPUT_SCHEMA = Object.freeze({
  type: 'object',
  required: ['profile', 'contextId', 'summary', 'claims', 'proposedActions'],
  additionalProperties: false,
  properties: {
    profile: { const: 'nova-agent-output-0.1' },
    contextId: { type: 'string', minLength: 1, maxLength: 200 },
    summary: { type: 'string', minLength: 1, maxLength: 4_000 },
    claims: {
      type: 'array', minItems: 1, maxItems: 100,
      items: {
        type: 'object', required: ['id', 'name', 'statement', 'value', 'confidence', 'evidence'], additionalProperties: false,
        properties: {
          id: { type: 'string', minLength: 1, maxLength: 200 },
          name: { type: 'string', minLength: 1, maxLength: 160 },
          statement: { type: 'string', minLength: 1, maxLength: 2_000 },
          value: true,
          confidence: { type: 'number', minimum: 0, maximum: 1 },
          evidence: {
            type: 'array', minItems: 1, maxItems: 100,
            items: {
              type: 'object', required: ['snapshotId', 'sourceId', 'payloadHash'], additionalProperties: false,
              properties: {
                snapshotId: { type: 'string', minLength: 1, maxLength: 200 },
                sourceId: { type: 'string', minLength: 1, maxLength: 160 },
                payloadHash: { type: 'string', pattern: '^[a-f0-9]{64}$' },
              },
            },
          },
        },
      },
    },
    proposedActions: {
      type: 'array', maxItems: 20,
      items: {
        type: 'object', required: ['type', 'parameters', 'rationale'], additionalProperties: false,
        properties: {
          type: { type: 'string', enum: ['record.append', 'webhook.dispatch'] },
          parameters: { type: 'object' },
          rationale: { type: 'string', minLength: 1, maxLength: 1_000 },
        },
      },
    },
  },
});

function securityEvent(ledger, event, actor, payload) {
  try { ledger.append(event, actor, payload); } catch (error) {
    if (error.code === 'audit_integrity_failure') throw error;
  }
}

export function assertAgentAdapter(adapter) {
  assert(adapter && adapter.contract === AGENT_ADAPTER_CONTRACT, 'invalid_agent_adapter', 'The agent adapter contract version is not supported.');
  assert(typeof adapter.id === 'string' && adapter.id.length > 0 && adapter.id.length <= 160, 'invalid_agent_adapter', 'The agent adapter needs a bounded ID.');
  assert(['fixture', 'external'].includes(adapter.kind) && typeof adapter.generate === 'function', 'invalid_agent_adapter', 'The agent adapter kind or generate method is invalid.');
  return adapter;
}

function normalizedEvidence(evidence) {
  return evidence.map(item => ({ snapshotId: item.snapshotId, sourceId: item.sourceId, payloadHash: item.payloadHash }));
}

/** Enforces claim-by-claim provenance; a context-level citation alone is never accepted. */
export function validateAgentOutput(output, context, { requireAllClaims = true } = {}) {
  assert(isPlainObject(context) && context.profile === 'nova-minimal-evidence-context-0.1', 'invalid_agent_context', 'A NOVA minimal evidence context is required.');
  assertJsonSchema(output, AGENT_OUTPUT_SCHEMA, 'invalid_agent_output');
  assert(output.contextId === context.id, 'agent_context_mismatch', 'The agent output is not bound to the supplied context.', 403);
  const contextClaims = new Map(context.claims.map(claim => [claim.name, claim]));
  const names = new Set();
  for (const claim of output.claims) {
    assert(!names.has(claim.name), 'duplicate_agent_claim', `Agent claim ${claim.name} is duplicated.`, 422);
    names.add(claim.name);
    const sourceClaim = contextClaims.get(claim.name);
    assert(sourceClaim, 'uncontextualized_agent_claim', `Agent claim ${claim.name} is not present in the evidence context.`, 422);
    assert(sourceClaim.status === 'supported' && sourceClaim.conflicts.length === 0, 'conflicted_agent_claim', `Agent claim ${claim.name} is based on unresolved evidence.`, 409);
    assert(canonical(claim.value) === canonical(sourceClaim.value), 'agent_claim_value_mismatch', `Agent claim ${claim.name} changes the evidenced value.`, 422);
    const allowed = new Map(sourceClaim.evidence.map(item => [item.snapshotId, item]));
    const seen = new Set();
    for (const citation of claim.evidence) {
      assert(!seen.has(citation.snapshotId), 'duplicate_claim_evidence', `Agent claim ${claim.name} cites a snapshot more than once.`, 422);
      seen.add(citation.snapshotId);
      const evidence = allowed.get(citation.snapshotId);
      assert(evidence && evidence.sourceId === citation.sourceId && evidence.payloadHash === citation.payloadHash, 'invalid_claim_evidence_binding', `Agent claim ${claim.name} has an invalid evidence binding.`, 403);
    }
    assert(seen.size === allowed.size && [...allowed.keys()].every(id => seen.has(id)), 'incomplete_claim_evidence', `Agent claim ${claim.name} must bind all evidence used by the context.`, 422);
  }
  if (requireAllClaims) {
    const supported = context.claims.filter(claim => claim.status === 'supported').map(claim => claim.name);
    assert(supported.every(name => names.has(name)), 'agent_claim_omission', 'The agent output omitted a supported context claim.', 422);
  }
  return output;
}

export class DeterministicAgentAdapter {
  constructor({ id = 'deterministic-fixture', responder } = {}) {
    this.id = id; this.kind = 'fixture'; this.contract = AGENT_ADAPTER_CONTRACT; this.responder = responder;
  }

  async generate({ context, prompt = '' } = {}) {
    if (this.responder) return await this.responder(Object.freeze({ context: structuredClone(context), prompt }));
    const claims = context.claims.filter(claim => claim.status === 'supported').map(claim => ({
      id: `claim_${sha256({ contextId: context.id, name: claim.name }).slice(0, 24)}`,
      name: claim.name,
      statement: `${claim.name} is supported by ${claim.independentSourceCount} independent source${claim.independentSourceCount === 1 ? '' : 's'}.`,
      value: structuredClone(claim.value),
      confidence: 1,
      evidence: normalizedEvidence(claim.evidence),
    }));
    return {
      profile: 'nova-agent-output-0.1', contextId: context.id,
      summary: `Deterministic fixture evaluated ${claims.length} evidence-bound claim${claims.length === 1 ? '' : 's'}.`,
      claims, proposedActions: [],
    };
  }
}

export class HttpJsonAgentAdapter {
  constructor({
    id,
    endpoint,
    enabled = false,
    allowlist = [],
    headers = {},
    timeoutMs = 10_000,
    maxBytes = 1_000_000,
    lookup,
  } = {}) {
    assert(typeof id === 'string' && id.length > 0 && id.length <= 160, 'invalid_agent_adapter', 'A bounded HTTP agent ID is required.');
    this.id = id; this.kind = 'external'; this.contract = AGENT_ADAPTER_CONTRACT;
    this.endpoint = endpoint; this.enabled = enabled; this.allowlist = [...allowlist]; this.headers = { ...headers };
    this.timeoutMs = timeoutMs; this.maxBytes = maxBytes; this.lookup = lookup;
  }

  async generate({ context, prompt = '', signal } = {}) {
    const response = await requestStrictJson(this.endpoint, {
      enabled: this.enabled, allowlist: this.allowlist, method: 'POST', headers: this.headers,
      timeoutMs: this.timeoutMs, maxBytes: this.maxBytes, lookup: this.lookup, signal,
      body: { profile: 'nova-agent-request-0.1', context, prompt },
    });
    return response.body;
  }
}

export class AgentService {
  constructor(state, ledger, { now = () => Date.now(), requireAllClaims = true } = {}) {
    assert(state && Array.isArray(state.claimAudits), 'invalid_state', 'AgentService requires initialized state.');
    assert(ledger?.append, 'ledger_required', 'AgentService requires a TrustLedger.');
    this.state = state; this.ledger = ledger; this.now = now; this.requireAllClaims = requireAllClaims;
  }

  async run({ adapter, context, prompt = '', actor = context?.subject, signal } = {}) {
    assertAgentAdapter(adapter);
    assert(typeof prompt === 'string' && prompt.length <= 16_000, 'invalid_agent_prompt', 'The agent prompt exceeds the bounded limit.');
    try {
      const output = await adapter.generate({ context: structuredClone(context), prompt, signal });
      validateAgentOutput(output, context, { requireAllClaims: this.requireAllClaims });
      const outputId = randomId('agent-output');
      const outputHash = sha256(output);
      const createdAt = timestamp(this.now());
      const entry = this.ledger.append('agent.output_accepted', actor, { outputId, outputHash, contextId: context.id, adapterId: adapter.id, adapterKind: adapter.kind });
      for (const claim of output.claims) this.state.claimAudits.push({
        id: randomId('claim-audit'), contextId: context.id, outputId, claimId: claim.id,
        claim: claim.name, status: 'agent-output-accepted', valueHash: sha256(claim.value),
        evidenceSnapshotIds: claim.evidence.map(item => item.snapshotId), outputHash, createdAt,
      });
      return {
        id: outputId, adapter: { id: adapter.id, kind: adapter.kind }, output: structuredClone(output),
        outputHash, createdAt, auditReceipt: this.ledger.receipt(entry),
      };
    } catch (error) {
      securityEvent(this.ledger, 'security.agent_output_rejected', actor || 'unknown', { adapterId: adapter.id, adapterKind: adapter.kind, contextId: context?.id || null, reason: error.code || 'agent_adapter_failed' });
      throw error;
    }
  }
}
