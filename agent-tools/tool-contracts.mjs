const objectSchema = { type: 'object', additionalProperties: true };

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export const NOVA_TOOL_CONTRACTS = deepFreeze([
  {
    name: 'nova_status',
    description: 'Read the local NOVA service status and verify its append-only audit ledger.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'nova_issue_credential',
    description: 'Issue a short-lived, locally admitted NOVA verifiable credential.',
    inputSchema: {
      type: 'object',
      required: ['type', 'subject', 'claims', 'audience', 'purpose'],
      properties: {
        type: { type: 'string', enum: ['IdentityCredential', 'DataSourceCredential', 'PolicyDecisionCredential'] },
        subject: { type: 'string', minLength: 1, maxLength: 240 },
        claims: objectSchema,
        audience: { type: 'string', minLength: 1, maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
        jurisdiction: { type: 'string', maxLength: 64 },
        ttl: { type: 'integer', minimum: 15, maximum: 3600 },
        evidenceRoot: { type: 'string', minLength: 64, maxLength: 64 },
        actor: { type: 'string', minLength: 1, maxLength: 240 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_verify_credential',
    description: 'Verify signature, time, audience, purpose, subject, admission, status, and audit integrity for a NOVA credential.',
    inputSchema: {
      type: 'object',
      required: ['token', 'audience', 'purpose', 'subject'],
      properties: {
        token: { type: 'string', minLength: 1, maxLength: 64000 },
        audience: { type: 'string', minLength: 1, maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
        subject: { type: 'string', minLength: 1, maxLength: 240 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_credential_status',
    description: 'Read the current local status of an admitted credential.',
    inputSchema: {
      type: 'object',
      required: ['id'],
      properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_change_credential_status',
    description: 'Activate, suspend, or irrevocably revoke a locally admitted credential.',
    inputSchema: {
      type: 'object',
      required: ['id', 'state', 'actor'],
      properties: {
        id: { type: 'string', minLength: 1, maxLength: 512 },
        state: { type: 'string', enum: ['active', 'suspended', 'revoked'] },
        actor: { type: 'string', minLength: 1, maxLength: 240 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_create_presentation_challenge',
    description: 'Create a short-lived, one-use verifiable-presentation challenge bound to subject, audience, and purpose.',
    inputSchema: {
      type: 'object',
      required: ['subject', 'audience', 'purpose'],
      properties: {
        subject: { type: 'string', minLength: 1, maxLength: 240 },
        audience: { type: 'string', minLength: 1, maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
        ttl: { type: 'integer', minimum: 15, maximum: 600 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_create_presentation',
    description: 'Create a signed presentation that binds an admitted credential to a one-use challenge.',
    inputSchema: {
      type: 'object',
      required: ['challengeId', 'credentialToken', 'subject'],
      properties: {
        challengeId: { type: 'string', minLength: 1, maxLength: 240 },
        credentialToken: { type: 'string', minLength: 1, maxLength: 64000 },
        subject: { type: 'string', minLength: 1, maxLength: 240 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_verify_presentation',
    description: 'Verify a presentation and its credential bindings, then consume the challenge to prevent replay.',
    inputSchema: {
      type: 'object',
      required: ['token', 'subject', 'audience', 'purpose'],
      properties: {
        token: { type: 'string', minLength: 1, maxLength: 64000 },
        subject: { type: 'string', minLength: 1, maxLength: 240 },
        audience: { type: 'string', minLength: 1, maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_issue_selective_disclosure',
    description: 'Issue an RFC 9901 SD-JWT with the supplied application claims marked selectively disclosable.',
    inputSchema: {
      type: 'object',
      required: ['subject', 'claims', 'audience', 'purpose'],
      properties: {
        subject: { type: 'string', minLength: 1, maxLength: 240 },
        claims: { type: 'object', minProperties: 1, additionalProperties: true },
        audience: { type: 'string', minLength: 1, maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
        jurisdiction: { type: 'string', maxLength: 64 },
        actor: { type: 'string', minLength: 1, maxLength: 240 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_present_selective_disclosure',
    description: 'Create and verify an RFC 9901 SD-JWT presentation containing only the selected application claims.',
    inputSchema: {
      type: 'object',
      required: ['credentialToken', 'claimNames', 'subject', 'audience', 'purpose'],
      properties: {
        credentialToken: { type: 'string', minLength: 1, maxLength: 64000 },
        claimNames: { type: 'array', minItems: 1, maxItems: 100, uniqueItems: true, items: { type: 'string', minLength: 1, maxLength: 160 } },
        subject: { type: 'string', minLength: 1, maxLength: 240 },
        audience: { type: 'string', minLength: 1, maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_predicate_proof_capabilities',
    description: 'Report whether a maintained and independently reviewed business predicate-proof provider is configured.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'nova_run_workflow',
    description: 'Run a verified NOVA workflow with external sources, models, and action executors disabled unless the embedding service explicitly enabled scoped adapters.',
    inputSchema: {
      type: 'object',
      required: ['purpose'],
      properties: {
        name: { type: 'string', maxLength: 160 },
        actor: { type: 'string', maxLength: 240 },
        subject: { type: 'string', maxLength: 240 },
        audience: { type: 'string', maxLength: 240 },
        purpose: { type: 'string', minLength: 1, maxLength: 160 },
        sourceIds: { type: 'array', maxItems: 100, items: { type: 'string', maxLength: 160 } },
        sourceInputs: objectSchema,
        fixtures: {
          type: 'array', minItems: 1, maxItems: 32,
          items: {
            type: 'object', required: ['id', 'payload'],
            properties: {
              id: { type: 'string', minLength: 1, maxLength: 160 },
              label: { type: 'string', maxLength: 240 },
              independenceKey: { type: 'string', maxLength: 160 },
              payload: {},
              schema: {},
            },
            additionalProperties: false,
          },
        },
        claims: {
          type: ['array', 'object'],
          minItems: 1,
          maxItems: 100,
          items: { type: 'string', minLength: 1, maxLength: 160 },
          description: 'A claim-name list for registered sources, or a claim object for the isolated two-source fixture path.',
        },
        authorization: objectSchema,
        authorizationId: { type: 'string', maxLength: 240 },
        prompt: { type: 'string', maxLength: 16000 },
        action: objectSchema,
        proposedActionIndex: { type: 'integer', minimum: 0 },
        actionExecution: objectSchema,
        issueAgentCredential: { type: 'boolean' },
        credentialTtl: { type: 'integer', minimum: 15, maximum: 3600 },
        maxAgeMs: { type: 'integer', minimum: 1000, maximum: 86400000 },
        minIndependentSources: { type: 'integer', minimum: 1, maximum: 10 },
        allowConflicts: { type: 'boolean' },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'nova_demo',
    description: 'Run a complete deterministic local workflow with two signed evidence sources, explicit authorization, an evidence-bound agent credential, and a signed local-action receipt.',
    inputSchema: {
      type: 'object',
      properties: {
        subject: { type: 'string', maxLength: 240 },
        audience: { type: 'string', maxLength: 240 },
        purpose: { type: 'string', maxLength: 160 },
      },
      additionalProperties: false,
    },
  },
]);

export const tools = NOVA_TOOL_CONTRACTS;

export function getToolContract(name) {
  return NOVA_TOOL_CONTRACTS.find(tool => tool.name === name);
}
