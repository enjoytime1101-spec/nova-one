# JavaScript SDK

NOVA One is an ES module package for Node.js 20 or newer. Runtime dependencies
are exact-version locked and reviewed in [`dependency-security.md`](dependency-security.md).

```js
import {
  createNovaService,
  WorkflowEngine,
  FixtureSourceAdapter,
  HttpsJsonSourceAdapter,
  DeterministicAgentAdapter,
  HttpJsonAgentAdapter,
  TrustLedger,
  splitKeyBundle,
  combineKeyBundle,
} from 'nova-one-digital-trust';
```

## Service façade

```js
import { createNovaService } from 'nova-one-digital-trust';

const nova = createNovaService({ home: './nova-state' });
const initialized = nova.isInitialized()
  ? nova.status()
  : nova.initialize({ issuer: 'https://issuer.example' });

const issued = await nova.issueCredential({
  type: 'IdentityCredential',
  subject: 'did:example:user-7',
  claims: { accountActive: true },
  audience: 'review-service',
  purpose: 'review-output',
  jurisdiction: 'AU',
  ttl: 300,
});

const verified = nova.verifyCredential({
  token: issued.token,
  subject: 'did:example:user-7',
  audience: 'review-service',
  purpose: 'review-output',
});
```

The public façade can issue `IdentityCredential`, `DataSourceCredential`, and
`PolicyDecisionCredential` as local-issuer attestations. `AgentOutputCredential`
is emitted only by the evidence-bound workflow. `DataSnapshotCredential` and
`ActionReceiptCredential` are reserved profile names but are not implemented as
VC issuance paths in this release. All three are rejected by CLI, HTTP and Agent
tools.

If `initialize()` creates configuration, it returns the API bearer token once.
Persist it in a secret manager; the configuration stores only its SHA-256 digest.

## Isolated workflow

`NovaService.runWorkflow()` accepts a non-empty claims object for the built-in
synthetic path:

```js
const result = await nova.runWorkflow({
  name: 'local-evidence-check',
  actor: 'did:example:operator',
  subject: 'did:example:operator',
  audience: 'local-review',
  purpose: 'review-synthetic-claims',
  claims: { accountActive: true, region: 'AU' },
});
```

The workflow generates two isolated source keys and independently labels the two
fixture sources. That exercises the independence threshold mechanically; it is
not evidence from two real independent organisations. Its agent credential is
signed with `trustLevel: untrusted-fixture` and the normal verifier rejects it.
HTTP routes prohibit this claims-object path.

## Configured workflow engine

Use `JsonStore.transaction()` so workflow state is persisted. Register adapters
inside the transaction because a `WorkflowEngine` is bound to that state object.

```js
import {
  JsonStore,
  loadKeyBundle,
  WorkflowEngine,
  FixtureSourceAdapter,
} from 'nova-one-digital-trust';

const store = new JsonStore('./nova-state/state.json');
const keys = loadKeyBundle('./nova-state/keys.json');

const result = await store.transaction(async state => {
  const first = new FixtureSourceAdapter({
    id: 'registry-a',
    payload: { claims: { accountActive: true } },
    schema: {
      type: 'object',
      required: ['claims'],
      properties: { claims: { type: 'object' } },
      additionalProperties: false,
    },
  });
  const second = new FixtureSourceAdapter({
    id: 'registry-b',
    payload: { claims: { accountActive: true } },
  });
  const engine = new WorkflowEngine(state, keys, {
    sourceAdapters: [
      { adapter: first, metadata: { independenceKey: 'publisher-a' } },
      { adapter: second, metadata: { independenceKey: 'publisher-b' } },
    ],
  });
  const authorization = engine.contexts.authorize({
    subject: 'did:example:alice',
    audience: 'review-service',
    purpose: 'check-account',
    claims: ['accountActive'],
    approvedBy: 'did:example:reviewer',
  });
  return engine.run({
    sourceIds: ['registry-a', 'registry-b'],
    authorizationId: authorization.id,
    claims: ['accountActive'],
    subject: 'did:example:alice',
    audience: 'review-service',
    purpose: 'check-account',
  });
});
```

Fixture private keys exist only to make repeatable tests possible. Never present
fixture output as production source evidence.

## Local action

```js
const actionResult = await store.transaction(async state => {
  const engine = new WorkflowEngine(state, keys);
  return engine.actions.execute({
    type: 'record.append',
    parameters: { record: { decision: 'manual-review-required' } },
    actor: 'did:example:operator',
    idempotencyKey: 'review-2026-09-09-001',
  });
});
```

The same idempotency key with identical content returns the prior receipt; reuse
with changed content is rejected.

## Witness adapter

The following is an isolated binding fixture, not an independent witness:

```js
const anchored = await store.transaction(async state => {
  const ledger = new TrustLedger(state, keys);
  return ledger.anchorLatest({
    async publish(checkpoint) {
      return {
        receiptId: `fixture-${checkpoint.root.slice(0, 16)}`,
        checkpointRoot: checkpoint.root,
        provider: 'isolated-fixture',
        witnessedAt: new Date().toISOString(),
        proof: { fixture: true },
      };
    },
  });
});
```

For a real adapter, transmit the complete signed checkpoint to an authenticated
independent service and map its response to the same fields. The runtime
validates the returned root binding, but the deployer must validate the
provider's identity, proof, timestamp semantics, durability, and trust model.
NOVA One does not supply that provider connection.

## Key backup primitives

```js
const shares = await splitKeyBundle(keys, { shares: 5, threshold: 3 });
const recovered = await combineKeyBundle([shares[0], shares[2], shares[4]]);
```

These functions return sensitive material. Prefer the CLI's exclusive file
creation for operator workflows, isolate shares, and review memory handling for
the deployment.

## Selective disclosure and predicate proofs

`NovaService.issueSelectiveDisclosure()` returns a complete holder SD-JWT.
`presentSelectiveDisclosure()` takes `claimNames` and returns a verified compact
presentation. It uses RFC 9901 mechanics through `@sd-jwt/core@0.20.1` under a
custom NOVA application profile, without holder key binding. Do not place the
complete holder token in a prompt or log.

`predicateProofCapabilities()` currently returns `enabled: false`. The custom
Schnorr implementation and active tools were removed; age, qualification and
hidden numeric thresholds are not implemented.

External webhook execution is also disabled until a durable outbox, upstream
idempotency, reconciliation, and authenticated approval provider are available.

## API map

| Module area | Main exports |
| --- | --- |
| Canonical data | `canonical`, `sha256`, `randomId`, base64url and timestamp helpers |
| Keys and tokens | `createKeyBundle`, `publicJwk`, byte signing/verification, compact token helpers |
| Persistence and audit | `JsonStore`, `statePaths`, `TrustLedger`, `merkle`, `verifyInclusion` |
| Credentials | `CredentialService` |
| Privacy | `PrivacyService` |
| Key recovery | `splitSecret`, `combineShares`, `splitKeyBundle`, `combineKeyBundle` |
| Sources | source envelope helpers, schema subset, strict JSON transport, source adapters and service |
| Context | `EvidenceContextService` |
| Agents | agent schema, validators, adapters and service |
| Actions | action types, receipt verifier and service |
| Workflow | `WorkflowEngine`, `createWorkflowEngine` |
| Application | `NovaService`, `createNovaService`, HTTP handler/server helpers |

These are pre-1.0 APIs. Pin the package version and review release notes before an
upgrade.
