# Broader requirements and remaining work

NOVA One's broader objective is safe, verifiable use of external data and controlled Agent actions across independent applications. v0.3.0 delivers an installable local workflow engineering package, Agent interfaces and open-source distribution. It does **not** declare the entire production objective accepted.

This table preserves requirements beyond the local prerelease, including engineering work that must not be misclassified as an unavailable external credential.

| Objective | Local release coverage | Remaining engineering | External evidence or resources |
| --- | --- | --- | --- |
| Platform independence | Standalone Node package and documented integration surfaces | Trust-domain/multi-tenant contracts and migration | A second application's interoperability review |
| End-to-end automation | Versioned local task, preview, execution, failure and receipt verification | General policy, authenticated approvals, durable external action lifecycle | Authorized real source/model/executor trial |
| Verifiable credentials | Ed25519, scope, issuer, time, admission, lifecycle and ledger binding | Standard profile processing, schemas, rotation and interop | Independent implementation conformance |
| Credential status | Signed local active/suspended/revoked projection | Standard status resolver/publisher, caching/failure/privacy semantics | External issuer/status federation tests |
| Privacy | RFC 9901 disclosure mechanics; undisclosed attributes excluded from persisted state | Holder/key binding, replay/linkability and external key resolution | Cross-implementation and privacy review |
| Business predicate proofs | Explicit disabled capability; no substituted custom mathematics | Maintained verifier adapter, statement/witness design and governance | Attribute issuers and independent cryptographic review |
| Trusted data | Signed envelopes, constrained HTTPS adapter, freshness/conflict checks | Provider license/region enforcement, rotation and additional network conformance | Authorized provider keys, data licenses and real endpoints |
| Agent output governance | Claim-by-claim evidence binding and deterministic example | Provider adapters and evaluations of hallucination/bias/fairness | Real models, licensed evaluation data and human review |
| Controlled actions | Idempotent local record.append and signed receipts | Durable outbox, upstream idempotency, retry/reconciliation, real approval identity | Authorized executor sandbox and approvers |
| Distributed trust | Signed local Merkle audit and witness adapter | Operational witness protocol, failure/quorum and rollback design | Independently operated witness organizations |
| User/admin experiences | Developer CLI and browser proof Playground | Authenticated account, credential, approval and recovery console | Real identity provider and usability validation |
| Persistent operation | Single-host coordinated JSON reference store | Production database adapter, transactions/migrations, backup and recovery | Database infrastructure, recovery objectives and drills |
| Authorization | Loopback bearer API; MCP read-only by default with local write allowlist | Tenant RBAC, least privilege, step-up and separation of duties | Organizational roles, IdP and administrators |
| Key custody | Private local files and encrypted offline recovery shares | Signer/KMS port, lifecycle/rotation and failures | KMS/HSM account, key ceremony and independent review |
| Service operations | Loopback boundary and bounded request validation | TLS gateway contract, rate limits, metrics/alerts and incident response | Domain/certificates, monitoring and operating team |
| Governance and compliance | Dated evidence mappings and explicit limitations | Control-specific evidence export and governance review | Appropriate legal/security professionals; no automatic certification |

## Release interpretation

A public repository and passing tests establish the delivered code and documented local behavior. They do not prove source truth, real-world identity, independent trust, mathematical ZKP, model accuracy, legal compliance or safe production operation.

Fixtures, local actors and deterministic models are marked as such. Missing interfaces, policies, adapters and tests remain project engineering responsibilities. Missing authorized accounts or independent organizations are external dependencies. Neither category may be marked complete merely because another feature passed.
