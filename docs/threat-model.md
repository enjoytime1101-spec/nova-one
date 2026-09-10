# Threat model

This document describes the security model of the open-source NOVA One runtime.
It is a starting point for a deployment-specific review, not a certification or
penetration-test report.

## Assets and trust boundaries

| Asset | Why it matters | Minimum control outside NOVA One |
| --- | --- | --- |
| Ed25519 private key bundle | Can issue local credentials and sign checkpoints | Encrypted storage, least privilege, backup, rotation, access logging |
| JSON state | Contains credential tokens, workflow records, challenges, and audit history | Restricted filesystem access, encrypted backups, integrity monitoring |
| Bearer or administrator credentials | May reach privileged API operations | TLS, secret manager, rotation, rate limits, phishing-resistant MFA where available |
| Source evidence and action input | Determines claims and proposed effects | Source authentication, validation, provenance review, minimisation |
| Executor credentials | Can cause external side effects | Separate secret domain, narrow scopes, approval gates, provider-side audit |

The built-in process trusts its configured local key and admitted issuer
registry. The host operating system, reverse proxy, identity provider, source
systems, executors, backup service, and human approvers are separate trust
boundaries.

## Threats and expected controls

### Stolen signing key

An attacker with the private key can create signatures that look locally valid.
Keep the key outside source control, restrict host access, rotate on suspected
compromise, suspend the affected issuer or key through deployment governance,
and re-establish trust out of band. The current local bundle is not an HSM or
threshold-signature implementation. NOVA encrypts the bundle under a random
wrapping key and Shamir-splits that key, but recovery still reconstructs the
entire bundle; shares do not keep the key distributed during signing. Keep the
shares in separate trust domains and test restoration without replacing the
active key.

### State rollback, deletion, or tampering

Hash-chain and checkpoint verification detects inconsistent edits, but an
attacker controlling both state and the signing key can rewrite history. A
whole-file rollback may also be indistinguishable without an independent latest
checkpoint. `TrustLedger.anchorLatest()` rejects an adapter receipt whose root
does not match the latest signed checkpoint, but the repository supplies no real
independent witness. Authenticate a production witness and retain its checkpoint
and proof in a separate trust domain if rollback resistance is required. Restore
tests and retention policy remain operator responsibilities.

### Credential replay or scope confusion

Verify signature, issuer, key, token type, time bounds, audience, subject,
purpose, local admission, status, and challenge state. Signed credential-status,
issuer-registry and challenge projections are checked against the latest
matching audit event, preventing selective rollback while the current ledger is
present. Challenges are single-use and time-limited. Do not reuse a presentation
or proof across audiences or purposes. Whole-store rollback still requires an
independent latest-checkpoint witness to detect.

### False or poisoned evidence

A digest preserves integrity of supplied evidence; it does not validate that
evidence. Authenticate sources, record collection time and method, validate
schemas, set freshness limits, and require an independent source when a policy
calls for one. An `independenceKey` is a deployment assertion, not proof of
organisational independence. Treat AI-generated assertions as untrusted until
the fixed workflow checks bind them to accepted evidence.

### Unauthorised or confused-deputy action

Keep proposals separate from caller-supplied execution metadata. `record.append`
is a bounded local action and does not require human approval.
`webhook.dispatch` is disabled in 0.2.0. The local JSON transaction cannot
durably persist authorization consumption before an external side effect or
reconcile a crash after the provider accepted it. Re-enable external actions
only behind a transactional outbox, upstream idempotency, result reconciliation,
and independently authenticated approval service. NOVA One has no general
policy DSL, policy evaluator, or dry-run API. No prompt text is an authorisation
signal.

### Privacy disclosure

Minimise data before it reaches the service. A credential token can contain
claims in readable encoded form even when signed. A complete SD-JWT held by the
holder contains its disclosure values; a selective presentation omits the
unselected disclosures. NOVA does not persist raw SD-JWT application claims,
but callers must protect the holder token and avoid putting it in logs or model
prompts.

### Denial of service and resource exhaustion

Apply body-size, token-size, concurrency, and request-rate limits at the network
edge. Monitor disk space and ledger growth. The local JSON store serialises
writes within one process and is not a multi-node transactional database.

### Dependency and build compromise

Runtime dependencies are exact-version locked. Use `npm ci`, verify lockfile and
package provenance, review release diffs, run online advisory checks, and keep a
license/SBOM inventory. Dependency count is not a security proof; see
[`dependency-security.md`](dependency-security.md).

## Non-goals

NOVA One does not by itself provide host hardening, endpoint protection, DDoS
mitigation, user authentication, legal identity proofing, source truth,
independent witnessing, HSM custody, disaster recovery, privacy compliance,
model evaluation, or organisational governance. These controls must be designed
and evidenced by the deployer.
