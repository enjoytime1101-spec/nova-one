# Security policy

## Supported versions

The rejected `0.1.0` candidate is unsupported. Security fixes target the latest
`0.x` release candidate, but no `0.x` build is approved for production merely by
being packaged. Verify provenance, the threat model, and the release evidence.

## Reporting a vulnerability

Use private GitHub vulnerability reporting. Include the affected version,
deployment mode, minimal reproduction, impact, required privilege and proposed
mitigation. Never include live credentials, private keys, personal information,
or data from a system you do not own.

## Enforced 0.3.0 boundaries

- The built-in plaintext HTTP server binds only to `127.0.0.1` or `::1`.
- Every `/v1/*` request requires the bearer token. Credential verification also
  requires an expected audience, purpose and subject.
- Tool calls are checked against the same deep-frozen schemas on both local and
  HTTP paths.
- HTTP routes reject fixture/self-asserted workflows, configured fixture source
  or Agent adapters, and the local demo. Any fixture source or Agent taints the
  entire output as signed `trustLevel: untrusted-fixture`, which the normal
  verifier rejects.
- Credential, issuer, credential-status and presentation-challenge projection
  records are locally signed and checked against current audit events before
  they influence a decision.
- RFC 9901 SD-JWT processing uses `@sd-jwt/core@0.20.1`, limits issuer signing to
  EdDSA, checks exact scope and required disclosed claims, and stores no raw
  selectively disclosable attributes in local state.
- The hand-written Schnorr and GF256 implementations are removed. Offline
  recovery AES-256-GCM-wraps the secret, splits only the random wrapping key
  with `shamir-secret-sharing@0.0.4`, and verifies authenticated decryption.
- IP parsing uses `ipaddr.js`; non-unicast, mapped private, NAT64, transition,
  documentation and other reserved destinations are rejected.
- External webhook actions are technically disabled because the JSON store
  cannot implement a crash-safe transactional outbox and reconciliation.
- Business predicate proofs are technically disabled until a maintained,
  independently reviewed provider and issuer/revocation governance are present.

## Remaining security limits

NOVA One is still a local reference runtime, not a complete security boundary.

- `state.json`, `keys.json` and `config.json` remain sensitive local files. File
  permissions are not a substitute for KMS/HSM custody, production databases,
  RBAC, backups, recovery drills or host hardening.
- A local signer and local signed projection can detect edits without the key;
  they do not protect against host-and-key compromise or whole-directory
  rollback. No real independent witness or trusted timestamp is configured.
- The custom NOVA credential/status profiles do not yet have complete W3C
  VC-JOSE/COSE or Bitstring Status List conformance evidence.
- The NOVA SD-JWT application profile has no holder key binding and is not BBS,
  a VC profile, an unlinkability guarantee, or a hidden range proof.
- Signed source bytes prove key control and integrity, not truth, independence,
  fairness, legal compliance, or safety.
- Real source, model, witness and approval integrations require independent
  authentication, provider-specific conformance testing and operational review.

Review [dependency-security.md](docs/dependency-security.md),
[threat-model.md](docs/threat-model.md), and the
[original requirements matrix](docs/original-requirements-matrix.md).
