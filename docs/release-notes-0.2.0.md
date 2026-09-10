# NOVA One Digital Trust 0.2.0 corrective candidate

**Date:** 2026-09-09
**Maturity:** local release candidate; not production accepted or publicly
released.

Version 0.2.0 replaces the rejected 0.1.0 candidate. It is an independent Node
package and does not depend on a consuming application's source tree.

## Corrected in this candidate

- Replaced the hand-written disclosure format with RFC 9901 mechanics from
  exact-pinned `@sd-jwt/core@0.20.1`; special claim path segments are encoded
  using the library implementation.
- Removed the custom Schnorr proof surface. Business predicate proofs remain
  explicitly unavailable instead of being represented as ZKP.
- Replaced hand-written GF(256) code with the reviewed Privy
  `shamir-secret-sharing@0.0.4`. Caller secrets are AES-256-GCM-wrapped and only
  the random wrapping key is split; shares do not expose a direct secret hash.
- Bound mutable issuer, credential-status and presentation-challenge projections
  to their current audit events, with negative tests for older signed-record
  replacement.
- Tainted an entire workflow when any source or Agent is a fixture. HTTP
  production entry points reject inline and configured fixture adapters.
- Added exact HTTPS/network constraints, explicit non-global IPv6 exclusions,
  public-only issuer JWK validation, stronger bearer validation, JSON boundary
  checks and local action-result integrity verification.
- Kept external webhook execution disabled until a durable transactional outbox,
  authenticated approval and reconciliation backend exist.

## Local verification scope

The source suite covers credential scope, expiry, revocation, presentation
replay, projection editing and rollback, RFC 9901 disclosure, Shamir recovery,
network classification, HTTP fixture isolation, Agent claim binding, source
conflicts and freshness, local action idempotency/result integrity, kill-switch
enforcement, witness root binding, CLI and tool contracts. The release process
also runs a package dry-run, installed-package checks, examples, loopback HTTP
smoke test, dependency tree inspection and the npm advisory audit.

## Deliberate gaps

This candidate does not include W3C Bitstring Status List federation, SD-JWT
holder key binding, hidden-range/business predicate proofs, real source/model
providers, durable external actions, a real independent witness, PostgreSQL,
tenant RBAC, Passkey step-up, KMS/HSM signing, a management UI, production TLS
gateway or a public GitHub/npm release. See the original requirements matrix for
the complete acceptance boundary.
