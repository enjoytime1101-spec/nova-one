# Dependency and cryptography review

**Review date:** 2026-09-10
**Release candidate:** 0.3.0

NOVA One does not use dependency count as a security claim. Security-sensitive
code should prefer a maintained implementation with public specifications,
tests, locked versions, license review, advisory review, and independent review
where available.

## Locked runtime dependencies

| Package | Locked version | Purpose | License | Security evidence and limits |
| --- | ---: | --- | --- | --- |
| [`@sd-jwt/core`](https://github.com/openwallet-foundation/sd-jwt-js) | 0.20.1 | RFC 9901 SD-JWT packing, disclosure selection and validation | Apache-2.0 | 0.20.0 fixed [GHSA-f9j6-8p6x-r9j6](https://github.com/openwallet-foundation/sd-jwt-js/security/advisories/GHSA-f9j6-8p6x-r9j6). NOVA pins 0.20.1, limits issuer algorithms to EdDSA, checks exact scope and required disclosed claims, and tests malformed disclosures. No independent audit claim is made. |
| `@owf/identity-common` | 0.3.2 | Encoding utilities used by SD-JWT core | Apache-2.0 | Declared directly at an exact version so a consumer install does not float the compatible transitive range; locked by `package-lock.json` and included in audit and inventory. |
| [`shamir-secret-sharing`](https://github.com/privy-io/shamir-secret-sharing) | 0.0.4 | Offline wrapping-key splitting/reconstruction | Apache-2.0 | The project publishes independent [Cure53](https://cure53.de/audit-report_privy-sss-library.pdf) and [Zellic](https://github.com/Zellic/publications/blob/master/Privy_Shamir_Secret_Sharing_-_Zellic_Audit_Report.pdf) reviews. JavaScript cannot guarantee constant time. NOVA first encrypts the caller secret with a random AES-256-GCM key, splits only that key, bounds encoded fields, and uses authenticated decryption to verify reconstruction. This is offline recovery, not threshold signing. |
| [`ipaddr.js`](https://github.com/whitequark/ipaddr.js) | 2.2.0 | Canonical IPv4/IPv6 parsing and range classification | MIT | Replaces textual prefix matching. NOVA additionally blocks deprecated site-local and current documentation prefixes and tests expanded, compressed, mapped and NAT64 forms. A controlled egress proxy remains preferable in production. |

The standard MCP stdio server adds `@modelcontextprotocol/sdk@1.30.0`
([official SDK](https://github.com/modelcontextprotocol/typescript-sdk), MIT).
It uses the v1 `Server` and stdio transport with NOVA's existing JSON Schema
validation. Its HTTP/OAuth transports are not exposed by this package. The SDK
increases the transitive dependency graph; the full locked graph, including
peer dependencies and license identifiers, is in the generated SBOM. Direct
versions are fixed; consumers installing the npm tarball resolve transitive
ranges under their own lockfile. Clone the source and use `npm ci` for this
release's exact transitive versions.

The lockfile records registry integrity digests and the release includes a
[CycloneDX 1.5 SBOM](sbom.cdx.json). `npm audit --audit-level=low`
reported zero known vulnerabilities on the review date. Registry availability
and an audit database are external dependencies, so CI must fail rather than
silently treating an unavailable audit endpoint as a clean result.

## Removed custom cryptography

- The hand-written GF(256) Shamir implementation was removed. Direct secret
  hashes were also removed from shares so one low-entropy share does not expose
  an offline password-verification oracle.
- The custom salted-claim disclosure format was removed from active surfaces.
- The hand-written MODP/Schnorr Fiat–Shamir proof was removed, together with its
  CLI and Agent tools. Legacy HTTP paths return HTTP 410.

Repository scans and tests should reject reintroduction of the former profiles:
`nova-shamir-gf256-0.1`, `nova-salted-claim-digest-0.1`, and
`Schnorr-PoK-Fiat-Shamir`.

## SD-JWT profile boundary

The implementation uses the Standards Track [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)
mechanics but currently defines a NOVA application envelope (`typ=nova+sd-jwt`).
It does **not** claim the IETF SD-JWT VC draft profile, W3C `vc+sd-jwt`, BBS,
unlinkable derived proofs, or holder key binding. The issuer returns the complete
credential to the holder; its disclosures necessarily contain the holder's raw
claim values. NOVA does not persist those raw selectively disclosable claims in
its local state.

## Business predicate proof boundary

SD-JWT reveals selected signed facts; it does not prove a hidden numeric range.
For most business cases the preferred design is issuer-signed derived claims
such as `ageOver18`, `qualificationValid`, or `quotaBand`, selectively disclosed
through SD-JWT. These are signed attestations, not mathematical zero-knowledge
range proofs.

If hidden integer predicates are mandatory, a separate AnonCreds profile is a
candidate because the [Hyperledger AnonCreds](https://github.com/anoncreds/anoncreds-rs)
implementation has production history and predicate/revocation support. It is
not enabled here: its native runtime, schema/issuer governance, link-secret
model, revocation system, deployment targets, and independent security review
must be qualified as a separate component. BBS and experimental general ZK
libraries remain research-only.

## Release gates

1. Use `npm ci`; do not float dependency versions.
2. Run tests, syntax/independence scan, package dry run, license inventory, SBOM,
   and online advisory audit in CI.
3. Test RFC vectors, malformed disclosures, algorithm confusion, missing claims,
   scope mismatch, expiry, replay and downgrade behavior.
4. Keep external actions and business predicate proofs disabled until their own
   architecture and independent review gates pass.
5. Repeat independent source review after any cryptographic or trust-boundary
   change.
