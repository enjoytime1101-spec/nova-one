# Interoperability and cryptographic profiles

**Review date:** 9 September 2026

NOVA One uses standards-shaped documents with intentionally narrow local
profiles. This page distinguishes implemented behaviour from external standards.
It is not a conformance statement.

| Area | External specification status | NOVA One implementation | Interoperability boundary |
| --- | --- | --- | --- |
| Credential data model | [Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) is a W3C Recommendation dated 15 May 2025. | Documents use the VC v2 context and common fields, plus NOVA application fields. | No complete W3C conformance test result or independent interoperability report is provided. Treat `profile: nova-vc-jose-0.1` as a custom profile. |
| JOSE/COSE securing | [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vc-jose-cose/) is a W3C Recommendation dated 15 May 2025. | Compact Ed25519-signed `vc+jwt` and `vp+jwt`-labelled envelopes use NOVA canonical JSON and claim binding. | The envelope is custom and is not claimed to implement the Recommendation's complete enveloped-credential, media-type, processing, or test requirements. A generic JWT library must not be assumed interoperable. |
| Credential status | [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/) is a W3C Recommendation dated 15 May 2025. | Local signed per-credential `active`, `suspended`, and `revoked` projections are exposed as `NovaCredentialStatus2026`. | This is not a Bitstring Status List. Status depends on the NOVA registry; offline or third-party verifiers need a standard adapter and freshness policy. |
| Selective disclosure | [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) defines SD-JWT mechanics. [Data Integrity BBS Cryptosuites](https://www.w3.org/TR/vc-di-bbs/) is a separate W3C track. | `@sd-jwt/core@0.20.1` issues and presents named claims under `nova-rfc9901-sd-jwt-0.2`; EdDSA, time, issuer, exact scope, admission, signed status and required claims are checked. | `typ=nova+sd-jwt` is a custom application profile. It is not an SD-JWT VC, W3C `vc+sd-jwt`, BBS, unlinkable derived proof, or holder-bound presentation. |
| Business predicate proof | SD-JWT disclosure does not prove a hidden numeric range. Predicate proof systems require separate issuer, holder, verifier and revocation semantics. | The prior custom Schnorr implementation and its active surfaces were removed. Capability status returns `business_zkp_not_configured`; legacy HTTP paths return 410. | Age, company qualification, balance, budget and other hidden predicates are not implemented. Issuer-signed boolean facts must be labelled attestations, not mathematical ZKP. |
| Audit integrity | Hash chains, Merkle inclusion proofs, and digital signatures are general cryptographic constructions. | Canonical event hashes form a chain; each append creates a signed Merkle checkpoint and receipts include an inclusion path. A witness-adapter receipt is accepted only for the exact checkpoint root. | The adapter contract is implemented, but no real independent witness, trusted timestamp, transparency-log federation, public blockchain anchor, or external append-only storage is configured. A signer and state compromise can defeat the local-only trust model. |

## Verifier requirements

Do not accept a token because it decodes or has familiar VC fields. Use NOVA's
verification operation and require the expected audience, purpose, and subject.
Verification must also check the admitted issuer/key, EdDSA signature, token
type, time claims, identifier bindings, local credential admission, credential
status, and audit-ledger integrity. Presentation challenges must be unexpired,
bound to their scope, and consumed once. SD-JWT currently lacks holder key
binding, so a bearer presentation must not be used where holder possession is
required.

## Adapter requirements

An adapter that claims compatibility with another ecosystem must define:

- the exact input and output profiles and registered media types;
- one-way versus round-trippable transformation;
- canonicalisation and semantic preservation rules;
- issuer/key resolution and trust policy;
- status resolution, privacy, caching, and freshness behaviour;
- audience, purpose, subject, holder, and challenge binding;
- loss, correlation, replay, and downgrade risks; and
- conformance tests and independent interoperability fixtures.

Until those artefacts exist, label the integration a custom adapter rather than
standards conformance.

## Roadmap gaps

The following are not implemented or certified in this release:

- a conforming VC JOSE/COSE processor and public conformance report;
- Bitstring Status List publication and privacy-preserving retrieval;
- BBS credentials or unlinkable BBS derived proofs;
- standards-based attribute, predicate, or range proofs;
- independently witnessed or externally anchored checkpoints;
- production identity, evidence, action-provider, or governance certification;
- a public trust registry with governance, key rotation, and federation rules.
