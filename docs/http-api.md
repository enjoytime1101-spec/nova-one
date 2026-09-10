# HTTP API

The built-in server is a loopback-only, plaintext integration surface. It binds
only to `127.0.0.1` or `::1`. Put a separately managed TLS, authentication,
authorization and rate-limit gateway in front of it for remote use.

`GET` and `HEAD /health` are public. Every `/v1/*` route requires:

```http
Authorization: Bearer <initialisation token>
```

JSON request bodies require `Content-Type: application/json` and default to a
1 MiB limit. Errors use `{ "ok": false, "error", "message", "requestId" }`.

## Routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/v1/status` | Local state counts, capabilities and ledger diagnostic. |
| POST | `/v1/credentials/issue` | Issue a supported short-lived NOVA credential. |
| POST | `/v1/credentials/verify` | Verify with required token, audience, purpose and subject. |
| GET | `/v1/credentials/:id/status` | Read and verify the signed local status projection. |
| POST | `/v1/credentials/:id/status` | Change status; `state` and authenticated-caller-supplied `actor` are required. |
| POST | `/v1/credentials/presentations/challenges` | Create a scoped, one-use presentation challenge. |
| POST | `/v1/credentials/presentations/create` | Create the local custom presentation envelope. |
| POST | `/v1/credentials/presentations/verify` | Verify and consume a presentation challenge. |
| POST | `/v1/privacy/selective-disclosures/issue` | Issue a `nova-rfc9901-sd-jwt-0.2` holder token. |
| POST | `/v1/privacy/selective-disclosures/present` | Select claim names and return a verified SD-JWT presentation. |
| GET | `/v1/privacy/predicate-proofs/capabilities` | Report the disabled business predicate-proof boundary. |
| POST | `/v1/workflows/run` | Run a source-backed workflow; fixtures and claims objects are forbidden. |
| POST | `/v1/tools/call` | Validate and execute a published Agent tool contract. |

`POST /v1/demo` is rejected on HTTP. The local fixture demo is CLI/SDK only.
Legacy `/v1/privacy/zkp/*` paths return HTTP 410 because the custom Schnorr
implementation was removed.

## SD-JWT issue and presentation

Issue:

```json
{
  "subject": "did:example:alice",
  "audience": "relying-party",
  "purpose": "onboarding",
  "jurisdiction": "AU",
  "claims": {
    "role": "operator",
    "qualificationValid": true
  }
}
```

The response returns one complete holder `token`. It contains the claim
disclosures and must be protected like sensitive credential material. NOVA
stores only its issuer-JWT hash, identifiers, signed status and audit metadata.

Present:

```json
{
  "credentialToken": "<complete holder SD-JWT>",
  "claimNames": ["qualificationValid"],
  "subject": "did:example:alice",
  "audience": "relying-party",
  "purpose": "onboarding"
}
```

The result contains the disclosed object and a compact presentation omitting
unselected disclosures. This is RFC 9901 mechanics under a NOVA application
profile, not an SD-JWT VC, BBS proof, hidden range proof, or holder-bound proof.

## Production isolation

The HTTP boundary rejects:

- `claims` as an object on workflow requests;
- any `fixtures` array;
- `nova_demo` through `/v1/tools/call`;
- missing audience, purpose or subject on credential verification;
- tool inputs that violate the same deep-frozen schema used locally; and
- requests to removed proof-of-possession routes.

External model/source adapters still require programmatic configuration and
provider-specific trust. External webhook execution is disabled in 0.3.0 until
a durable outbox, upstream idempotency, reconciliation and real approval proof
are implemented.
