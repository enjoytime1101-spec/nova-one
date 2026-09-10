# Architecture

NOVA One is a Node.js trust-workflow reference runtime. It turns signed
source snapshots into a minimal authorised context, validates an agent's claims
against that context, optionally executes one of two bounded action types, and
records hash-linked evidence. It does not decide whether source claims are true
or whether an organisational decision is lawful or fair.

```text
signed source envelope(s)
          |
          v
schema + signature + freshness checks
          |
          v
explicit evidence authorisation --> minimal evidence context
                                      |
                                      v
                             agent adapter output
                                      |
                                      v
                          claim-by-claim binding checks
                                      |
                     +----------------+----------------+
                     |                                 |
                     v                                 v
            agent-output credential          optional bounded action
                                                       |
                                                       v
                                             signed action receipt

Every state transition --> hash chain --> signed Merkle checkpoint
                                           |
                                           v
                              optional witness adapter receipt
```

## Runtime surfaces

- The CLI initialises local state, issues and verifies credentials, runs isolated
  fixture workflows, manages local credential status, splits and recovers key
  backups, and starts the server.
- `NovaService` is the application façade and transaction boundary for the CLI,
  HTTP server, and tools.
- The HTTP adapter exposes authenticated `/v1` JSON routes and an unauthenticated
  health route.
- Agent tools expose the same service operations through frozen JSON Schemas and
  a JSON-lines stdio bridge.
- The JavaScript API exports the services, adapters, profiles, and cryptographic
  helpers needed for an embedding application.

## Core components

| Component | Responsibility | Boundary |
| --- | --- | --- |
| `JsonStore` | Versioned local state, in-process queue plus exclusive local file lock, restrictive file modes, atomic rename and failure-only audit commits. | Single-host reference storage; not a production database, replicated lock, or backup system. |
| `TrustLedger` | Hash-chain entries, signed Merkle checkpoints, inclusion receipts, optional witness-adapter binding. | Not immutable against a host-and-key compromise; no real independent witness is configured. |
| `CredentialService` | Issue, admit, present, verify, and status-check NOVA credential envelopes; sign and verify registry/status projections. | Custom local JOSE/status profile, not a complete W3C conformance claim. |
| `PrivacyService` | RFC 9901 selective-disclosure mechanics through `@sd-jwt/core`; report disabled predicate-proof capability. | Custom NOVA application profile, no holder key binding, BBS, VC-profile claim, unlinkability, or hidden range proof. |
| `SourceService` | Register source adapters, validate signed envelopes, enforce schema and freshness, persist snapshots. | A valid source signature proves source-key control, not source accuracy or independence. |
| `EvidenceContextService` | Record bounded authorisation; minimise claims; enforce freshness, independent-source count, and conflict handling. | Independence is a configured `independenceKey`; deployers must validate real organisational independence. |
| `AgentService` | Call a deterministic or HTTPS JSON adapter and require every output claim to preserve values and cite all context evidence. | Does not evaluate semantic truth, reasoning quality, fairness, or model safety. |
| `ActionService` | Append a bounded local record and sign the receipt. | External webhook execution is disabled until a durable outbox, upstream idempotency and authenticated approval provider exist. |
| `WorkflowEngine` | Orchestrate the source-to-receipt sequence and issue an optional agent-output credential. | A fixture run is synthetic evidence and must stay labelled as such. |

## Persistence

The default `NOVA_HOME` is `~/.nova-one` and contains:

| File | Contents | Default mode |
| --- | --- | --- |
| `state.json` | Credentials, local status, challenges, authorisations, sources, snapshots, contexts, claim audits, actions, receipts, notes, audit entries, checkpoints, and witness receipts. | `0600` |
| `keys.json` | Ed25519 private and public signing key bundle. | `0600` |
| `config.json` | Version, issuer, SHA-256 digest of the API bearer token, and disabled capability defaults. | `0600` |

The directory is set to `0700`. Each transaction reads the whole state, performs
the operation, and atomically renames a complete replacement file. The in-memory
queue serialises calls made through one `JsonStore` instance. Two processes using
the same directory can race; deploy one writer per state directory.

## Integrity and witnessing

Every audit entry contains the previous entry hash and a hash of its payload.
Each append also creates an Ed25519-signed Merkle checkpoint over the current
entry set. Inclusion receipts contain the entry, checkpoint, and Merkle path.

`TrustLedger.anchorLatest(adapter)` sends a copy of the latest signed checkpoint
to `adapter.publish(checkpoint)` and accepts a receipt only when its
`checkpointRoot` exactly matches. The adapter contract and fixture tests are
implemented. NOVA One does not ship a connection to a real independent witness,
transparency log, blockchain, or trusted timestamp authority. A witness receipt
establishes only what the selected provider's separately verified contract
supports.

## Credential processing

Credentials are short-lived and locally admitted. Verification checks Ed25519,
token type, required time claims, expected audience/subject, purpose, NOVA field
bindings, signed registry admission, signed current local status, and ledger integrity.
Presentations add a time-limited, single-use challenge.

Registered external issuers must use HTTPS identifiers and Ed25519 public JWKs.
Admitted external credentials receive a NOVA local status. The current runtime
does not federate the external issuer's revocation/status system, so the local
status is the decision boundary.

See [interoperability](interoperability.md) for the exact standards boundary.

## External access

Network and model capabilities start false. The CLI does not expose
switches to enable them. Programmatic HTTPS adapters require an exact complete
URL allowlist, HTTPS, public DNS results, pinned resolved-address checks,
redirect rejection, bounded time and response size, restricted headers, and a
JSON content type. These checks reduce SSRF risk but do not establish vendor
trust, data residency, confidentiality at the destination, or service quality.

## Controlled actions

`record.append` is local, low-risk, limited to one `record` object, bounded to
256,000 canonical bytes, and protected by an idempotency key.

`webhook.dispatch` is present as a future contract but is technically disabled
in 0.3.0. The JSON transaction cannot safely persist authorization consumption
before a network side effect and reconcile a crash after acceptance. A future
adapter must use a durable outbox, forward an upstream idempotency key, reconcile
results, and consume an approval proof bound to an authenticated principal.

## Key recovery

The serialized signing-key bundle is first encrypted with a random AES-256-GCM
wrapping key. The reviewed `shamir-secret-sharing@0.0.4` implementation splits
that random key into 2–255 shares with a threshold of 2 through the share count.
Bounded fields, checksums, set binding, unique indexes, authenticated decryption,
and recovered-bundle validation detect common mix-up or corruption errors. No
direct hash of the caller secret is copied into a share. This is offline backup
and recovery, not threshold signing, an HSM, a distributed signer, or on-chain
custody. Reconstructed key material exists in process memory and in the explicit
output file.
