# Tool contracts

Read this reference when calling NOVA One tools. The executable source of truth
is MCP `tools/list`. The original thirteen shared contracts remain in
`agent-tools/tool-contracts.mjs`; the additional MCP receipt verifier is in
`agent-tools/mcp-receipts.mjs`. Use the live schema if documentation differs.

MCP defaults to five read-only tools: status, credential verification, credential
status, predicate-proof capability status, and local action-receipt verification.
Every other tool below requires a local operator startup allowlist. Presentation
verification consumes a challenge; selective-disclosure presentation writes an
audit event; signing a new presentation is also gated. Do not infer read-only
permission from a tool's name. The legacy JSONL adapter has its original behavior
and is not an MCP or permission-bypass fallback.

All inputs are JSON objects. Preserve returned identifiers and pass exact
audience, purpose, subject, hashes, and approval-bound input to later steps. The
live schemas set the authoritative length, type, and enum limits.

## `nova_status`

No input fields. Confirms initialisation, capability flags, record counts, and
ledger verification. `ledger.valid` must be true before relying on the store.
Capability flags describe this process only.

## `nova_issue_credential`

Required: `type`, `subject`, `claims`, `audience`, and `purpose`. Optional:
`jurisdiction`, `ttl` (15–3600 seconds), 64-character `evidenceRoot`, and
`actor`. The public tool accepts `IdentityCredential`, `DataSourceCredential`,
and `PolicyDecisionCredential`. `AgentOutputCredential` is emitted only by the
evidence-bound workflow. Data snapshot and action receipt VC profile names are
reserved but are not implemented in this release. Issue only when the user or
workflow is authorised to create the credential. Issuance does not verify the
truth of `claims`.

## `nova_verify_credential`

Required: `token`, `audience`, `purpose`, and `subject`.
Success verifies the supported signature and time claims, expected scope, local
admission, current local status, and audit integrity. Decoding the token is not
verification.

## `nova_credential_status`

Requires the credential `id`. The result is the custom local status used by the
current registry. It is not a federated or W3C Bitstring Status List result.

## `nova_change_credential_status`

Requires `id`, `state`, and `actor`. `state` is `active`, `suspended`, or
`revoked`. Revocation is final. Confirm authority to change status before the
call and report the returned audit receipt.

## Presentation tools

`nova_create_presentation_challenge` requires `subject`, `audience`, and
`purpose`, with optional `ttl`. Preserve the returned challenge exactly.
`nova_create_presentation` requires that challenge's `challengeId`, an admitted
`credentialToken`, and the exact `subject`. `nova_verify_presentation` requires
the presentation `token` and exact `subject`, `audience`, and `purpose`; success
consumes the one-use challenge. Creating or decoding a presentation is not
verification.

## Selective-disclosure tools

`nova_issue_selective_disclosure` requires `subject`, non-empty `claims`,
`audience`, and `purpose`; `jurisdiction` and `actor` are optional. Protect the
complete returned holder token. `nova_present_selective_disclosure` requires the
credential token, at least one `claimNames` entry, and the expected
subject/audience/purpose. These tools use RFC 9901 mechanics under the custom
`nova-rfc9901-sd-jwt-0.2` application profile. They do not provide holder key
binding, an SD-JWT VC, BBS, unlinkable derived proofs, or hidden ranges.

## `nova_predicate_proof_capabilities`

No input fields. It currently reports `enabled: false` and
`business_zkp_not_configured`. The former custom Schnorr tools are unavailable.
Do not represent signed boolean attestations as mathematical predicate proofs.

## `nova_verify_action_receipt` (MCP only, read-only)

Requires `receipt`, `expectedIssuer`, `expectedKeyId`, `expectedActionId`,
`expectedRequestHash` (64 lowercase hexadecimal characters), and `expectedActor`.
The expectations come from the agreed operation. The verifier uses the keys of
the operator-selected `NOVA_HOME`, checks signature and exact context, confirms
local receipt/action admission, verifies the stored record hash and audit-chain
binding, and never re-executes the action. It rejects arbitrary supplied public
keys. A successful result confirms a completed local `record.append`, not an
external provider action or independent witnessing. The local trust-store
selection must not come from the untrusted receipt.

## `nova_run_workflow`

Requires `purpose`. Important optional inputs include `name`, `actor`, `subject`,
`audience`, `sourceIds`, `sourceInputs`, `fixtures`, `claims`, `authorization`,
`authorizationId`, `prompt`, `action`, `proposedActionIndex`,
`actionExecution`, `issueAgentCredential`, `credentialTtl`, `maxAgeMs`,
`minIndependentSources`, and `allowConflicts`. The live workflow schema and
runtime validation are authoritative. `claims` is a claim-name array for
registered sources or a non-empty claim object for the isolated two-source
fixture path.

Do not set `allowConflicts` merely to obtain a successful run. A context that
retains conflicts must not be represented as establishing the conflicted claim.
An `action` is not executed unless the workflow returns an execution result and
receipt after the implemented fixed action controls. Only local `record.append`
is enabled in this reference transport; external webhook execution is technically
disabled. The CLI automation runner provides a separate dry-run mode. Do not
invent a `dryRun` parameter for this MCP tool; its live schema is authoritative.

## `nova_demo`

Accepts optional `subject`, `audience`, and `purpose`. It runs two independently
labelled signed fixtures through context authorisation, deterministic agent
validation, credential verification, local `record.append`, and signed receipts.
Its result demonstrates the complete local control path; it is not external
evidence, a live model result, or an executed provider action.

## Result interpretation

Treat errors as fail-closed. Do not retry a mutation with changed input under the
same idempotency key. A successful verification establishes only the properties
listed by that verifier. A receipt must bind the expected action, input, approval
where required, result, and ledger checkpoint before it is described as an
executed action.
