# Extension contracts

Extensions run inside the NOVA process and therefore share its trust boundary.
Treat adapter code as privileged. Pin and review it, give it narrow credentials,
and preserve the fail-closed semantics below.

## Signed source adapters

A source adapter has an `id`, a `kind` of `fixture` or `external`, optional JSON
`schema`, and an async `fetch(input)` that returns a signed envelope:

```json
{
  "profile": "nova-signed-source-0.1",
  "sourceId": "registry-a",
  "issuedAt": "2026-09-09T00:00:00.000Z",
  "expiresAt": "2026-09-09T00:05:00.000Z",
  "payload": { "claims": { "accountActive": true } },
  "payloadHash": "64 lowercase hex characters",
  "signature": {
    "alg": "EdDSA",
    "keyId": "source-ed25519-v1",
    "value": "base64url signature"
  }
}
```

`createSignedSourceEnvelope()` and `verifySignedSourceEnvelope()` implement this
custom profile. The verifier checks the source ID, hash, Ed25519 signature, time
bounds, freshness, and configured schema. It must know the source public key
through a separately trusted registration process.

Assign an `independenceKey` representing the real controlling organisation or
failure domain. Giving two adapters different labels or keys does not make them
independent when they share the same upstream authority.

`HttpsJsonSourceAdapter` adds exact HTTPS URL allowlisting, public-IP resolution,
DNS-rebinding checks, redirect rejection, JSON-only responses, restricted
headers, and bounded time and size. It expects the endpoint to return the signed
envelope, not an unsigned business payload.

## Agent adapters

An adapter must expose:

```js
{
  id: 'bounded-id',
  kind: 'fixture', // or 'external'
  contract: 'nova-agent-adapter-0.1',
  async generate({ context, prompt, signal }) { /* structured output */ }
}
```

The output must match `AGENT_OUTPUT_SCHEMA`: profile, exact context ID, bounded
summary, claim array, and proposed action array. Each claim must preserve the
context value and cite every accepted snapshot with the exact source ID and
payload hash. `AgentService` rejects invented, changed, duplicated, conflicted,
or incompletely cited claims.

`HttpJsonAgentAdapter` uses the same strict JSON transport and posts
`nova-agent-request-0.1`. Network controls do not prove model quality or prevent
a permitted endpoint from retaining data. Minimise the context before the call
and apply provider and jurisdiction controls outside the adapter.

## Actions

NOVA One intentionally has no arbitrary executor plugin. The supported action
types are:

- `record.append`: one bounded local object, no external call;
- `webhook.dispatch`: reserved contract name only. Authorization and execution
  both return `durable_action_backend_required` in 0.3.0. There is no supported
  switch that enables it.

Adding another action type is a security-sensitive protocol change. Define its
risk, parameter schema, idempotency semantics, explicit authorisation boundary,
kill switch, response evidence, receipt fields, tests, and failure receipts.
Never let an agent generate its own approval or executor credential.

Re-enabling `webhook.dispatch` requires a different durable implementation with
a transactional outbox, authenticated approver identities, upstream
idempotency, reconciliation, crash/concurrency tests and signed failure as well
as success evidence. The retired in-memory sender is not retained behind a flag.

## Witness adapters

A witness adapter implements `publish(checkpoint)` and returns at least
`receiptId`, the exact `checkpointRoot`, `provider`, and `witnessedAt`. Additional
provider proof can be retained in `proof`. NOVA validates the root binding and
records the result; the adapter/deployer must validate provider identity,
response authenticity, timestamp semantics, durability, and independent trust.

No real witness or blockchain connector ships with the project.

## Agent tool surfaces

The public package subpath `nova-one-digital-trust/tool-contracts` exports frozen
tool definitions and `getToolContract()`. The repository also contains a service
executor and JSON-lines stdio bridge:

```bash
NOVA_HOME=./nova-state node agent-tools/stdio.mjs
```

Each input line is either `{"method":"tools/list"}` or a tool call using
`{"method":"tools/call","params":{"name":"nova_status","input":{}}}`.
The legacy JSONL stdio bridge is a narrow transport, not the standard MCP server and not an
authentication boundary. Start it only for a trusted local parent process.

The standard MCP entry point is `agent-tools/mcp.mjs`; see [Agent integration](agent-integration.md) for initialization, explicit state selection and local write policy.
