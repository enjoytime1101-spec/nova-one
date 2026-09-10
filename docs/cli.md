# CLI guide

The CLI operates on one local `NOVA_HOME`. External network, model and action
capabilities are not enabled by command-line switches.

## Initialise and inspect

```bash
export NOVA_HOME="$PWD/.local-nova-state"
nova-one init --issuer https://issuer.example
nova-one status
```

The first command prints a generated 256-bit API token once. Use `--api-token`
only with a randomly generated secret-manager value encoded as 43–256 base64url
characters; the local diversity check rejects obvious repeated values but is not
an entropy estimator.

## Credential operations

```bash
nova-one credential issue --stdin
nova-one credential verify --stdin
nova-one credential status --id urn:uuid:...
nova-one credential suspend --id urn:uuid:... --actor did:example:operator
nova-one credential activate --id urn:uuid:... --actor did:example:operator
nova-one credential revoke --id urn:uuid:... --actor did:example:operator
```

Issue requires `type`, `subject`, `claims`, `audience` and `purpose`. Verify
requires `token`, expected `subject`, expected `audience`, and expected
`purpose`. Revocation is final. Status projection records are signed locally;
an invalid projection signature fails closed.

Presentations use:

```bash
nova-one credential presentation challenge --stdin
nova-one credential presentation create --stdin
nova-one credential presentation verify --stdin
```

Challenges are short-lived and one-use.

## Selective disclosure

Issue a holder SD-JWT:

```bash
nova-one privacy selective-disclosure issue --stdin <<'JSON'
{
  "subject": "did:example:alice",
  "audience": "relying-party",
  "purpose": "onboarding",
  "claims": {"role":"operator","qualificationValid":true}
}
JSON
```

Protect the complete returned token; it includes the holder disclosures. Create
a presentation by supplying the token and selected names:

```bash
nova-one privacy selective-disclosure present --stdin <<'JSON'
{
  "credentialToken": "<holder token>",
  "claimNames": ["qualificationValid"],
  "subject": "did:example:alice",
  "audience": "relying-party",
  "purpose": "onboarding"
}
JSON
```

This uses RFC 9901 mechanics under `nova-rfc9901-sd-jwt-0.2`. It currently has
no holder key binding and is not a VC/BBS/range-proof profile.

## Predicate proof status

```bash
nova-one privacy predicate-proof status
```

The command returns `business_zkp_not_configured`. The prior custom Schnorr
commands were removed rather than treating key possession as age, company,
balance or budget proof.

## Workflows and demo

```bash
nova-one demo
nova-one workflow --input '{"purpose":"local-test","claims":{"status":"ready"}}'
```

These claims-object flows create local same-process fixtures. Any agent-output
credential is signed with `trustLevel: untrusted-fixture` and is rejected by the
normal production verifier. HTTP routes do not expose this fixture path.

Source-backed SDK workflows use registered source IDs, explicit authorization,
minimal context and evidence-bound agent output. External providers require
separate configuration.

## Offline key backup

```bash
nova-one keys split --shares 5 --threshold 3 --out ./offline-shares
nova-one keys recover --input ./offline-shares/share-001-of-005.json,./offline-shares/share-003-of-005.json,./offline-shares/share-005-of-005.json --out ./recovered-keys.json
```

The command encrypts the bundle with a random AES-256-GCM wrapping key, splits
that key with `shamir-secret-sharing@0.0.4`, never deletes the active key, and
refuses to overwrite an output. Reconstruction restores the entire private key
bundle in memory and the explicit output file; it is offline recovery, not HSM
custody or threshold signing.

## HTTP server

```bash
nova-one serve --host 127.0.0.1 --port 8787
```

Only literal `127.0.0.1` and `::1` are accepted. Use a trusted TLS gateway for
remote traffic.

## JSON input and exit behavior

Commands that accept JSON require exactly one of `--input`, `--file`, or
`--stdin`. `--compact` emits one compact JSON value. Validation and authorization
errors exit non-zero; server/internal failures use exit code 2.

## Versioned automation (v0.3.0)

Use `nova-one automation --file TASK.json` to preview. Add `--execute --run-key KEY` to execute, and `--out REPORT.json` to save evidence. Verify without re-execution using `nova-one automation verify --file REPORT.json --task TASK.json --run-key KEY`. The task and run key are independent expected inputs, not values trusted from the report. See [Automation](automation.md).
