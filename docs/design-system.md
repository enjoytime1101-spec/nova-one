# NOVA One Playground design system

The Playground is a static, English-language browser proof demonstration at
`https://enjoytime1101-spec.github.io/nova-one/`. GitHub Pages publishes the
contents of `playground/`; relative assets also work beneath a project path.
There is no build dependency, server runtime, provider integration, API key,
telemetry, font CDN or data upload. The Node.js runtime remains a separate
product surface and format.

## Visual direction: a precision trust workbench

Deep black surfaces carry the evidence. Ice cyan identifies verified bytes and
available operations. Warm gold identifies scoped context, agent reasoning and
policy authority. The interface is a working surface: editable source and
scenario controls sit beside the actual execution trace and signed receipt.
No marketing hero, decorative stock image or fabricated activity feed is used.

The six-stage rail is a functional status diagram:

```text
Inputs -> Verify -> Minimum context -> Agent -> Policy -> Receipt
```

A failed signature or expired input stops context release and agent execution.
A policy denial preserves valid evidence and agent output but records no
execution. Every completed demonstration creates a signed diagnostic receipt;
a valid receipt signature alone is never presented as workflow approval.

## Grid and spacing

- Maximum content width: 1680 px. Desktop gutters: 40 px; medium: 24 px;
  phone: 16 px. The masthead is 84 px, adapting to its content on phones.
- Above 1199 px, the workbench uses three columns: input, wider trace, receipt.
  Fractional tracks use `minmax` so content can shrink without widening the page.
- At 768–1199 px, inputs and trace use two columns; the receipt becomes a full
  width section. The JSON verifier stays in two flexible columns.
- At 767 px and below, sections use one column in task order. The stage rail
  becomes a 3-by-2 grid. Receipt metadata uses two columns with long values
  spanning the full row. Buttons remain at least 44 px high.
- Spacing scale: 4, 8, 12, 16, 20, 24, 32, 40, 48 px. Panel corners are 8 px;
  chips and contained data rows use 4–5 px. Borders are 1 px.
- Long hashes, identifiers, JSON and commands wrap within their own surfaces.
  Panels and grid children have a zero minimum inline size. JSON editors may
  resize vertically. Page-wide horizontal scrolling is not an intended flow.

## Color tokens

| Token | Value | Use |
| --- | --- | --- |
| `--bg` | `#090d11` | Page and quiet negative space |
| `--panel` | `#10171d` | Main work surfaces |
| `--raised` | `#151e26` | Secondary actions |
| `--line` | `#29343e` | Separators and panel boundaries |
| `--text` | `#edf3f6` | Primary text |
| `--muted` | `#a1b0bc` | Supporting text and metadata |
| `--cyan` | `#98ece7` | Primary action, intact signatures, focus |
| `--gold` | `#ecca8d` | Context scope, policy, withheld data |
| `--rose` | `#f3a9af` | Tampering and invalid evidence |
| `--orange` | `#f2c38e` | Reserved expiry emphasis |

Color never carries a result by itself. Each stage uses text and a symbol:
`✓ Complete`, `× Failed`, `— Not executed`, `○ Ready`.

## Typography

System sans-serif keeps the page self-contained. SF Mono / Consolas / Liberation
Mono distinguishes JSON, hashes, commands and indices. The page title is
approximately 31–42 px, major result text 22–24 px, body 14–16 px, interactive
labels 14 px, and secondary metadata 12 px. Relative units respect browser font
settings. There are no external font downloads.

## Interaction and accessibility

Native form controls provide scenario radio selection, keyboard submission,
editable JSON and file selection. All fields have visible labels. The skip
link goes directly to the workbench. Focus uses a 2 px cyan outline with a 4 px
offset. Status and error regions announce outcomes without moving focus away
from the user. The local verifier invalidates a displayed result when its JSON
changes; a new check is required. Controls are disabled during their operation.
User values are inserted with `textContent`, never HTML. Reduced motion disables
transitions and uses immediate scrolling.

The default run executes locally after loading to provide a real first result.
Editing input does not relabel a previous receipt as a new run. The interface
asks for another run and retains the old receipt until it has a replacement.
Failed input parsing does not discard an earlier valid receipt.

## Proof and status contract

The WebCrypto module generates non-exportable Ed25519 private keys in memory
and exports only their public keys. Separate ephemeral keys sign source and
receipt. SHA-256 binds the complete signed source, including its key and
signature, into the receipt. Verification checks both signatures and recomputes
the source/context/agent/policy relationship. The source validity window is five
minutes; an imported receipt is checked against the current clock.

| Scenario | Source signature | Context / agent | Policy | Final status |
| --- | --- | --- | --- | --- |
| Valid evidence | Valid | Three disclosed fields | Allowed within limit | Workflow allowed |
| Tampered input | Invalid | Not executed | Not evaluated | Tampering detected |
| Expired evidence | Valid, stale | Not executed | Not evaluated | Evidence expired |
| Policy denied | Valid | Runs on minimum context | Denied | Action denied |
| Edited receipt | Receipt invalid | Not trusted | Not trusted | Tampering detected |

`privateContact` is withheld from the agent context. It is still present in the
signed source and therefore in the downloaded bundle: this is field minimization,
not an SD-JWT implementation or a zero-knowledge proof. The deterministic agent
compares a requested amount with a disclosed limit and cites those exact fields.
No LLM or provider is called. An allowed `record.append` is only represented by a
record in browser memory, never an external business effect.

Imported public keys are self-contained and not admitted by any issuer registry.
A signature proves that those keys signed particular bytes, not source truth,
provider identity, model accuracy, independent witness, real payment, or
production authorization. Browser bundles use `nova-browser-proof-demo/1` and
cannot be substituted for NOVA runtime credentials.

## Local preview and validation

```bash
node playground/serve.mjs
# http://127.0.0.1:18935/nova-one/
node --test test/playground-proof.test.mjs
```

`PORT=0` selects a random loopback port. The static server allowlists four public
assets and cannot serve source keys, state, repository files or directories.
GitHub Pages needs only `index.html`, `styles.css`, `app.mjs`, and `proof.mjs`.
The CSP blocks all data connections. Download and file verification use browser
Blob and File APIs; no backend exists in this surface.

The application links to the actual CLI guide and displays the implemented
`nova-one init`, `nova-one demo`, and `nova-one status` commands. The runtime demo
also uses fixtures. Browser responsive and keyboard acceptance is separate from
the crypto unit tests; test 320, 390, 768 and a wide desktop viewport before
publishing.
