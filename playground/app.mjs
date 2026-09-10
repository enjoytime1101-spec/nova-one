import { DEFAULT_CLAIMS, createDemo, verifyBundle, parseBundle, tamperBundle } from './proof.mjs';

const $ = id => document.getElementById(id);
const notes = {
  verified: 'Both signatures pass. The local action is allowed only when the requested amount is within the limit.',
  tampered: 'A source value changes after it is signed. Verification fails before any context or agent output is produced.',
  expired: 'The signature is authentic, but the signed validity window has ended. The workflow stops at verification.',
  denied: 'Evidence passes and the agent proposes a record. The policy refuses it because no action authorization was granted.',
};
const titles = { verified: 'Workflow allowed', tampered: 'Tampering detected', expired: 'Evidence expired', denied: 'Action denied', invalid: 'Evidence rejected' };
const copy = {
  verified: 'The evidence and receipt signatures pass; their binding and the recorded local policy are consistent.',
  tampered: 'A signature or signed binding failed. Do not treat this bundle as an accepted proof.',
  expired: 'The source validity window has ended. A valid signature does not make expired evidence usable.',
  denied: 'The signatures and recorded decision are intact. The local action was denied, not executed.',
  invalid: 'The evidence does not meet this demonstration profile. No action is accepted.',
};
let currentBundle = null;
let runVersion = 0;
let verificationVersion = 0;
const date = value => new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(value));
const money = value => new Intl.NumberFormat('en', { maximumFractionDigits: 2 }).format(value);
const selectedScenario = () => document.querySelector('input[name="scenario"]:checked').value;
function setText(id, value) { $(id).textContent = value; }
function setStage(name, state) {
  const row = document.querySelector(`[data-stage="${name}"]`);
  row.dataset.state = state;
  const indicator = row.querySelector('.stage-state');
  indicator.textContent = { passed: '✓', failed: '×', blocked: '—', ready: '○' }[state];
  indicator.setAttribute('aria-label', { passed: 'Complete', failed: 'Failed', blocked: 'Not executed', ready: 'Ready' }[state]);
}
function renderRun(bundle, verification) {
  const { receipt, source } = bundle;
  const record = receipt.payload;
  const acceptedSource = verification.sourceStatus === 'verified';
  setText('workflow-result', titles[verification.status] || 'Evidence rejected');
  setText('outcome-badge', verification.status.toUpperCase());
  $('outcome-badge').dataset.state = verification.status;
  setStage('inputs', 'passed'); setStage('verify', acceptedSource ? 'passed' : 'failed');
  setStage('context', record.context ? 'passed' : 'blocked'); setStage('agent', record.agent ? 'passed' : 'blocked');
  setStage('policy', record.policy.decision === 'allowed' ? 'passed' : record.policy.decision === 'denied' ? 'failed' : 'blocked'); setStage('receipt', verification.receiptSignature ? 'passed' : 'failed');
  setText('source-state', verification.sourceStatus.toUpperCase());
  setText('source-signature', verification.sourceSignature ? 'Ed25519 · Valid' : 'Ed25519 · Failed');
  setText('source-expiry', verification.sourceStatus === 'expired' ? 'Expired before this run' : `Until ${new Date(source.payload.expiresAt).toLocaleTimeString('en')}`);
  setText('source-message', acceptedSource ? 'The signed bytes, audience, purpose and time window pass this demonstration profile.' : verification.sourceStatus === 'tampered' ? 'The source no longer matches its signature. Context construction and the agent are blocked.' : 'The signed evidence is outside its permitted window. Later workflow stages are blocked.');
  const fields = $('context-fields'); fields.replaceChildren();
  for (const [key, value] of Object.entries(record.context || {})) {
    const row = document.createElement('div'); row.className = 'context-field';
    const label = document.createElement('span'); label.textContent = key;
    const content = document.createElement('b'); content.textContent = typeof value === 'number' ? money(value) : value;
    row.append(label, content); fields.append(row);
  }
  if (!record.context) { const empty = document.createElement('span'); empty.className = 'muted'; empty.textContent = 'No context released: evidence verification did not pass.'; fields.append(empty); }
  setText('context-count', record.context ? '3 DISCLOSED / 1 WITHHELD' : 'BLOCKED');
  setText('agent-output', record.agent?.statement || 'No agent output was produced. Unaccepted evidence stays outside the agent context.');
  setText('agent-evidence', record.agent ? 'Bound to: requestedAmount + approvedLimit · Deterministic fixture' : 'The fixture agent was not invoked.');
  setText('policy-state', record.policy.decision.toUpperCase()); setText('policy-reason', record.policy.reason);
  setText('action-effect', record.effect === 'browser-memory-record-only' ? 'Recorded in browser memory' : 'No action executed');
  setText('receipt-symbol', verification.receiptSignature ? '✓' : '×');
  setText('receipt-state', verification.receiptSignature ? 'Receipt signature valid' : 'Receipt signature failed');
  setText('receipt-caption', record.outcome === 'verified' ? 'The signed record binds this source, context, output and local decision.' : 'A signed diagnostic record of the refused workflow. This is not an approval.');
  setText('receipt-id', record.runId); setText('receipt-time', date(record.createdAt)); setText('receipt-hash', record.sourceHash); setText('receipt-key', receipt.publicKey);
  for (const id of ['download-button', 'inspect-button', 'tamper-button']) $(id).disabled = false;
}
async function run(event) {
  event?.preventDefault();
  const version = ++runVersion;
  $('run-error').hidden = true;
  const controls = [...$('run-form').querySelectorAll('button,input,textarea')]; controls.forEach(control => { control.disabled = true; });
  $('run-form').setAttribute('aria-busy', 'true'); setText('run-status', 'Generating ephemeral keys, signing and checking locally…');
  try {
    const claims = parseBundle($('source-input').value);
    const bundle = await createDemo({ scenario: selectedScenario(), claims });
    const result = await verifyBundle(bundle);
    if (version !== runVersion) return;
    currentBundle = bundle; renderRun(bundle, result);
    setText('run-status', `Run completed · ${new Date().toLocaleTimeString('en')} · No data left this page.`);
  } catch (error) {
    if (version !== runVersion) return;
    setText('run-error', error instanceof Error ? error.message : 'The browser demonstration could not complete.'); $('run-error').hidden = false;
    setText('run-status', currentBundle ? 'The previous receipt is unchanged. Correct the input and run again.' : 'No workflow was accepted.');
  } finally {
    if (version === runVersion) { controls.forEach(control => { control.disabled = false; }); $('run-form').removeAttribute('aria-busy'); }
  }
}
function displayVerification(result) {
  $('verification-result').dataset.state = result.status;
  setText('verify-result-title', result.status === 'verified' ? 'Proof checks passed' : titles[result.status] || 'Bundle rejected');
  setText('verify-result-copy', `${copy[result.status] || copy.invalid} Keys are self-contained demonstration keys, not a trusted provider identity.`);
  const list = $('verification-checks'); list.replaceChildren();
  for (const [label, pass, success] of [['Source signature', result.sourceSignature, 'Valid'], ['Receipt signature', result.receiptSignature, 'Valid'], ['Source + decision binding', result.bindingValid, 'Consistent'], ['Current evidence window', result.sourceStatus === 'verified', 'Current'], ['Local action allowed', result.accepted, 'Allowed']]) {
    const row = document.createElement('li'); const name = document.createElement('span'); name.textContent = label;
    const value = document.createElement('b'); value.textContent = pass ? success : label === 'Current evidence window' ? result.sourceStatus : 'Not passed'; value.dataset.pass = String(pass);
    row.append(name, value); list.append(row);
  }
}
function clearVerification(message = 'Verify the edited JSON to check its signatures and current validity.') {
  verificationVersion++;
  $('verification-result').removeAttribute('data-state'); setText('verify-result-title', 'Ready to verify'); setText('verify-result-copy', message); $('verification-checks').replaceChildren();
}
async function verify() {
  const version = ++verificationVersion; $('verify-button').disabled = true;
  setText('verify-result-title', 'Checking proof…'); $('verification-result').removeAttribute('data-state'); $('verification-checks').replaceChildren();
  try {
    const result = await verifyBundle(parseBundle($('receipt-json').value));
    if (version === verificationVersion) displayVerification(result);
  } catch (error) {
    if (version !== verificationVersion) return;
    $('verification-result').dataset.state = 'invalid'; setText('verify-result-title', 'Bundle could not be verified');
    setText('verify-result-copy', error instanceof Error ? error.message : 'The JSON bundle is not supported.');
  } finally { $('verify-button').disabled = false; }
}
function inspect(tampered = false) {
  if (!currentBundle) return;
  $('receipt-json').value = JSON.stringify(tampered ? tamperBundle(currentBundle) : currentBundle, null, 2);
  setText('file-name', tampered ? 'Tampered copy · Original receipt preserved' : 'Current run');
  clearVerification(); $('receipt-json').focus(); $('verifier-title').scrollIntoView({ block: 'start', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  void verify();
}
$('source-input').value = JSON.stringify(DEFAULT_CLAIMS, null, 2);
$('run-form').addEventListener('submit', run);
$('run-form').addEventListener('input', event => {
  if (event.target.name === 'scenario') setText('scenario-note', notes[selectedScenario()]);
  setText('run-status', 'Inputs changed. Run again to replace the current receipt.');
});
$('reset-input').addEventListener('click', () => { $('source-input').value = JSON.stringify(DEFAULT_CLAIMS, null, 2); setText('run-status', 'Example restored. Run again to create a fresh receipt.'); });
$('inspect-button').addEventListener('click', () => inspect());
$('tamper-button').addEventListener('click', () => inspect(true));
$('verify-button').addEventListener('click', () => void verify());
$('receipt-json').addEventListener('input', () => clearVerification());
$('receipt-file').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  clearVerification('Reading a local file. Nothing is uploaded.');
  const readVersion = verificationVersion;
  try {
    if (file.size > 131072) throw new Error('Choose a JSON file smaller than 128 KiB.');
    const value = await file.text(); if (readVersion !== verificationVersion) return;
    parseBundle(value); $('receipt-json').value = value; setText('file-name', file.name); clearVerification(); await verify();
  } catch (error) {
    if (readVersion !== verificationVersion) return;
    $('verification-result').dataset.state = 'invalid'; setText('verify-result-title', 'File could not be read'); setText('verify-result-copy', error instanceof Error ? error.message : 'Choose a valid JSON bundle.');
  } finally { event.target.value = ''; }
});
$('download-button').addEventListener('click', () => {
  if (!currentBundle) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentBundle, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = `nova-browser-proof-${currentBundle.receipt.payload.runId}.json`; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('copy-command').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('cli-command').textContent); setText('copy-command', 'Copied'); }
  catch { setText('copy-command', 'Select text to copy'); }
});
void run();
