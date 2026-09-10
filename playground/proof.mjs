// Browser-only proof demonstration. This is not the NOVA Node.js runtime.
export const FORMAT = 'nova-browser-proof-demo/1';
export const PROFILE = 'nova-playground-ed25519-v1';
export const DEFAULT_CLAIMS = Object.freeze({ organization: 'Northstar Research', requestedAmount: 2400, approvedLimit: 5000, privateContact: 'demo@example.invalid' });
export const SCENARIOS = Object.freeze(['verified', 'tampered', 'expired', 'denied']);
const encoder = new TextEncoder();
const MAX_JSON_BYTES = 131072;

export function canonicalize(value, depth = 0) {
  if (depth > 24) throw new Error('JSON nesting exceeds the demonstration limit.');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(item => canonicalize(item, depth + 1)).join(',')}]`;
  if (value && Object.getPrototypeOf(value) === Object.prototype) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key], depth + 1)}`).join(',')}}`;
  throw new Error('Use ordinary JSON objects, strings, booleans and finite numbers.');
}
export function parseBundle(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_JSON_BYTES) throw new Error('Choose a JSON file smaller than 128 KiB.');
  const value = JSON.parse(text);
  canonicalize(value);
  return value;
}
function api() {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto is unavailable. Open this page over HTTPS or localhost.');
  return globalThis.crypto;
}
const hex = bytes => [...new Uint8Array(bytes)].map(n => n.toString(16).padStart(2, '0')).join('');
function fromHex(value, length) {
  if (typeof value !== 'string' || !new RegExp(`^[a-f0-9]{${length * 2}}$`).test(value)) throw new Error('The proof contains an invalid key or signature.');
  return Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16));
}
export async function digest(value) { return hex(await api().subtle.digest('SHA-256', encoder.encode(canonicalize(value)))); }
async function sign(payload) {
  let keys;
  try { keys = await api().subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']); }
  catch { throw new Error('This browser does not support WebCrypto Ed25519. Try a current Chrome, Edge, Firefox or Safari. No weaker fallback is used.'); }
  return { payload, algorithm: 'Ed25519', publicKey: hex(await api().subtle.exportKey('raw', keys.publicKey)), signature: hex(await api().subtle.sign('Ed25519', keys.privateKey, encoder.encode(canonicalize(payload)))) };
}
async function signatureValid(signed) {
  try {
    if (signed?.algorithm !== 'Ed25519') return false;
    const publicKey = await api().subtle.importKey('raw', fromHex(signed.publicKey, 32), 'Ed25519', false, ['verify']);
    return await api().subtle.verify('Ed25519', publicKey, fromHex(signed.signature, 64), encoder.encode(canonicalize(signed.payload)));
  } catch (error) {
    if (error?.name === 'NotSupportedError') throw new Error('This browser does not support WebCrypto Ed25519 verification. No weaker fallback is used.');
    return false;
  }
}
function validateClaims(claims) {
  if (!claims || Array.isArray(claims) || typeof claims !== 'object') throw new Error('The source payload must be a JSON object.');
  if (Object.keys(claims).sort().join(',') !== 'approvedLimit,organization,privateContact,requestedAmount') throw new Error('Keep the four example fields: organization, requestedAmount, approvedLimit and privateContact.');
  if (typeof claims.organization !== 'string' || !claims.organization.trim() || claims.organization.length > 100) throw new Error('Organization must contain 1–100 characters.');
  if (typeof claims.privateContact !== 'string' || claims.privateContact.length > 160) throw new Error('Private contact must be text, up to 160 characters.');
  for (const key of ['requestedAmount', 'approvedLimit']) if (typeof claims[key] !== 'number' || !Number.isFinite(claims[key]) || claims[key] < 0 || claims[key] > 1000000) throw new Error(`${key} must be a number between 0 and 1,000,000.`);
}
function sourceStatus(source, signed, at) {
  if (!signed) return 'tampered';
  const p = source.payload;
  if (p?.profile !== PROFILE || p.kind !== 'untrusted-fixture' || p.audience !== 'nova:playground' || p.purpose !== 'procurement-review') return 'invalid';
  try { validateClaims(p.claims); } catch { return 'invalid'; }
  if (!Number.isFinite(p.issuedAt) || !Number.isFinite(p.expiresAt) || p.expiresAt <= p.issuedAt || p.issuedAt > at) return 'invalid';
  return p.expiresAt <= at ? 'expired' : 'verified';
}
function evaluate(source, status, actionAuthorized) {
  if (status !== 'verified') return { context: null, agent: null, policy: { action: 'record.append', decision: 'not-evaluated', authorized: actionAuthorized, reason: 'Evidence did not pass verification.' }, outcome: status };
  const { organization, requestedAmount, approvedLimit } = source.payload.claims;
  const context = { organization, requestedAmount, approvedLimit };
  const withinLimit = requestedAmount <= approvedLimit;
  const agent = { kind: 'deterministic-fixture', statement: withinLimit ? 'The requested amount is within the disclosed limit.' : 'The requested amount exceeds the disclosed limit.', evidence: ['requestedAmount', 'approvedLimit'], proposedAction: 'record.append' };
  const allowed = actionAuthorized && withinLimit;
  return { context, agent, policy: { action: 'record.append', decision: allowed ? 'allowed' : 'denied', authorized: actionAuthorized, reason: !actionAuthorized ? 'No local action authorization was granted.' : withinLimit ? 'Authorized local record; requested amount is within the limit.' : 'Requested amount exceeds the approved limit.' }, outcome: allowed ? 'verified' : 'denied' };
}
export async function createDemo({ scenario = 'verified', claims = DEFAULT_CLAIMS, now = Date.now() } = {}) {
  if (!SCENARIOS.includes(scenario)) throw new Error('Choose one of the four demonstration scenarios.');
  validateClaims(claims);
  if (!Number.isFinite(now)) throw new Error('The demonstration clock is invalid.');
  const source = await sign({ profile: PROFILE, kind: 'untrusted-fixture', issuer: 'urn:nova:playground:ephemeral-source', audience: 'nova:playground', purpose: 'procurement-review', issuedAt: scenario === 'expired' ? now - 600000 : now, expiresAt: scenario === 'expired' ? now - 300000 : now + 300000, claims: { ...claims } });
  if (scenario === 'tampered') source.payload.claims.requestedAmount += 1;
  const sourceSignature = await signatureValid(source);
  const status = sourceStatus(source, sourceSignature, now);
  const evaluated = evaluate(source, status, scenario !== 'denied');
  const receipt = await sign({ profile: PROFILE, runId: api().randomUUID(), createdAt: now, trustLevel: 'untrusted-fixture', sourceHash: await digest(source), ...evaluated, effect: evaluated.outcome === 'verified' ? 'browser-memory-record-only' : 'no-action' });
  return { format: FORMAT, demonstration: 'Browser proof demonstration. Self-contained ephemeral keys; fictional source and deterministic fixture agent. Not a NOVA runtime credential or provider attestation.', source, receipt };
}
export async function verifyBundle(bundle, { now = Date.now() } = {}) {
  if (bundle?.format !== FORMAT || !bundle.source || !bundle.receipt) throw new Error('This is not a NOVA browser proof demonstration bundle. Runtime credentials use the NOVA CLI instead.');
  if (encoder.encode(canonicalize(bundle)).length > MAX_JSON_BYTES) throw new Error('The bundle exceeds 128 KiB.');
  const [sourceSignature, receiptSignature] = await Promise.all([signatureValid(bundle.source), signatureValid(bundle.receipt)]);
  const p = bundle.receipt.payload;
  if (!p || typeof p !== 'object') throw new Error('The receipt payload is missing.');
  const currentSourceStatus = sourceStatus(bundle.source, sourceSignature, now);
  const executionSourceStatus = sourceStatus(bundle.source, sourceSignature, p.createdAt);
  const expected = evaluate(bundle.source, executionSourceStatus, p.policy?.authorized === true);
  const bindingValid = Number.isFinite(p.createdAt) && p.createdAt <= now && p.profile === PROFILE && p.trustLevel === 'untrusted-fixture'
    && p.sourceHash === await digest(bundle.source)
    && canonicalize(p.context ?? null) === canonicalize(expected.context)
    && canonicalize(p.agent ?? null) === canonicalize(expected.agent)
    && canonicalize(p.policy ?? null) === canonicalize(expected.policy)
    && p.outcome === expected.outcome && p.effect === (expected.outcome === 'verified' ? 'browser-memory-record-only' : 'no-action');
  const status = !receiptSignature || !bindingValid || currentSourceStatus === 'tampered' ? 'tampered' : currentSourceStatus !== 'verified' ? currentSourceStatus : expected.outcome;
  return { status, sourceSignature, receiptSignature, bindingValid, accepted: status === 'verified', sourceStatus: currentSourceStatus, scope: 'Self-contained demonstration keys. Signatures prove these bytes, not source truth, provider identity or external execution.' };
}
export function tamperBundle(bundle) {
  const copy = structuredClone(bundle);
  copy.receipt.payload.sourceHash = '0'.repeat(64);
  return copy;
}
