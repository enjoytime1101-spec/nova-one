import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import crypto from 'node:crypto';
import ipaddr from 'ipaddr.js';
import { canonical, isPlainObject, randomId, sha256, timestamp } from './canonical.mjs';
import { assert, fail } from './errors.mjs';
import { createKeyBundle, publicJwk, signBytes, verifyBytes } from './crypto.mjs';

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 1_000_000;
const DEFAULT_MAX_AGE_MS = 5 * 60_000;
const MAX_CLOCK_SKEW_MS = 30_000;

function exactHttpsUrl(value) {
  assert(typeof value === 'string' && value.length <= 2_048, 'invalid_source_url', 'A bounded source URL is required.');
  let url;
  try { url = new URL(value); } catch { fail('invalid_source_url', 'The source URL is invalid.'); }
  assert(url.protocol === 'https:', 'https_required', 'External adapters only accept HTTPS URLs.', 403);
  assert(!url.username && !url.password && !url.hash, 'unsafe_source_url', 'Source URLs cannot contain credentials or fragments.', 403);
  assert(url.hostname && !url.hostname.endsWith('.'), 'unsafe_source_host', 'The source hostname is not accepted.', 403);
  return url;
}

function normalizeIp(address) {
  const normalized = typeof address === 'string' && address.startsWith('[') && address.endsWith(']')
    ? address.slice(1, -1)
    : address;
  if (normalized?.toLowerCase().startsWith('::ffff:')) return normalized.slice(7);
  return normalized;
}

// ipaddr.js classifies ordinary unicast syntax, not the IANA "Globally
// Reachable" property. Keep the security-sensitive exceptions explicit and
// cover them with regression tests. An outbound proxy remains the stronger
// deployment boundary for production.
const NON_GLOBAL_IPV6_CIDRS = [
  '64:ff9b::/96',     // IPv4/IPv6 translation (well-known prefix)
  '64:ff9b:1::/48',  // local-use IPv4/IPv6 translation (RFC 8215)
  '100::/64',        // discard-only
  '100:0:0:1::/64',  // dummy IPv6 prefix
  '2001::/32',       // Teredo
  '2001:2::/48',     // benchmarking
  '2001:db8::/32',   // documentation
  '2002::/16',       // 6to4 transition
  '3fff::/20',       // documentation
  '5f00::/16',       // SRv6 SIDs
  'fec0::/10',       // deprecated site-local
].map(ipaddr.parseCIDR);

/** Reject non-routable, loopback, link-local, documentation and private addresses. */
export function isPublicIp(input) {
  const address = normalizeIp(input);
  if (typeof address !== 'string' || address.includes('%') || !ipaddr.isValid(address)) return false;
  let parsed = ipaddr.parse(address);
  if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) parsed = parsed.toIPv4Address();
  if (parsed.kind() === 'ipv6' && NON_GLOBAL_IPV6_CIDRS.some(cidr => parsed.match(cidr))) return false;
  return parsed.range() === 'unicast';
}

async function resolvePublicAddresses(hostname, lookup = dns.lookup) {
  const literalFamily = net.isIP(hostname);
  const records = literalFamily ? [{ address: hostname, family: literalFamily }] : await lookup(hostname, { all: true, verbatim: true });
  assert(Array.isArray(records) && records.length > 0, 'source_dns_failure', 'The source hostname did not resolve.', 502);
  const unique = [...new Map(records.map(record => [`${normalizeIp(record.address)}/${record.family}`, { address: normalizeIp(record.address), family: record.family }])).values()];
  assert(unique.every(record => isPublicIp(record.address)), 'private_network_target', 'The source resolved to a private or reserved address.', 403);
  return unique;
}

function validateHeaders(headers) {
  assert(isPlainObject(headers), 'invalid_headers', 'HTTP headers must be a plain object.');
  const forbidden = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'upgrade', 'proxy-authorization']);
  for (const [name, value] of Object.entries(headers)) {
    assert(/^[a-z0-9!#$%&'*+.^_`|~-]+$/i.test(name) && !forbidden.has(name.toLowerCase()), 'unsafe_header', `The header ${name} is not allowed.`);
    assert(typeof value === 'string' && value.length <= 8_192 && !/[\r\n]/.test(value), 'unsafe_header', `The header ${name} is invalid.`);
  }
}

/**
 * Strict JSON transport shared by external source and agent adapters.
 * External access is denied unless enabled and the complete normalized URL is allowlisted.
 */
export async function requestStrictJson(value, {
  enabled = false,
  allowlist = [],
  method = 'GET',
  headers = {},
  body,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_BYTES,
  lookup = dns.lookup,
  signal,
} = {}) {
  assert(enabled === true, 'external_access_disabled', 'Real external access is disabled by default.', 403);
  const url = exactHttpsUrl(value);
  assert(Array.isArray(allowlist) && allowlist.length > 0, 'empty_allowlist', 'An exact external URL allowlist is required.', 403);
  const normalizedAllowlist = allowlist.map(item => exactHttpsUrl(item).href);
  assert(normalizedAllowlist.includes(url.href), 'source_not_allowlisted', 'The exact external URL is not allowlisted.', 403);
  assert(['GET', 'POST'].includes(method), 'unsupported_http_method', 'Only GET and POST are supported.');
  assert(Number.isInteger(timeoutMs) && timeoutMs >= 100 && timeoutMs <= 30_000, 'invalid_timeout', 'Timeout must be between 100 and 30000 milliseconds.');
  assert(Number.isInteger(maxBytes) && maxBytes >= 1_024 && maxBytes <= 10_000_000, 'invalid_max_bytes', 'Response limit must be between 1024 and 10000000 bytes.');
  validateHeaders(headers);
  const addresses = await resolvePublicAddresses(url.hostname, lookup);
  let requestBody;
  if (body !== undefined) {
    requestBody = Buffer.from(canonical(body));
    assert(requestBody.length <= maxBytes, 'request_too_large', 'The JSON request body exceeds the configured limit.', 413);
  }
  const approved = new Set(addresses.map(record => normalizeIp(record.address)));
  const requestHeaders = {
    accept: 'application/json',
    'user-agent': 'nova-one/0.2',
    ...headers,
    ...(requestBody ? { 'content-type': 'application/json', 'content-length': String(requestBody.length) } : {}),
  };

  return await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener('abort', abort);
      error ? reject(error) : resolve(result);
    };
    const abort = () => request.destroy(Object.assign(new Error('The request was aborted.'), { code: 'request_aborted' }));
    const request = https.request({
      protocol: 'https:', hostname: url.hostname, port: url.port || 443,
      path: `${url.pathname}${url.search}`, method, headers: requestHeaders,
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
      lookup: (_hostname, _options, callback) => callback(null, addresses[0].address, addresses[0].family),
      timeout: timeoutMs,
      agent: false,
    }, response => {
      const remote = normalizeIp(response.socket.remoteAddress);
      if (!approved.has(remote) || !isPublicIp(remote)) {
        response.destroy();
        finish(Object.assign(new Error('The connected peer is not the approved public address.'), { code: 'dns_rebinding_detected' }));
        return;
      }
      if (response.statusCode >= 300 && response.statusCode < 400) {
        response.resume();
        finish(Object.assign(new Error('Redirects are not followed.'), { code: 'redirect_forbidden', status: response.statusCode }));
        return;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        response.resume();
        finish(Object.assign(new Error(`The endpoint returned HTTP ${response.statusCode}.`), { code: 'upstream_http_error', status: response.statusCode }));
        return;
      }
      const contentType = String(response.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/json' && contentType !== 'application/problem+json') {
        response.resume();
        finish(Object.assign(new Error('The endpoint did not return JSON.'), { code: 'invalid_content_type' }));
        return;
      }
      let size = 0;
      const chunks = [];
      response.on('data', chunk => {
        size += chunk.length;
        if (size > maxBytes) response.destroy(Object.assign(new Error('The JSON response exceeds the configured limit.'), { code: 'response_too_large' }));
        else chunks.push(chunk);
      });
      response.on('error', error => finish(error));
      response.on('end', () => {
        const raw = Buffer.concat(chunks);
        try {
          const parsed = JSON.parse(raw.toString('utf8'));
          finish(null, { status: response.statusCode, headers: response.headers, body: parsed, raw, url: url.href, remoteAddress: remote });
        } catch {
          finish(Object.assign(new Error('The endpoint returned malformed JSON.'), { code: 'invalid_json' }));
        }
      });
    });
    request.on('timeout', () => request.destroy(Object.assign(new Error('The external request timed out.'), { code: 'request_timeout' })));
    request.on('error', error => finish(error));
    if (signal) {
      if (signal.aborted) abort();
      else signal.addEventListener('abort', abort, { once: true });
    }
    if (requestBody) request.write(requestBody);
    request.end();
  });
}

function schemaError(path, message) { return `${path || '$'} ${message}`; }

function jsonCompatibilityErrors(value, path = '$', depth = 0, stack = new WeakSet()) {
  if (depth > 32) return [schemaError(path, 'exceeds the maximum JSON depth')];
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return [];
  if (typeof value === 'number') return Number.isFinite(value) ? [] : [schemaError(path, 'must be a finite JSON number')];
  if (!Array.isArray(value) && !isPlainObject(value)) return [schemaError(path, 'must be JSON-compatible')];
  if (stack.has(value)) return [schemaError(path, 'contains a cycle')];
  stack.add(value);
  const errors = [];
  if (Array.isArray(value)) value.forEach((item, index) => errors.push(...jsonCompatibilityErrors(item, `${path}[${index}]`, depth + 1, stack)));
  else for (const [key, child] of Object.entries(value)) {
    if (['__proto__', 'prototype', 'constructor'].includes(key)) errors.push(schemaError(`${path}.${key}`, 'uses a blocked key'));
    else errors.push(...jsonCompatibilityErrors(child, `${path}.${key}`, depth + 1, stack));
  }
  stack.delete(value);
  return errors;
}

/** A deliberately small, fail-closed JSON Schema subset suitable for adapter boundaries. */
export function validateJsonSchema(value, schema, path = '$') {
  if (schema === true || schema === undefined) return [];
  if (schema === false || !isPlainObject(schema)) return [schemaError(path, 'is rejected by the schema')];
  const errors = [];
  if (schema.const !== undefined && canonical(value) !== canonical(schema.const)) errors.push(schemaError(path, 'does not equal const'));
  if (Array.isArray(schema.enum) && !schema.enum.some(item => canonical(item) === canonical(value))) errors.push(schemaError(path, 'is not an allowed enum value'));
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
  if (types.length && !types.includes(actual) && !(actual === 'integer' && types.includes('number'))) return [...errors, schemaError(path, `must be ${types.join(' or ')}`)];
  if (typeof value === 'string') {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) errors.push(schemaError(path, 'is too short'));
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) errors.push(schemaError(path, 'is too long'));
    if (schema.pattern) {
      try { if (!new RegExp(schema.pattern, 'u').test(value)) errors.push(schemaError(path, 'does not match pattern')); } catch { errors.push(schemaError(path, 'uses an invalid schema pattern')); }
    }
    if (schema.format === 'date-time' && !Number.isFinite(Date.parse(value))) errors.push(schemaError(path, 'is not a date-time'));
    if (schema.format === 'uri') { try { new URL(value); } catch { errors.push(schemaError(path, 'is not a URI')); } }
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (typeof schema.minimum === 'number' && value < schema.minimum) errors.push(schemaError(path, 'is below minimum'));
    if (typeof schema.maximum === 'number' && value > schema.maximum) errors.push(schemaError(path, 'is above maximum'));
  }
  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) errors.push(schemaError(path, 'has too few items'));
    if (Number.isInteger(schema.maxItems) && value.length > schema.maxItems) errors.push(schemaError(path, 'has too many items'));
    value.forEach((item, index) => errors.push(...validateJsonSchema(item, schema.items, `${path}[${index}]`)));
  }
  if (isPlainObject(value)) {
    for (const required of schema.required || []) if (!(required in value)) errors.push(schemaError(`${path}.${required}`, 'is required'));
    for (const [key, child] of Object.entries(value)) {
      if (schema.properties?.[key] !== undefined) errors.push(...validateJsonSchema(child, schema.properties[key], `${path}.${key}`));
      else if (schema.additionalProperties === false) errors.push(schemaError(`${path}.${key}`, 'is not allowed'));
      else if (isPlainObject(schema.additionalProperties)) errors.push(...validateJsonSchema(child, schema.additionalProperties, `${path}.${key}`));
    }
  }
  return errors;
}

export function assertJsonSchema(value, schema, code = 'schema_validation_failed') {
  const errors = [...jsonCompatibilityErrors(value), ...validateJsonSchema(value, schema)];
  assert(errors.length === 0, code, 'JSON schema validation failed.', 422, { errors: errors.slice(0, 20) });
  return value;
}

export function createSignedSourceEnvelope(payload, { sourceId, keyBundle, now = Date.now(), ttlMs = DEFAULT_MAX_AGE_MS } = {}) {
  assert(sourceId && keyBundle?.activeKeyId, 'fixture_signer_required', 'A source ID and isolated signing key are required.');
  assert(Number.isInteger(ttlMs) && ttlMs >= 1_000 && ttlMs <= 24 * 60 * 60_000, 'invalid_fixture_ttl', 'Fixture TTL is outside the accepted range.');
  const unsigned = {
    profile: 'nova-signed-source-0.1', sourceId,
    issuedAt: timestamp(now), expiresAt: timestamp(now + ttlMs),
    payload, payloadHash: sha256(payload),
  };
  return { ...unsigned, signature: { alg: 'EdDSA', keyId: keyBundle.activeKeyId, value: signBytes(keyBundle, canonical(unsigned)) } };
}

export function verifySignedSourceEnvelope(envelope, {
  sourceId,
  publicKey,
  keyId,
  schema = true,
  now = Date.now(),
  maxAgeMs = DEFAULT_MAX_AGE_MS,
  clockSkewMs = MAX_CLOCK_SKEW_MS,
} = {}) {
  assert(isPlainObject(envelope) && envelope.profile === 'nova-signed-source-0.1', 'invalid_source_envelope', 'The signed source envelope profile is invalid.', 422);
  assert(Object.keys(envelope).sort().join(',') === 'expiresAt,issuedAt,payload,payloadHash,profile,signature,sourceId', 'invalid_source_envelope', 'The signed source envelope contains unsupported fields.', 422);
  const { signature, ...unsigned } = envelope;
  assert(isPlainObject(signature) && Object.keys(signature).sort().join(',') === 'alg,keyId,value', 'invalid_source_binding', 'The source signature metadata is invalid.', 403);
  assert(unsigned.sourceId === sourceId && signature.alg === 'EdDSA' && typeof signature.keyId === 'string' && typeof signature.value === 'string', 'invalid_source_binding', 'The signed source is not correctly bound.', 403);
  let key;
  try { key = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : crypto.createPublicKey({ key: publicKey, format: 'jwk' }); } catch { fail('invalid_source_public_key', 'The source public key is invalid.', 403); }
  assert(key.asymmetricKeyType === 'ed25519', 'invalid_source_public_key', 'Only Ed25519 source keys are accepted.', 403);
  const expectedKeyId = keyId || publicKey?.kid;
  assert(typeof expectedKeyId === 'string' && expectedKeyId.length > 0 && expectedKeyId === signature.keyId, 'source_key_id_mismatch', 'The source signature key ID does not match.', 403);
  assert(unsigned.payloadHash === sha256(unsigned.payload), 'source_payload_hash_mismatch', 'The source payload hash does not match.', 403);
  assert(verifyBytes(publicKey, canonical(unsigned), signature.value), 'invalid_source_signature', 'The source signature is invalid.', 403);
  const issuedAt = Date.parse(unsigned.issuedAt);
  const expiresAt = Date.parse(unsigned.expiresAt);
  assert(Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && expiresAt > issuedAt, 'invalid_source_time', 'The source time bounds are invalid.', 403);
  assert(issuedAt <= now + clockSkewMs, 'source_not_yet_valid', 'The source statement is not yet valid.', 403);
  assert(expiresAt > now - clockSkewMs, 'source_expired', 'The source statement has expired.', 403);
  assert(now - issuedAt <= maxAgeMs + clockSkewMs, 'source_stale', 'The source statement is too old.', 403);
  assertJsonSchema(unsigned.payload, schema, 'source_schema_failed');
  return { verified: true, envelope };
}

export function verifySourceRegistration(source, trustKeyBundle) {
  assert(isPlainObject(source) && isPlainObject(source.trustSignature), 'invalid_source_registration', 'Source trust metadata is missing.', 403);
  const { trustSignature, ...unsigned } = source;
  assert(trustSignature.alg === 'EdDSA' && trustKeyBundle?.keys?.[trustSignature.keyId], 'invalid_source_registration', 'Source trust metadata uses an unexpected key.', 403);
  assert(verifyBytes(publicJwk(trustKeyBundle, trustSignature.keyId), canonical(unsigned), trustSignature.value), 'invalid_source_registration_signature', 'Source trust metadata signature is invalid.', 403);
  return { verified: true, sourceId: source.id, publicKeyHash: sha256(source.publicKey) };
}

export class FixtureSourceAdapter {
  constructor({ id, payload, producer, schema = true, keyBundle, now = () => Date.now(), ttlMs = DEFAULT_MAX_AGE_MS } = {}) {
    assert(typeof id === 'string' && id.length > 0 && id.length <= 160, 'invalid_source_id', 'A bounded fixture source ID is required.');
    assert(payload !== undefined || typeof producer === 'function', 'fixture_payload_required', 'A fixture payload or producer is required.');
    this.id = id;
    this.kind = 'fixture';
    this.payload = payload;
    this.producer = producer;
    this.schema = schema;
    this.keys = keyBundle || createKeyBundle({ issuer: `urn:nova:fixture:${id}`, keyId: 'fixture-ed25519-v1' });
    this.now = now;
    this.ttlMs = ttlMs;
  }

  publicKey() { return publicJwk(this.keys); }

  async fetch(input = {}) {
    const payload = this.producer ? await this.producer(Object.freeze({ ...input })) : structuredClone(this.payload);
    assertJsonSchema(payload, this.schema, 'fixture_schema_failed');
    assert(Buffer.byteLength(canonical(payload)) <= DEFAULT_MAX_BYTES, 'fixture_too_large', 'The fixture payload exceeds 1000000 bytes.', 413);
    return createSignedSourceEnvelope(payload, { sourceId: this.id, keyBundle: this.keys, now: this.now(), ttlMs: this.ttlMs });
  }
}

export class HttpsJsonSourceAdapter {
  constructor({ id, url, publicKey, keyId = publicKey?.kid, schema = true, enabled = false, allowlist = [], timeoutMs, maxBytes, maxAgeMs, lookup, now = () => Date.now() } = {}) {
    assert(typeof id === 'string' && id.length > 0 && id.length <= 160, 'invalid_source_id', 'A bounded external source ID is required.');
    assert(publicKey, 'source_public_key_required', 'External sources require an Ed25519 public key.');
    assert(typeof keyId === 'string' && keyId.length > 0 && keyId.length <= 200, 'source_key_id_required', 'External sources require an expected signing key ID.');
    this.id = id; this.kind = 'external'; this.url = exactHttpsUrl(url).href; this.publicKey = publicKey; this.keyId = keyId; this.schema = schema;
    this.enabled = enabled; this.allowlist = [...allowlist]; this.timeoutMs = timeoutMs; this.maxBytes = maxBytes;
    this.maxAgeMs = maxAgeMs || DEFAULT_MAX_AGE_MS; this.lookup = lookup; this.now = now;
  }

  async fetch() {
    const response = await requestStrictJson(this.url, {
      enabled: this.enabled, allowlist: this.allowlist, timeoutMs: this.timeoutMs,
      maxBytes: this.maxBytes, lookup: this.lookup,
    });
    verifySignedSourceEnvelope(response.body, { sourceId: this.id, publicKey: this.publicKey, keyId: this.keyId, schema: this.schema, now: this.now(), maxAgeMs: this.maxAgeMs });
    return response.body;
  }
}

export class SourceService {
  constructor(state, ledger, { now = () => Date.now() } = {}) {
    assert(state && Array.isArray(state.sources) && Array.isArray(state.snapshots), 'invalid_state', 'SourceService requires initialized state.');
    assert(ledger?.append, 'ledger_required', 'SourceService requires a TrustLedger.');
    assert(ledger.keys?.activeKeyId, 'signer_not_configured', 'Source trust metadata requires the ledger signing key.', 503);
    this.state = state; this.ledger = ledger; this.keys = ledger.keys; this.now = now; this.adapters = new Map();
  }

  register(adapter, { label = adapter.id, independenceKey = adapter.id } = {}) {
    assert(adapter?.id && ['fixture', 'external'].includes(adapter.kind) && typeof adapter.fetch === 'function', 'invalid_source_adapter', 'The source adapter contract is invalid.');
    assert(typeof independenceKey === 'string' && independenceKey.length > 0 && independenceKey.length <= 160, 'invalid_independence_key', 'A bounded source independence key is required.');
    const existing = this.state.sources.find(item => item.id === adapter.id);
    const metadataUnsigned = {
      id: adapter.id, label, kind: adapter.kind, independenceKey,
      endpoint: adapter.kind === 'external' ? adapter.url : null,
      publicKey: adapter.kind === 'fixture' ? adapter.publicKey() : adapter.publicKey,
      keyId: adapter.kind === 'fixture' ? adapter.publicKey().kid : adapter.keyId,
      registeredAt: existing?.registeredAt || timestamp(this.now()),
    };
    let metadata;
    if (existing) {
      verifySourceRegistration(existing, this.keys);
      const { trustSignature: _signature, ...existingUnsigned } = existing;
      assert(canonical(existingUnsigned) === canonical(metadataUnsigned), 'source_identity_conflict', 'A source ID cannot be rebound to different trust metadata.', 409);
      metadata = existing;
    } else {
      metadata = { ...metadataUnsigned, trustSignature: { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(metadataUnsigned)) } };
    }
    this.ledger.append('source.registered', 'system', { sourceId: adapter.id, kind: adapter.kind, independenceKey, endpointHash: metadata.endpoint ? sha256(metadata.endpoint) : null, publicKeyHash: sha256(metadata.publicKey), trustSignatureHash: sha256(metadata.trustSignature) }, `source-register:${adapter.id}`);
    if (!existing) this.state.sources.push(metadata);
    this.adapters.set(adapter.id, adapter);
    return structuredClone(metadata);
  }

  registerFixture(options, metadata) { return this.register(new FixtureSourceAdapter(options), metadata); }
  registerExternal(options, metadata) { return this.register(new HttpsJsonSourceAdapter(options), metadata); }

  async collect(sourceId, { actor = 'system', input } = {}) {
    const adapter = this.adapters.get(sourceId);
    assert(adapter, 'source_adapter_unavailable', 'The source adapter is not registered in this process.', 404);
    try {
      const envelope = await adapter.fetch(input);
      const source = this.state.sources.find(item => item.id === sourceId);
      verifySourceRegistration(source, this.keys);
      verifySignedSourceEnvelope(envelope, { sourceId, publicKey: source.publicKey, keyId: source.keyId, schema: adapter.schema, now: this.now(), maxAgeMs: adapter.maxAgeMs || DEFAULT_MAX_AGE_MS });
      const snapshot = {
        id: randomId('snapshot'), sourceId, sourceKind: source.kind, independenceKey: source.independenceKey,
        payload: structuredClone(envelope.payload), payloadHash: envelope.payloadHash,
        issuedAt: envelope.issuedAt, expiresAt: envelope.expiresAt, receivedAt: timestamp(this.now()),
        signature: structuredClone(envelope.signature), profile: envelope.profile,
      };
      const entry = this.ledger.append('source.snapshot_accepted', actor, { snapshotId: snapshot.id, sourceId, sourceKind: source.kind, payloadHash: snapshot.payloadHash });
      snapshot.auditEntryId = entry.id;
      this.state.snapshots.push(snapshot);
      return { ...structuredClone(snapshot), auditReceipt: this.ledger.receipt(entry) };
    } catch (error) {
      this.ledger.append('security.source_rejected', actor, { sourceId, sourceKind: adapter.kind, reason: error.code || 'source_collection_failed' });
      throw error;
    }
  }
}

export const SOURCE_DEFAULTS = Object.freeze({ timeoutMs: DEFAULT_TIMEOUT_MS, maxBytes: DEFAULT_MAX_BYTES, maxAgeMs: DEFAULT_MAX_AGE_MS, clockSkewMs: MAX_CLOCK_SKEW_MS });
