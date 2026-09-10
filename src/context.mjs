import { canonical, isPlainObject, randomId, sha256, timestamp } from './canonical.mjs';
import { assert } from './errors.mjs';
import { publicJwk, signBytes, verifyBytes } from './crypto.mjs';
import { verifySignedSourceEnvelope, verifySourceRegistration } from './sources.mjs';

const DEFAULT_CONTEXT_MAX_AGE_MS = 5 * 60_000;
const BLOCKED_PATHS = new Set(['__proto__', 'prototype', 'constructor']);

function boundedString(value, code, message, max = 240) {
  assert(typeof value === 'string' && value.length > 0 && value.length <= max, code, message);
  return value;
}

function getClaim(payload, path) {
  const root = isPlainObject(payload?.claims) ? payload.claims : payload;
  const parts = path.split('.');
  if (parts.some(part => !part || BLOCKED_PATHS.has(part))) return { present: false };
  let cursor = root;
  for (const part of parts) {
    if (!isPlainObject(cursor) && !Array.isArray(cursor)) return { present: false };
    if (!Object.prototype.hasOwnProperty.call(cursor, part)) return { present: false };
    cursor = cursor[part];
  }
  return { present: true, value: cursor };
}

function availableClaimNames(snapshot) {
  const root = isPlainObject(snapshot.payload?.claims) ? snapshot.payload.claims : snapshot.payload;
  return isPlainObject(root) ? Object.keys(root).filter(key => !BLOCKED_PATHS.has(key)) : [];
}

function safeSecurityEvent(ledger, event, actor, payload) {
  try { ledger.append(event, actor, payload); } catch (error) {
    if (error.code === 'audit_integrity_failure') throw error;
  }
}

function authorizationPayload(record) {
  return {
    id: record.id, kind: record.kind, subject: record.subject, audience: record.audience,
    purpose: record.purpose, scopes: record.scopes, claims: record.claims,
    approvedBy: record.approvedBy, createdAt: record.createdAt, expiresAt: record.expiresAt,
  };
}

export class EvidenceContextService {
  constructor(state, ledger, {
    now = () => Date.now(),
    maxAgeMs = DEFAULT_CONTEXT_MAX_AGE_MS,
    minIndependentSources = 2,
  } = {}) {
    assert(state && Array.isArray(state.snapshots) && Array.isArray(state.contexts) && Array.isArray(state.claimAudits) && Array.isArray(state.authorizations), 'invalid_state', 'EvidenceContextService requires initialized state.');
    assert(ledger?.append, 'ledger_required', 'EvidenceContextService requires a TrustLedger.');
    assert(Number.isInteger(maxAgeMs) && maxAgeMs >= 1_000 && maxAgeMs <= 24 * 60 * 60_000, 'invalid_context_age', 'Context max age is outside the accepted range.');
    assert(Number.isInteger(minIndependentSources) && minIndependentSources >= 1 && minIndependentSources <= 10, 'invalid_source_threshold', 'Independent source threshold must be between 1 and 10.');
    this.state = state; this.ledger = ledger; this.now = now;
    this.keys = ledger.keys;
    assert(this.keys?.activeKeyId, 'signer_not_configured', 'Evidence authorization requires the ledger signing key.', 503);
    this.maxAgeMs = maxAgeMs; this.minIndependentSources = minIndependentSources;
  }

  /** Records an explicit, bounded local authorization. The audit ledger protects the grant. */
  authorize({ subject, audience, purpose, claims = ['*'], approvedBy, ttlMs = 10 * 60_000 } = {}) {
    boundedString(subject, 'invalid_authorization_subject', 'An authorization subject is required.');
    boundedString(audience, 'invalid_authorization_audience', 'An authorization audience is required.');
    boundedString(purpose, 'invalid_authorization_purpose', 'An authorization purpose is required.', 160);
    boundedString(approvedBy, 'explicit_approval_required', 'An explicit approver identity is required.');
    assert(Array.isArray(claims) && claims.length > 0 && claims.length <= 100 && claims.every(item => typeof item === 'string' && item.length > 0 && item.length <= 160), 'invalid_authorized_claims', 'Authorized claims must be a bounded string list.');
    assert(Number.isInteger(ttlMs) && ttlMs >= 15_000 && ttlMs <= 60 * 60_000, 'invalid_authorization_ttl', 'Authorization TTL must be between 15 seconds and one hour.');
    const now = this.now();
    const record = {
      id: randomId('authz'), kind: 'evidence-context', subject, audience, purpose,
      scopes: ['evidence.read'], claims: [...new Set(claims)].sort(),
      approvedBy, status: 'active', createdAt: timestamp(now), expiresAt: timestamp(now + ttlMs), consumedAt: null,
    };
    record.signature = { alg: 'EdDSA', keyId: this.keys.activeKeyId, value: signBytes(this.keys, canonical(authorizationPayload(record))) };
    const entry = this.ledger.append('authorization.evidence_granted', approvedBy, { authorizationId: record.id, subject, audience, purpose, claimsHash: sha256(record.claims), expiresAt: record.expiresAt });
    record.auditEntryId = entry.id;
    this.state.authorizations.push(record);
    return { ...structuredClone(record), auditReceipt: this.ledger.receipt(entry) };
  }

  revokeAuthorization(id, { actor } = {}) {
    boundedString(actor, 'actor_required', 'An actor is required to revoke authorization.');
    const record = this.state.authorizations.find(item => item.id === id && item.kind === 'evidence-context');
    assert(record, 'authorization_not_found', 'The evidence authorization was not found.', 404);
    record.status = 'revoked'; record.revokedAt = timestamp(this.now());
    const entry = this.ledger.append('authorization.evidence_revoked', actor, { authorizationId: id }, `authorization-evidence-revoked:${id}`);
    record.auditEntryId = entry.id;
    return { ...structuredClone(record), auditReceipt: this.ledger.receipt(entry) };
  }

  build({
    snapshotIds,
    claims,
    authorizationId,
    subject,
    audience,
    purpose,
    actor = subject,
    maxAgeMs = this.maxAgeMs,
    minIndependentSources = this.minIndependentSources,
    allowConflicts = false,
  } = {}) {
    try {
      boundedString(subject, 'context_subject_required', 'A context subject is required.');
      boundedString(audience, 'context_audience_required', 'A context audience is required.');
      boundedString(purpose, 'context_purpose_required', 'A context purpose is required.', 160);
      assert(Array.isArray(snapshotIds) && snapshotIds.length > 0 && snapshotIds.length <= 100, 'snapshots_required', 'At least one bounded snapshot ID is required.');
      assert(new Set(snapshotIds).size === snapshotIds.length, 'duplicate_snapshot', 'A snapshot cannot be supplied twice.');
      assert(Number.isInteger(maxAgeMs) && maxAgeMs >= 1_000 && maxAgeMs <= 24 * 60 * 60_000, 'invalid_context_age', 'Context max age is outside the accepted range.');
      assert(Number.isInteger(minIndependentSources) && minIndependentSources >= 1 && minIndependentSources <= 10, 'invalid_source_threshold', 'Independent source threshold must be between 1 and 10.');
      const authorization = this.#authorization(authorizationId, { subject, audience, purpose });
      const snapshots = snapshotIds.map(id => {
        const snapshot = this.state.snapshots.find(item => item.id === id);
        assert(snapshot, 'snapshot_not_found', `Snapshot ${id} was not found.`, 404);
        return snapshot;
      });
      const now = this.now();
      for (const snapshot of snapshots) {
        const source = this.state.sources.find(item => item.id === snapshot.sourceId);
        assert(source, 'source_registration_missing', 'Snapshot source trust metadata is unavailable.', 403);
        verifySourceRegistration(source, this.keys);
        assert(snapshot.sourceKind === source.kind && snapshot.independenceKey === source.independenceKey, 'snapshot_source_binding_failed', 'Snapshot source metadata was modified.', 403);
        verifySignedSourceEnvelope({
          profile: snapshot.profile, sourceId: snapshot.sourceId, issuedAt: snapshot.issuedAt,
          expiresAt: snapshot.expiresAt, payload: snapshot.payload, payloadHash: snapshot.payloadHash,
          signature: snapshot.signature,
        }, { sourceId: source.id, publicKey: source.publicKey, keyId: source.keyId, now, maxAgeMs });
      }
      const freshness = snapshots.map(snapshot => {
        const issuedAt = Date.parse(snapshot.issuedAt);
        const expiresAt = Date.parse(snapshot.expiresAt);
        const receivedAt = Date.parse(snapshot.receivedAt);
        const ageMs = now - issuedAt;
        const fresh = Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && Number.isFinite(receivedAt) &&
          issuedAt <= now + 30_000 && expiresAt > now - 30_000 && ageMs <= maxAgeMs + 30_000;
        return { snapshotId: snapshot.id, issuedAt: snapshot.issuedAt, expiresAt: snapshot.expiresAt, ageMs, fresh };
      });
      assert(freshness.every(item => item.fresh), 'stale_context_evidence', 'The evidence context contains stale or invalid snapshots.', 403, { staleSnapshotIds: freshness.filter(item => !item.fresh).map(item => item.snapshotId) });
      const claimNames = claims === undefined ? [...new Set(snapshots.flatMap(availableClaimNames))].sort() : claims;
      assert(Array.isArray(claimNames) && claimNames.length > 0 && claimNames.length <= 100 && claimNames.every(item => typeof item === 'string' && item.length > 0 && item.length <= 160), 'invalid_context_claims', 'Context claims must be a bounded string list.');
      assert(authorization.claims.includes('*') || claimNames.every(name => authorization.claims.includes(name)), 'claim_not_authorized', 'The authorization does not cover every requested claim.', 403);

      const contextClaims = claimNames.map(name => {
        const evidence = snapshots.flatMap(snapshot => {
          const selected = getClaim(snapshot.payload, name);
          return selected.present ? [{
            snapshotId: snapshot.id, sourceId: snapshot.sourceId,
            sourceKind: snapshot.sourceKind, independenceKey: snapshot.independenceKey,
            payloadHash: snapshot.payloadHash, issuedAt: snapshot.issuedAt, value: structuredClone(selected.value),
          }] : [];
        });
        assert(evidence.length > 0, 'claim_evidence_missing', `No evidence supports claim ${name}.`, 422);
        const independentSources = [...new Set(evidence.map(item => item.independenceKey))].sort();
        assert(independentSources.length >= minIndependentSources, 'insufficient_independent_sources', `Claim ${name} does not meet the independent-source threshold.`, 422, { claim: name, required: minIndependentSources, actual: independentSources.length });
        const groups = new Map();
        for (const item of evidence) {
          const key = canonical(item.value);
          const group = groups.get(key) || { value: item.value, snapshotIds: [], independenceKeys: [] };
          group.snapshotIds.push(item.snapshotId); group.independenceKeys.push(item.independenceKey); groups.set(key, group);
        }
        const variants = [...groups.values()].map(item => ({ ...item, snapshotIds: item.snapshotIds.sort(), independenceKeys: [...new Set(item.independenceKeys)].sort() }));
        const conflicted = variants.length > 1;
        return {
          name, status: conflicted ? 'conflicted' : 'supported',
          value: conflicted ? null : structuredClone(variants[0].value),
          independentSourceCount: independentSources.length, independentSources,
          evidence, conflicts: conflicted ? variants : [],
        };
      });
      const conflicts = contextClaims.filter(claim => claim.status === 'conflicted').map(claim => ({ claim: claim.name, variants: claim.conflicts }));
      assert(allowConflicts || conflicts.length === 0, 'evidence_conflict', 'Conflicting evidence requires explicit resolution.', 409, { conflicts });
      const context = {
        id: randomId('context'), profile: 'nova-minimal-evidence-context-0.1',
        subject, audience, purpose, authorization: {
          id: authorization.id, approvedBy: authorization.approvedBy,
          scope: 'evidence.read', expiresAt: authorization.expiresAt,
        },
        claims: contextClaims, conflicts,
        sourceSummary: snapshots.map(snapshot => ({ id: snapshot.sourceId, kind: snapshot.sourceKind, independenceKey: snapshot.independenceKey })),
        freshness, createdAt: timestamp(now),
      };
      context.evidenceRoot = sha256({ claims: context.claims, authorization: context.authorization, freshness: context.freshness });
      const entry = this.ledger.append('context.created', actor, { contextId: context.id, evidenceRoot: context.evidenceRoot, authorizationId, claims: claimNames, conflicts: conflicts.map(item => item.claim) });
      context.auditEntryId = entry.id;
      this.state.contexts.push(structuredClone(context));
      for (const claim of context.claims) this.state.claimAudits.push({
        id: randomId('claim-audit'), contextId: context.id, claim: claim.name,
        status: claim.status, evidenceSnapshotIds: claim.evidence.map(item => item.snapshotId),
        evidenceRoot: sha256(claim.evidence), createdAt: context.createdAt,
      });
      return { ...structuredClone(context), auditReceipt: this.ledger.receipt(entry) };
    } catch (error) {
      safeSecurityEvent(this.ledger, 'security.context_rejected', actor || 'unknown', { authorizationId: authorizationId || null, reason: error.code || 'context_build_failed' });
      throw error;
    }
  }

  #authorization(id, expected) {
    const record = this.state.authorizations.find(item => item.id === id && item.kind === 'evidence-context');
    assert(record, 'authorization_not_found', 'A recorded evidence authorization is required.', 403);
    assert(record.signature?.alg === 'EdDSA' && this.keys.keys?.[record.signature.keyId] && verifyBytes(publicJwk(this.keys, record.signature.keyId), canonical(authorizationPayload(record)), record.signature.value), 'authorization_signature_invalid', 'The evidence authorization signature is invalid.', 403);
    assert(!this.state.auditEntries.some(entry => entry.idempotencyKey === `authorization-evidence-revoked:${id}`), 'authorization_inactive', 'The evidence authorization is inactive.', 403);
    assert(record.status === 'active', 'authorization_inactive', 'The evidence authorization is inactive.', 403);
    assert(Date.parse(record.expiresAt) > this.now(), 'authorization_expired', 'The evidence authorization has expired.', 403);
    assert(record.scopes?.includes('evidence.read') && record.subject === expected.subject && record.audience === expected.audience && record.purpose === expected.purpose, 'authorization_scope_mismatch', 'The evidence authorization is not bound to this context.', 403);
    return record;
  }
}

export const CONTEXT_DEFAULTS = Object.freeze({ maxAgeMs: DEFAULT_CONTEXT_MAX_AGE_MS, minIndependentSources: 2 });
