import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { assert, fail } from './errors.mjs';
import { timestamp } from './canonical.mjs';

function emptyState() {
  return {
    version: 1,
    meta: { createdAt: timestamp(), updatedAt: timestamp() },
    issuers: [], credentials: [], credentialStatuses: [], challenges: [],
    authorizations: [], sources: [], snapshots: [], contexts: [], claimAudits: [],
    actions: [], receipts: [], notes: [], auditEntries: [], checkpoints: [], witnessReceipts: [],
  };
}

// O_EXCL coordinates every instance/process using this local state file.
// Never steal a stale-looking lock: a paused live writer must not lose ownership.
function tryLock(file) {
  const owner = JSON.stringify({ pid: process.pid, nonce: crypto.randomUUID(), createdAt: timestamp() });
  let fd;
  try { fd = fs.openSync(file, 'wx', 0o600); }
  catch (error) { if (error.code === 'EEXIST') return null; throw error; }
  try { fs.writeFileSync(fd, owner); }
  catch (error) { fs.closeSync(fd); fs.unlinkSync(file); throw error; }
  fs.closeSync(fd);
  return () => {
    try { if (fs.readFileSync(file, 'utf8') === owner) fs.unlinkSync(file); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  };
}

export function withInitializationLock(file, operation) {
  const release = tryLock(file);
  assert(release, 'store_initialization_busy', 'Another process is initializing this NOVA home. Retry after it finishes.', 409);
  try { return operation(); } finally { release(); }
}

export class JsonStore {
  constructor(file, { lockTimeoutMs = 10_000, lockRetryMs = 25 } = {}) {
    assert(Number.isInteger(lockTimeoutMs) && lockTimeoutMs >= 0 && lockTimeoutMs <= 60_000, 'invalid_lock_timeout', 'The local lock timeout must be between 0 and 60000 milliseconds.');
    assert(Number.isInteger(lockRetryMs) && lockRetryMs >= 1 && lockRetryMs <= 1000, 'invalid_lock_retry', 'The lock retry interval must be between 1 and 1000 milliseconds.');
    this.file = path.resolve(file);
    this.lockFile = `${this.file}.lock`;
    this.lockTimeoutMs = lockTimeoutMs;
    this.lockRetryMs = lockRetryMs;
    this.queue = Promise.resolve();
  }

  initialize() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    // Hard-link a complete private temp file into place without overwriting an
    // existing store, including when two first-time callers race.
    if (!fs.existsSync(this.file)) this.#write(emptyState(), true);
    return this.read();
  }

  read() {
    assert(fs.existsSync(this.file), 'store_not_initialized', 'Run `nova-one init` before using the store.', 503);
    const state = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    assert(state?.version === 1 && Array.isArray(state.auditEntries), 'invalid_store', 'The NOVA state file is invalid.', 503);
    return state;
  }

  async #lock() {
    const deadline = Date.now() + this.lockTimeoutMs;
    while (true) {
      const release = tryLock(this.lockFile);
      if (release) return release;
      if (Date.now() >= deadline) fail('store_busy', 'The local state is locked. Retry after the writer exits; after a crash, an operator must verify no writer remains before removing the lock.', 503);
      await new Promise(resolve => setTimeout(resolve, this.lockRetryMs));
    }
  }

  async transaction(operation, { onFailure } = {}) {
    const run = this.queue.catch(() => {}).then(async () => {
      const release = await this.#lock();
      try {
        const state = this.read();
        const before = onFailure ? structuredClone(state) : null;
        let result;
        try { result = await operation(state); }
        catch (error) {
          if (onFailure) {
            // Record only failure evidence on the clean pre-operation state.
            // A failed business mutation must never leak into the commit.
            try {
              const evidence = await onFailure(before, error);
              before.meta.updatedAt = timestamp();
              this.#write(before);
              if (error && typeof error === 'object') error.failureEvidence = evidence;
            } catch (auditError) {
              fail('failure_evidence_unavailable', 'The operation failed and its failure evidence could not be committed. No business result was committed.', 503, { operationCode: typeof error?.code === 'string' ? error.code : 'internal_error', evidenceCode: typeof auditError?.code === 'string' ? auditError.code : 'storage_or_signing_error' });
            }
          }
          throw error;
        }
        state.meta.updatedAt = timestamp();
        this.#write(state);
        return result;
      } finally { release(); }
    });
    this.queue = run;
    return run;
  }

  #write(state, exclusive = false) {
    const temp = `${this.file}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let fd;
    try {
      fd = fs.openSync(temp, 'wx', 0o600);
      fs.writeFileSync(fd, `${JSON.stringify(state, null, 2)}\n`);
      fs.fsyncSync(fd);
      fs.closeSync(fd); fd = undefined;
      if (exclusive) {
        try { fs.linkSync(temp, this.file); }
        catch (error) { if (error.code !== 'EEXIST') throw error; }
      } else fs.renameSync(temp, this.file);
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
      try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
  }
}

export function statePaths(home) {
  const root = path.resolve(home);
  return { root, state: path.join(root, 'state.json'), keys: path.join(root, 'keys.json'), config: path.join(root, 'config.json') };
}
