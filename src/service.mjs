import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { getToolContract } from '../agent-tools/tool-contracts.mjs';
import { sha256, timestamp } from './canonical.mjs';
import { CredentialService } from './credentials.mjs';
import { createKeyBundle, loadKeyBundle, writeKeyBundle } from './crypto.mjs';
import { assert, fail } from './errors.mjs';
import { TrustLedger } from './ledger.mjs';
import { PrivacyService } from './privacy.mjs';
import { combineKeyBundle, splitKeyBundle } from './shamir.mjs';
import { JsonStore, statePaths, withInitializationLock } from './store.mjs';
import { assertJsonSchema } from './sources.mjs';

const DEFAULT_ISSUER = 'https://nova-one.local';
const CONFIG_VERSION = 1;
const PUBLIC_CREDENTIAL_TYPES = new Set(['IdentityCredential', 'DataSourceCredential', 'PolicyDecisionCredential']);

function writeJsonAtomic(file, value) {
  const temporary = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, file);
  fs.chmodSync(file, 0o600);
}

function writeJsonExclusive(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}

function readJson(file, code, message, status = 503) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    fail(code, message, status);
  }
}

function validateIssuer(issuer) {
  assert(typeof issuer === 'string' && issuer.length > 0 && issuer.length <= 512, 'invalid_issuer', 'Issuer must be a bounded HTTPS URL.');
  try {
    const url = new URL(issuer);
    assert(url.protocol === 'https:' && url.hostname && !url.username && !url.password && !url.hash, 'invalid_issuer', 'Issuer must be a credential-free HTTPS URL.');
  } catch (error) {
    if (error?.code === 'invalid_issuer') throw error;
    fail('invalid_issuer', 'Issuer must be a valid HTTPS URL.');
  }
  return issuer;
}

function validateApiToken(token) {
  assert(typeof token === 'string' && token.length >= 43 && token.length <= 256 && /^[A-Za-z0-9_-]+$/.test(token), 'invalid_api_token', 'API bearer tokens must contain 43 to 256 base64url characters.');
  assert(new Set(token).size >= 16 && !/^(.{1,32})\1+$/.test(token), 'weak_api_token', 'The supplied API bearer token does not meet the minimum diversity policy. Generate a random 256-bit token instead.');
  return token;
}

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function buildContext(state, keys) {
  const ledger = new TrustLedger(state, keys);
  const credentials = new CredentialService(state, keys, ledger);
  const privacy = new PrivacyService(state, credentials, ledger);
  return { state, keys, ledger, credentials, privacy };
}

function workflowOptions(service, context) {
  const capabilities = { ...service.capabilities };
  return {
    state: context.state,
    keys: context.keys,
    keyBundle: context.keys,
    ledger: context.ledger,
    credentials: context.credentials,
    privacy: context.privacy,
    capabilities,
    allowNetwork: capabilities.network,
    allowModel: capabilities.model,
    allowExecutor: capabilities.executor,
    externalSources: capabilities.network ? service.adapters.network : undefined,
    externalAgents: capabilities.model ? service.adapters.model : undefined,
    externalActions: capabilities.executor ? service.adapters.executor : undefined,
  };
}

async function createWorkflow(factory, service, context) {
  const options = workflowOptions(service, context);
  // Support the documented positional contract and the object-form factory used
  // by early NOVA cores. The function arity lets us do this without executing a
  // factory twice and risking duplicate side effects.
  if (factory.length <= 1) return factory(options);
  if (factory.length <= 3) return factory(context.state, context.keys, options);
  return factory(context.state, context.keys, context.ledger, context.credentials, context.privacy, options);
}

function prepareWorkflow(engine, spec, capabilities, { allowFixtures = true } = {}) {
  const input = { ...spec };
  if (input.agentAdapter?.kind === 'external') {
    assert(capabilities.model, 'external_models_disabled', 'External model adapters are disabled for this NOVA service.', 403);
  }
  if (input.action?.type === 'webhook.dispatch') {
    assert(capabilities.executor, 'external_actions_disabled', 'External action executors are disabled for this NOVA service.', 403);
  }

  if (input.fixtures !== undefined) {
    assert(Array.isArray(input.fixtures) && input.fixtures.length > 0 && input.fixtures.length <= 32, 'invalid_workflow_fixtures', 'Workflow fixtures must be a non-empty list of at most 32 items.');
    assert(engine.sources?.registerFixture, 'workflow_fixture_unsupported', 'This workflow engine cannot register fixture sources.', 503);
    for (const fixture of input.fixtures) {
      assert(fixture && typeof fixture === 'object' && !Array.isArray(fixture), 'invalid_workflow_fixture', 'Each workflow fixture must be an object.');
      engine.sources.registerFixture({
        id: fixture.id,
        payload: fixture.payload,
        schema: fixture.schema ?? true,
      }, {
        label: fixture.label || fixture.id,
        independenceKey: fixture.independenceKey || fixture.id,
      });
    }
    if (input.sourceIds === undefined) input.sourceIds = input.fixtures.map(fixture => fixture.id);
    delete input.fixtures;
  }

  if (input.authorization !== undefined) {
    assert(!input.authorizationId, 'ambiguous_workflow_authorization', 'Specify authorization or authorizationId, not both.');
    assert(input.authorization && typeof input.authorization === 'object' && !Array.isArray(input.authorization), 'invalid_workflow_authorization', 'Workflow authorization must be an object.');
    if (input.authorization.id) {
      input.authorizationId = input.authorization.id;
    } else {
      assert(engine.contexts?.authorize, 'workflow_authorization_unsupported', 'This workflow engine cannot record evidence authorization.', 503);
      const resolvedSubject = input.subject || input.actor || 'urn:nova:local-user';
      const resolvedAudience = input.audience || 'nova:workflow';
      const requestedClaims = input.authorization.claims
        || (Array.isArray(input.claims) ? input.claims : input.claims && typeof input.claims === 'object' ? Object.keys(input.claims) : ['*']);
      const authorization = engine.contexts.authorize({
        subject: resolvedSubject,
        audience: resolvedAudience,
        purpose: input.purpose,
        claims: requestedClaims,
        approvedBy: input.authorization.approvedBy,
        ttlMs: input.authorization.ttlMs,
      });
      input.authorizationId = authorization.id;
      input.subject = resolvedSubject;
      input.audience = resolvedAudience;
    }
    delete input.authorization;
  }
  if (!allowFixtures) {
    assert(Array.isArray(input.sourceIds) && input.sourceIds.length > 0, 'production_sources_required', 'Production workflows require registered external source IDs.', 403);
    const registeredSources = new Map((engine.state?.sources || []).map(source => [source.id, source]));
    assert(input.sourceIds.every(id => registeredSources.get(id)?.kind === 'external'), 'fixture_source_forbidden', 'Production workflows accept only registered external source adapters.', 403);
    const selectedAgent = input.agentAdapter || engine.defaultAgentAdapter;
    assert(selectedAgent?.kind === 'external', 'fixture_agent_forbidden', 'Production workflows require a configured external agent adapter.', 403);
  }
  return input;
}

export function resolveNovaHome(explicitHome = process.env.NOVA_HOME) {
  const selected = explicitHome || path.join(os.homedir(), '.nova-one');
  assert(typeof selected === 'string' && selected.trim() && selected.length <= 4096, 'invalid_nova_home', 'NOVA_HOME must be a bounded filesystem path.');
  return path.resolve(selected);
}

export class NovaService {
  constructor({
    home,
    allowNetwork = false,
    allowModel = false,
    allowExecutor = false,
    network,
    model,
    executor,
  } = {}) {
    this.home = resolveNovaHome(home);
    this.paths = statePaths(this.home);
    this.store = new JsonStore(this.paths.state);
    this.capabilities = Object.freeze({
      network: allowNetwork === true,
      model: allowModel === true,
      executor: allowExecutor === true,
    });
    this.adapters = Object.freeze({ network, model, executor });
  }

  isInitialized() {
    return fs.existsSync(this.paths.state) && fs.existsSync(this.paths.keys) && fs.existsSync(this.paths.config);
  }

  initialize({ issuer = DEFAULT_ISSUER, apiToken } = {}) {
    issuer = validateIssuer(issuer);
    if (apiToken !== undefined) validateApiToken(apiToken);

    fs.mkdirSync(this.paths.root, { recursive: true, mode: 0o700 });
    fs.chmodSync(this.paths.root, 0o700);
    return withInitializationLock(`${this.paths.state}.init.lock`, () => {
      const createdState = !fs.existsSync(this.paths.state);
      this.store.initialize();

      const createdKeys = !fs.existsSync(this.paths.keys);
      if (createdKeys) writeKeyBundle(this.paths.keys, createKeyBundle({ issuer }));
      const keys = loadKeyBundle(this.paths.keys);

      const createdConfig = !fs.existsSync(this.paths.config);
      let revealedApiToken;
      if (createdConfig) {
        revealedApiToken = apiToken || crypto.randomBytes(32).toString('base64url');
        validateApiToken(revealedApiToken);
        writeJsonAtomic(this.paths.config, {
          version: CONFIG_VERSION,
          issuer: keys.issuer,
          apiTokenSha256: sha256(revealedApiToken),
          createdAt: timestamp(),
          security: { network: false, model: false, executor: false },
        });
      } else if (apiToken !== undefined) {
        assert(this.authenticate(apiToken), 'api_token_conflict', 'The supplied API token does not match the initialized NOVA_HOME.', 409);
      }

      const config = this.#config();
      assert(config.issuer === keys.issuer, 'issuer_configuration_mismatch', 'The configured issuer does not match the signing key bundle.', 503);
      return {
        initialized: true,
        created: createdState || createdKeys || createdConfig,
        home: this.home,
        issuer: config.issuer,
        ...(revealedApiToken ? { apiToken: revealedApiToken } : {}),
        apiTokenRevealed: Boolean(revealedApiToken),
        capabilities: { ...this.capabilities },
      };
    });
  }

  status() {
    this.#ready();
    const state = this.store.read();
    const keys = loadKeyBundle(this.paths.keys);
    const ledger = new TrustLedger(state, keys);
    const verification = ledger.verify();
    return {
      initialized: true,
      home: this.home,
      issuer: keys.issuer,
      activeKeyId: keys.activeKeyId,
      capabilities: { ...this.capabilities },
      counts: {
        credentials: state.credentials.length,
        sources: state.sources.length,
        snapshots: state.snapshots.length,
        contexts: state.contexts.length,
        actions: state.actions.length,
        receipts: state.receipts.length,
        auditEntries: state.auditEntries.length,
      },
      ledger: verification,
      createdAt: state.meta.createdAt,
      updatedAt: state.meta.updatedAt,
    };
  }

  health() {
    if (!this.isInitialized()) {
      return { ok: true, initialized: false, service: 'nova-one', capabilities: { ...this.capabilities } };
    }
    const status = this.status();
    return { ok: status.ledger.valid, initialized: true, service: 'nova-one', ledger: status.ledger, capabilities: status.capabilities };
  }

  authenticate(token) {
    try {
      validateApiToken(token);
    } catch {
      return false;
    }
    const config = this.#config();
    return safeEqual(sha256(token), config.apiTokenSha256);
  }

  async issueCredential(input) {
    assert(PUBLIC_CREDENTIAL_TYPES.has(input?.type), 'reserved_credential_type', 'This credential type is issued only by its bound internal workflow.', 403);
    return this.#transaction(({ credentials }) => credentials.issue(input));
  }

  verifyCredential(tokenOrInput, options = {}) {
    const input = typeof tokenOrInput === 'string' ? { token: tokenOrInput, ...options } : tokenOrInput;
    assert(input && typeof input === 'object' && !Array.isArray(input), 'invalid_request', 'Credential verification input must be an object.');
    return this.#read(({ credentials }) => credentials.verify(input.token, {
      audience: input.audience,
      purpose: input.purpose,
      subject: input.subject,
    }));
  }

  credentialStatus(id) {
    assert(typeof id === 'string' && id.length <= 512, 'invalid_credential_id', 'A bounded credential identifier is required.');
    return this.#read(({ credentials }) => credentials.status(id));
  }

  async changeCredentialStatus(id, state, actor) {
    assert(typeof actor === 'string' && actor.length > 0 && actor.length <= 240, 'invalid_actor', 'A bounded actor identifier is required.');
    return this.#transaction(({ credentials }) => credentials.changeStatus(id, state, actor));
  }

  async createPresentationChallenge(input) {
    assert(input && typeof input === 'object' && !Array.isArray(input), 'invalid_challenge', 'Presentation challenge input must be an object.');
    const ttl = input.ttl ?? 120;
    assert(Number.isInteger(ttl) && ttl >= 15 && ttl <= 600, 'invalid_challenge_ttl', 'Presentation challenge TTL must be between 15 and 600 seconds.');
    const challenge = await this.#transaction(({ credentials }) => credentials.createChallenge({ ...input, ttl, kind: 'presentation' }));
    return { ...challenge, subject: input.subject };
  }

  createCredentialPresentation(input) {
    return this.#read(({ credentials }) => credentials.createPresentation(input));
  }

  async verifyCredentialPresentation(input) {
    assert(input && typeof input === 'object' && !Array.isArray(input), 'invalid_presentation', 'Presentation verification input must be an object.');
    return this.#transaction(({ credentials }) => credentials.verifyPresentation(input.token, {
      audience: input.audience,
      purpose: input.purpose,
      subject: input.subject,
    }));
  }

  async issueSelectiveDisclosure(input) {
    return this.#transaction(({ privacy }) => privacy.issueSelectiveDisclosure(input));
  }

  async presentSelectiveDisclosure(input) {
    return this.#transaction(({ privacy }) => privacy.presentSelectiveDisclosure(input));
  }

  predicateProofCapabilities() {
    return this.#read(({ privacy }) => privacy.predicateProofCapabilities());
  }

  async runWorkflow(spec, { allowFixtures = true, dryRun = false, auditBinding } = {}) {
    assert(spec && typeof spec === 'object' && !Array.isArray(spec), 'invalid_workflow', 'Workflow input must be a JSON object.');
    assert(typeof dryRun === 'boolean', 'invalid_dry_run', 'dryRun must be a boolean.');
    if (auditBinding !== undefined) {
    assert(auditBinding && typeof auditBinding === 'object' && !Array.isArray(auditBinding), 'invalid_automation_binding', 'Automation trace binding must be an object.');
    assertJsonSchema(auditBinding, { type: 'object', additionalProperties: false, required: ['taskId', 'revision', 'taskHash', 'policyHash', 'runKey'], properties: {
      taskId: { type: 'string', minLength: 1, maxLength: 160 }, revision: { type: 'integer', minimum: 1 },
      taskHash: { type: 'string', pattern: '^[a-f0-9]{64}$' }, policyHash: { type: 'string', pattern: '^[a-f0-9]{64}$' }, runKey: { type: 'string', minLength: 1, maxLength: 160 },
    } }, 'invalid_automation_binding');
    }
    this.#ready();
    const workflowModule = await import('./workflow.mjs');
    const inputHash = sha256(spec);
    const attemptId = crypto.randomUUID();
    const actor = typeof spec.actor === 'string' && spec.actor.length <= 240 ? spec.actor : typeof spec.subject === 'string' && spec.subject.length <= 240 ? spec.subject : 'urn:nova:local-user';
    const perform = async state => {
      const context = buildContext(state, loadKeyBundle(this.paths.keys));
      const engine = await createWorkflow(workflowModule.createWorkflowEngine, this, context);
      const input = { ...spec };
      if (dryRun) { delete input.action; delete input.proposedActionIndex; delete input.actionExecution; }
      const result = await engine.run(prepareWorkflow(engine, input, this.capabilities, { allowFixtures }));
      if (auditBinding !== undefined) {
        const binding = { ...auditBinding, inputHash, workflowId: result.workflowId, contextId: result.context.id, evidenceRoot: result.context.evidenceRoot, outputHash: result.agent.outputHash, actionId: result.action?.action.id || null, actionReceiptHash: result.action ? sha256(result.action.receipt) : null, mode: dryRun ? 'dry-run' : 'execute', fixture: result.mode === 'fixture' };
        const entry = context.ledger.append('automation.completed', actor, binding);
        result.automation = { binding, auditReceipt: context.ledger.receipt(entry) };
      }
      return { ...result, dryRun, persisted: !dryRun };
    };
    if (dryRun) return perform(this.store.read());
    return this.store.transaction(perform, { onFailure: (state, error) => {
      const { ledger } = buildContext(state, loadKeyBundle(this.paths.keys));
      const reason = typeof error?.code === 'string' && /^[a-z0-9_]{1,100}$/.test(error.code) ? error.code : 'workflow_failed';
      const payload = { attemptId, inputHash, reason, ...(auditBinding ? { taskHash: auditBinding.taskHash, policyHash: auditBinding.policyHash } : {}) };
      const entry = ledger.append('security.workflow_failed', actor, payload);
      return { payload, auditReceipt: ledger.receipt(entry) };
    } });
  }

  async runDemo({ subject = 'did:example:alice', audience = 'nova-demo', purpose = 'demonstrate-verifiable-output' } = {}) {
    const suffix = crypto.randomUUID();
    const sourceIds = [`demo-source-a-${suffix}`, `demo-source-b-${suffix}`];
    const workflow = await this.runWorkflow({
      name: 'local-verified-workflow-demo',
      subject,
      audience,
      purpose,
      actor: subject,
      sourceIds,
      fixtures: sourceIds.map((id, index) => ({
        id,
        label: `Independent local fixture ${index + 1}`,
        independenceKey: `demo-independent-${index + 1}-${suffix}`,
        payload: { claims: { capacity: 42, region: 'local' } },
      })),
      claims: ['capacity', 'region'],
      authorization: { approvedBy: subject, claims: ['capacity', 'region'] },
      minIndependentSources: 2,
      prompt: 'Summarize only the supplied, signed fixture evidence.',
      action: {
        type: 'record.append',
        parameters: { record: { demo: true, subject, result: 'verified' } },
        idempotencyKey: `demo-${suffix}`,
      },
    });
    return {
      demo: 'local-verified-workflow',
      workflow,
      verifiedAgentCredential: this.#read(({ credentials }) => credentials.verify(workflow.agentCredential.token, {
        audience,
        purpose,
        subject,
        allowUntrustedFixture: true,
      })),
      capabilities: { ...this.capabilities },
    };
  }

  async splitKeys({ shares = 3, threshold = 2, outputDirectory } = {}) {
    this.#ready();
    assert(typeof outputDirectory === 'string' && outputDirectory.length > 0 && outputDirectory.length <= 4096, 'output_directory_required', 'An explicit output directory is required.');
    const output = path.resolve(outputDirectory);
    if (!fs.existsSync(output)) fs.mkdirSync(output, { recursive: true, mode: 0o700 });
    assert(fs.statSync(output).isDirectory(), 'invalid_output_directory', 'The shard output path is not a directory.');
    const bundle = loadKeyBundle(this.paths.keys);
    const shards = await splitKeyBundle(bundle, { shares, threshold });
    const files = shards.map((_shard, index) => path.join(output, `share-${String(index + 1).padStart(3, '0')}-of-${String(shares).padStart(3, '0')}.json`));
    assert(files.every(file => !fs.existsSync(file)), 'shard_target_exists', 'A shard output file already exists; no files were overwritten.', 409, { files: files.filter(file => fs.existsSync(file)) });
    for (let index = 0; index < shards.length; index += 1) writeJsonExclusive(files[index], shards[index]);
    return { split: true, shares, threshold, files, originalKeyPreserved: true, source: this.paths.keys };
  }

  async recoverKeys({ files, outputFile } = {}) {
    assert(Array.isArray(files) && files.length >= 2 && files.every(file => typeof file === 'string' && file.length > 0 && file.length <= 4096), 'invalid_shard_files', 'At least two explicit shard file paths are required.');
    assert(typeof outputFile === 'string' && outputFile.length > 0 && outputFile.length <= 4096, 'output_file_required', 'An explicit recovery output file is required.');
    const destination = path.resolve(outputFile);
    assert(!fs.existsSync(destination), 'recovery_target_exists', 'The recovery target already exists and will not be overwritten.', 409);
    const shards = files.map(file => {
      const resolved = path.resolve(file);
      assert(fs.existsSync(resolved), 'shard_file_not_found', 'A shard file does not exist.', 404, { file: resolved });
      const stat = fs.statSync(resolved);
      assert(stat.isFile() && stat.size > 0 && stat.size <= 128 * 1024, 'invalid_shard_file', 'Shard files must be non-empty JSON files no larger than 131072 bytes.', 400, { file: resolved });
      return readJson(resolved, 'invalid_shard_file', `Shard file is not valid JSON: ${resolved}`, 400);
    });
    const bundle = await combineKeyBundle(shards);
    assert(bundle?.version === 1 && typeof bundle.issuer === 'string' && typeof bundle.activeKeyId === 'string' && bundle.keys?.[bundle.activeKeyId]?.privateKeyPem, 'invalid_recovered_key_bundle', 'The recovered key bundle is invalid.', 409);
    writeKeyBundle(destination, bundle);
    return { recovered: true, outputFile: destination, issuer: bundle.issuer, activeKeyId: bundle.activeKeyId, sourceShares: files.length };
  }

  async executeTool(name, input = {}, { allowFixtures = true } = {}) {
    assert(typeof name === 'string' && name.length <= 128, 'invalid_tool_name', 'A bounded tool name is required.');
    const contract = getToolContract(name);
    assert(contract, 'unknown_tool', `Unknown NOVA tool: ${name}`, 404);
    assertJsonSchema(input, contract.inputSchema, 'tool_input_invalid');
    const handlers = {
      nova_status: () => this.status(),
      nova_issue_credential: value => this.issueCredential(value),
      nova_verify_credential: value => this.verifyCredential(value),
      nova_credential_status: value => this.credentialStatus(value.id),
      nova_change_credential_status: value => this.changeCredentialStatus(value.id, value.state, value.actor),
      nova_create_presentation_challenge: value => this.createPresentationChallenge(value),
      nova_create_presentation: value => this.createCredentialPresentation(value),
      nova_verify_presentation: value => this.verifyCredentialPresentation(value),
      nova_issue_selective_disclosure: value => this.issueSelectiveDisclosure(value),
      nova_present_selective_disclosure: value => this.presentSelectiveDisclosure(value),
      nova_predicate_proof_capabilities: () => this.predicateProofCapabilities(),
      nova_run_workflow: value => this.runWorkflow(value, { allowFixtures }),
      nova_demo: value => this.runDemo(value),
    };
    assert(handlers[name], 'tool_handler_unavailable', `NOVA tool handler is unavailable: ${name}`, 503);
    assert(input && typeof input === 'object' && !Array.isArray(input), 'invalid_tool_input', 'Tool input must be a JSON object.');
    return handlers[name](input);
  }

  #ready() {
    assert(this.isInitialized(), 'nova_not_initialized', 'Run `nova-one init` with the intended NOVA_HOME first.', 503);
  }

  #config() {
    assert(fs.existsSync(this.paths.config), 'nova_not_initialized', 'Run `nova-one init` with the intended NOVA_HOME first.', 503);
    const config = readJson(this.paths.config, 'invalid_config', 'The NOVA configuration file is invalid.');
    assert(config?.version === CONFIG_VERSION && typeof config.issuer === 'string' && /^[0-9a-f]{64}$/.test(config.apiTokenSha256), 'invalid_config', 'The NOVA configuration file is invalid.', 503);
    return config;
  }

  #read(operation) {
    this.#ready();
    const state = this.store.read();
    return operation(buildContext(state, loadKeyBundle(this.paths.keys)));
  }

  async #transaction(operation) {
    this.#ready();
    const keys = loadKeyBundle(this.paths.keys);
    return this.store.transaction(state => operation(buildContext(state, keys)));
  }
}

export function createNovaService(options) {
  return new NovaService(options);
}
