#!/usr/bin/env node

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import { fail, publicError } from '../src/errors.mjs';
import { startNovaHttpServer } from '../src/http.mjs';
import { createNovaService } from '../src/service.mjs';
import { runAutomation, verifyAutomationReport, readAutomationJson, automationFailure } from '../automation/runner.mjs';

const HELP = `nova-one - local verifiable trust infrastructure

Usage:
  nova-one init [--home PATH] [--issuer URL] [--api-token TOKEN]
  nova-one status [--home PATH]
  nova-one demo [--home PATH] [--subject ID] [--audience VALUE] [--purpose VALUE]
  nova-one automation --file TASK.json [--execute --run-key KEY] [--home PATH] [--out REPORT.json]
  nova-one automation verify --file REPORT.json --task TASK.json [--run-key KEY] [--home PATH]
  nova-one workflow [--home PATH] (--input JSON | --file FILE | --stdin)
  nova-one credential issue [--home PATH] (--input JSON | --file FILE | --stdin)
  nova-one credential verify [--home PATH] (--input JSON | --file FILE | --stdin)
  nova-one credential status [--home PATH] --id CREDENTIAL_ID
  nova-one credential activate|suspend|revoke [--home PATH] --id ID --actor ID
  nova-one credential presentation challenge|create|verify [--home PATH] (--input JSON | --file FILE | --stdin)
  nova-one privacy selective-disclosure issue [--home PATH] (--input JSON | --file FILE | --stdin)
  nova-one privacy selective-disclosure present [--home PATH] (--input JSON | --file FILE | --stdin)
  nova-one privacy predicate-proof status [--home PATH]
  nova-one keys split [--home PATH] --shares N --threshold T --out DIRECTORY
  nova-one keys recover --input SHARE1,SHARE2[,SHARE_N] --out FILE
  nova-one serve [--home PATH] [--host 127.0.0.1|::1] [--port 8787] [--body-limit BYTES]

Input and output use JSON. NOVA_HOME is used when --home is omitted. External
network access, model calls, and action executors are disabled by this CLI.`;

function parseArguments(argv) {
  const positionals = [];
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      positionals.push(argument);
      continue;
    }
    const equals = argument.indexOf('=');
    if (equals > 2) {
      options[argument.slice(2, equals)] = argument.slice(equals + 1);
      continue;
    }
    const name = argument.slice(2);
    if (['help', 'stdin', 'compact', 'execute'].includes(name)) {
      options[name] = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) fail('invalid_cli_arguments', `Option --${name} requires a value.`);
    options[name] = value;
    index += 1;
  }
  return { positionals, options };
}

function parseInteger(value, fallback, name) {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) fail('invalid_cli_arguments', `Option --${name} must be an integer.`);
  return parsed;
}

async function readStandardInput(limit = 1_048_576) {
  const chunks = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > limit) fail('body_too_large', `Standard input exceeds ${limit} bytes.`, 413);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function jsonInput(options) {
  const selected = [options.input !== undefined, options.file !== undefined, options.stdin === true].filter(Boolean).length;
  if (selected !== 1) fail('invalid_cli_arguments', 'Choose exactly one of --input JSON, --file FILE, or --stdin.');
  let source;
  if (options.input !== undefined) source = options.input;
  else if (options.file !== undefined) source = fs.readFileSync(options.file, 'utf8');
  else source = await readStandardInput();
  let value;
  try { value = JSON.parse(source); } catch { fail('invalid_json', 'Input is not valid JSON.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_json_body', 'JSON input must be an object.');
  return value;
}

function output(value, compact) {
  process.stdout.write(`${JSON.stringify(value, null, compact ? 0 : 2)}\n`);
}

// Reserve the report before running any workflow. The caller owns the local
// directory; still avoid overwriting or deleting a path replaced during a run.
function reserveAutomationReport(file) {
  if (typeof file !== 'string' || !file.length || file.length > 4096) fail('invalid_cli_arguments', '--out requires a bounded file path.');
  let fd;
  try { fd = fs.openSync(file, 'wx', 0o600); }
  catch (error) {
    if (error.code === 'EEXIST') fail('report_target_exists', 'The report target already exists. Choose a new --out file; no workflow was executed.', 409);
    if (['ENOENT', 'ENOTDIR'].includes(error.code)) fail('report_directory_unavailable', 'The report parent directory does not exist or is not a directory; no workflow was executed.');
    if (['EACCES', 'EPERM', 'EROFS'].includes(error.code)) fail('report_target_not_writable', 'The report target is not writable; no workflow was executed.', 403);
    fail('report_target_unavailable', 'The report target could not be reserved; no workflow was executed.', 503);
  }
  const identity = fs.fstatSync(fd); let completed = false;
  const stillOwned = () => { try { const current = fs.lstatSync(file); return current.ino === identity.ino && current.dev === identity.dev; } catch { return false; } };
  return {
    write(report) {
      if (!stillOwned()) fail('report_target_changed', 'The reserved report target changed. Execution may have committed; retry with the same run key and a new output path.', 409);
      try { fs.writeFileSync(fd, `${JSON.stringify(report, null, 2)}\n`); fs.fsyncSync(fd); completed = true; }
      catch { fail('report_write_failed', 'The reserved report could not be written. Execution may have committed; retry with the same run key and a new output path.', 503); }
    },
    close() {
      try { fs.closeSync(fd); } finally {
        if (!completed && stillOwned()) { try { fs.unlinkSync(file); } catch { /* An incomplete reserved file can be removed by its local operator. */ } }
      }
    },
  };
}

function serviceFrom(options) {
  // Capabilities are intentionally not exposed as command-line switches. A
  // local operator must opt in programmatically with explicitly scoped adapters.
  return createNovaService({ home: options.home });
}

async function waitForShutdown(running) {
  await new Promise((resolve, reject) => {
    let stopping = false;
    const stop = () => {
      if (stopping) return;
      stopping = true;
      running.close().then(resolve, reject);
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    running.server.once('error', reject);
  });
}

export async function runCli(argv = process.argv.slice(2)) {
  const { positionals, options } = parseArguments(argv);
  const [command, subcommand, operation] = positionals;
  if (!command || command === 'help' || options.help) {
    process.stdout.write(`${HELP}\n`);
    return 0;
  }

  const service = serviceFrom(options);
  if (command === 'init') {
    output(service.initialize({ issuer: options.issuer, apiToken: options['api-token'] }), options.compact);
    return 0;
  }
  if (command === 'status') {
    output(service.status(), options.compact);
    return 0;
  }
  if (command === 'demo') {
    output(await service.runDemo({ subject: options.subject, audience: options.audience, purpose: options.purpose }), options.compact);
    return 0;
  }
  if (command === 'automation') {
    if (!options.file) fail('invalid_cli_arguments', 'automation requires --file.');
    let reservedReport;
    try {
      if (options.out !== undefined) reservedReport = reserveAutomationReport(options.out);
      let report;
      if (subcommand === 'verify') {
        if (!options.task) fail('invalid_cli_arguments', 'automation verify requires --task and an expected --run-key for execution reports.');
        report = verifyAutomationReport({ service, report: readAutomationJson(options.file), task: readAutomationJson(options.task), runKey: options['run-key'] });
      } else {
        if (subcommand) fail('invalid_cli_arguments', 'automation supports only run (no subcommand) or verify.');
        report = await runAutomation({ service, task: readAutomationJson(options.file), execute: options.execute === true, runKey: options['run-key'] });
      }
      if (reservedReport) reservedReport.write(report);
      output(report, options.compact);
      return 0;
    } catch (error) {
      process.stderr.write(`${JSON.stringify(automationFailure(error))}\n`);
      return 1;
    } finally { reservedReport?.close(); }
  }
  if (command === 'workflow') {
    output(await service.runWorkflow(await jsonInput(options)), options.compact);
    return 0;
  }
  if (command === 'credential') {
    if (subcommand === 'issue') output(await service.issueCredential(await jsonInput(options)), options.compact);
    else if (subcommand === 'verify') output(service.verifyCredential(await jsonInput(options)), options.compact);
    else if (subcommand === 'status') {
      if (!options.id) fail('invalid_cli_arguments', 'credential status requires --id.');
      output(service.credentialStatus(options.id), options.compact);
    } else if (['activate', 'suspend', 'revoke'].includes(subcommand)) {
      if (!options.id) fail('invalid_cli_arguments', `credential ${subcommand} requires --id.`);
      if (!options.actor) fail('invalid_cli_arguments', `credential ${subcommand} requires --actor.`);
      const state = subcommand === 'activate' ? 'active' : subcommand === 'suspend' ? 'suspended' : 'revoked';
      output(await service.changeCredentialStatus(options.id, state, options.actor), options.compact);
    } else if (subcommand === 'presentation') {
      if (operation === 'challenge') output(await service.createPresentationChallenge(await jsonInput(options)), options.compact);
      else if (operation === 'create') output(service.createCredentialPresentation(await jsonInput(options)), options.compact);
      else if (operation === 'verify') output(await service.verifyCredentialPresentation(await jsonInput(options)), options.compact);
      else fail('invalid_cli_arguments', 'credential presentation requires challenge, create, or verify.');
    } else {
      fail('invalid_cli_arguments', 'credential requires issue, verify, status, activate, suspend, revoke, or presentation.');
    }
    return 0;
  }
  if (command === 'privacy') {
    if (subcommand === 'selective-disclosure') {
      if (operation === 'issue') output(await service.issueSelectiveDisclosure(await jsonInput(options)), options.compact);
      else if (operation === 'present') output(await service.presentSelectiveDisclosure(await jsonInput(options)), options.compact);
      else fail('invalid_cli_arguments', 'privacy selective-disclosure requires issue or present.');
    } else if (subcommand === 'predicate-proof' && operation === 'status') {
      output(service.predicateProofCapabilities(), options.compact);
    } else {
      fail('invalid_cli_arguments', 'privacy requires selective-disclosure or predicate-proof status.');
    }
    return 0;
  }
  if (command === 'keys') {
    if (subcommand === 'split') {
      if (!options.out) fail('invalid_cli_arguments', 'keys split requires an explicit --out directory.');
      output(await service.splitKeys({
        shares: parseInteger(options.shares, 3, 'shares'),
        threshold: parseInteger(options.threshold, 2, 'threshold'),
        outputDirectory: options.out,
      }), options.compact);
    } else if (subcommand === 'recover') {
      if (!options.input || !options.out) fail('invalid_cli_arguments', 'keys recover requires --input file1,file2 and an explicit --out file.');
      const files = options.input.split(',').map(file => file.trim()).filter(Boolean);
      output(await service.recoverKeys({ files, outputFile: options.out }), options.compact);
    } else {
      fail('invalid_cli_arguments', 'keys requires split or recover.');
    }
    return 0;
  }
  if (command === 'serve') {
    if (!service.isInitialized()) fail('nova_not_initialized', 'Run `nova-one init` with the same NOVA_HOME before serving.', 503);
    const running = await startNovaHttpServer({
      service,
      host: options.host || '127.0.0.1',
      port: parseInteger(options.port, 8787, 'port'),
      bodyLimit: parseInteger(options['body-limit'], undefined, 'body-limit'),
    });
    output({ listening: true, url: running.url, home: service.home, capabilities: service.capabilities }, options.compact);
    await waitForShutdown(running);
    return 0;
  }
  fail('unknown_command', `Unknown command: ${command}`, 404);
}

function isDirectExecution() {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isDirectExecution()) {
  runCli().then(code => {
    process.exitCode = code;
  }).catch(error => {
    const exposed = publicError(error);
    process.stderr.write(`${JSON.stringify({ ok: false, ...exposed.body })}\n`);
    process.exitCode = exposed.status >= 500 ? 2 : 1;
  });
}
