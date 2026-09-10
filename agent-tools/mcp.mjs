#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import { createNovaToolExecutor, NOVA_TOOL_CONTRACTS } from './index.mjs';
import { assert, publicError } from '../src/errors.mjs';
import { MCP_RECEIPT_TOOL, verifyLocalActionReceipt } from './mcp-receipts.mjs';

// A verifier that consumes a challenge or writes an audit event is not read-only.
// New contracts are denied unless explicitly classified or locally allowed.
export const MCP_READ_ONLY_TOOLS = Object.freeze([
  'nova_status', 'nova_verify_credential', 'nova_credential_status',
  'nova_predicate_proof_capabilities',
  'nova_verify_action_receipt',
]);
const readOnly = new Set(MCP_READ_ONLY_TOOLS);
const mcpContracts = [...NOVA_TOOL_CONTRACTS, MCP_RECEIPT_TOOL];
const contracts = new Map(mcpContracts.map(tool => [tool.name, tool]));
const packageInfo = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

function explicitHome(home) {
  assert(typeof home === 'string' && home.length <= 4096 && path.isAbsolute(home),
    'mcp_home_required', 'Set NOVA_HOME to an explicit absolute directory; MCP never selects a shared default.');
  const resolved = path.resolve(home);
  return fs.existsSync(resolved) ? fs.realpathSync(resolved) : resolved;
}

function writeAllowlist(value) {
  assert(Array.isArray(value) && value.length <= contracts.size && new Set(value).size === value.length,
    'invalid_mcp_policy', 'allowWriteTools must be an array of unique mutating tool names.');
  assert(value.every(name => typeof name === 'string' && contracts.has(name) && !readOnly.has(name)),
    'invalid_mcp_policy', 'allowWriteTools contains an unknown or read-only tool.');
  return Object.freeze([...value]);
}

/** Load only operator-controlled startup configuration, never tool arguments. */
export function loadMcpConfiguration(env = process.env) {
  const home = explicitHome(env.NOVA_HOME);
  const file = env.NOVA_MCP_POLICY_FILE;
  if (!file) return Object.freeze({ home, allowWriteTools: Object.freeze([]) });
  assert(path.isAbsolute(file), 'invalid_mcp_policy', 'NOVA_MCP_POLICY_FILE must be an absolute local file path.');
  let policy;
  try {
    const stat = fs.statSync(file);
    assert(stat.isFile() && stat.size > 0 && stat.size <= 16_384,
      'invalid_mcp_policy', 'The MCP policy must be a non-empty JSON file smaller than 16 KiB.');
    assert(process.platform === 'win32' || (stat.mode & 0o022) === 0,
      'invalid_mcp_policy', 'The MCP policy must not be writable by other users.');
    policy = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    if (error?.code === 'invalid_mcp_policy') throw error;
    assert(false, 'invalid_mcp_policy', 'The MCP policy file could not be read as JSON.');
  }
  assert(policy && typeof policy === 'object' && !Array.isArray(policy)
    && Object.keys(policy).every(key => ['version', 'home', 'allowWriteTools'].includes(key))
    && policy.version === 1 && explicitHome(policy.home) === home,
  'invalid_mcp_policy', 'The MCP policy must use version 1 and bind the exact NOVA_HOME.');
  return Object.freeze({ home, allowWriteTools: writeAllowlist(policy.allowWriteTools) });
}

export function createNovaMcpServer({ home, allowWriteTools = [] } = {}) {
  const selectedHome = explicitHome(home);
  const allowedWrites = new Set(writeAllowlist(allowWriteTools));
  // No external adapter/capability option is accepted on this transport.
  const executor = createNovaToolExecutor({ home: selectedHome });
  // The SDK's low-level server preserves the existing JSON Schemas verbatim;
  // validation remains in the shared NOVA executor rather than a second schema.
  const server = new Server({ name: 'nova-one', version: packageInfo.version }, {
    capabilities: { tools: {} },
    instructions: 'Local NOVA tools. Read and verification tools are available by default. '
      + 'Mutations require an operator startup policy; tool input cannot grant permission. '
      + 'Network, model, and external executors are disabled. Do not initialize or change homes to bypass a refusal. '
      + 'Fixture results are demonstrations, not external evidence or production certification.',
  });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: mcpContracts.filter(tool => readOnly.has(tool.name) || allowedWrites.has(tool.name))
      .map(tool => ({
        ...tool,
        annotations: {
          readOnlyHint: readOnly.has(tool.name),
          destructiveHint: !readOnly.has(tool.name),
          idempotentHint: readOnly.has(tool.name),
          openWorldHint: false,
        },
      })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const { name, arguments: input = {} } = request.params;
    if (!contracts.has(name)) throw new McpError(ErrorCode.InvalidParams, 'Unknown NOVA tool.');
    try {
      assert(readOnly.has(name) || allowedWrites.has(name), 'mcp_write_tool_disabled',
        'This tool changes state or creates signed material. An operator must allow its exact name in the local startup policy.', 403);
      const result = name === MCP_RECEIPT_TOOL.name
        ? verifyLocalActionReceipt(selectedHome, input) : await executor.callTool(name, input);
      return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
    } catch (error) {
      const { body } = publicError(error);
      return { isError: true, content: [{ type: 'text', text: JSON.stringify(body) }], structuredContent: body };
    }
  });
  return server;
}

export async function runMcp(configuration = loadMcpConfiguration()) {
  const server = createNovaMcpServer(configuration);
  await server.connect(new StdioServerTransport());
  return server;
}

function isEntrypoint() {
  if (!process.argv[1]) return false;
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); }
  catch { return false; }
}

if (isEntrypoint()) {
  const args = process.argv.slice(2);
  const reportStartupError = error => {
    // stdout is exclusively the SDK's JSON-RPC channel; never log input or keys.
    process.stderr.write(`${JSON.stringify(publicError(error).body)}\n`);
    process.exitCode = 2;
  };
  if (args.length === 1 && args[0] === '--help') {
    process.stdout.write('nova-one-mcp — local NOVA Model Context Protocol stdio server\n\n'
      + 'Usage: nova-one-mcp [--help | --version]\n'
      + 'NOVA_HOME: required absolute, separately initialized state directory.\n'
      + 'NOVA_MCP_POLICY_FILE: optional absolute local JSON policy; default is read-only.\n'
      + 'Policy: {"version":1,"home":"/absolute/state","allowWriteTools":["nova_issue_credential"]}\n'
      + 'External network/model/action adapters are disabled. Startup never initializes state.\n');
  } else if (args.length === 1 && args[0] === '--version') {
    process.stdout.write(`${packageInfo.version}\n`);
  } else if (args.length) {
    try { assert(false, 'invalid_mcp_arguments', 'Use no arguments for stdio, or --help / --version. Configure permissions locally via NOVA_MCP_POLICY_FILE.'); }
    catch (error) { reportStartupError(error); }
  } else {
    runMcp().catch(reportStartupError);
  }
}
