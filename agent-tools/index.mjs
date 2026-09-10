import { assert } from '../src/errors.mjs';
import { createNovaService } from '../src/service.mjs';
import { assertJsonSchema } from '../src/sources.mjs';
import { getToolContract, NOVA_TOOL_CONTRACTS } from './tool-contracts.mjs';

export function createNovaToolExecutor({ service, ...serviceOptions } = {}) {
  const nova = service || createNovaService(serviceOptions);
  return Object.freeze({
    tools: NOVA_TOOL_CONTRACTS,
    listTools() {
      return NOVA_TOOL_CONTRACTS;
    },
    async callTool(nameOrCall, maybeInput = {}) {
      const name = typeof nameOrCall === 'string' ? nameOrCall : nameOrCall?.name;
      const input = typeof nameOrCall === 'string' ? maybeInput : (nameOrCall?.input ?? nameOrCall?.arguments ?? {});
      const contract = getToolContract(name);
      assert(contract, 'unknown_tool', `Unknown NOVA tool: ${name}`, 404);
      assertJsonSchema(input, contract.inputSchema, 'tool_input_invalid');
      return nova.executeTool(name, input);
    },
  });
}

export async function executeToolCall(call, options) {
  assert(call && typeof call === 'object' && !Array.isArray(call), 'invalid_tool_call', 'A tool call object is required.');
  return createNovaToolExecutor(options).callTool(call);
}

export { NOVA_TOOL_CONTRACTS } from './tool-contracts.mjs';
