#!/usr/bin/env node

import readline from 'node:readline';
import { pathToFileURL } from 'node:url';

import { publicError } from '../src/errors.mjs';
import { createNovaToolExecutor } from './index.mjs';

const MAX_LINE_LENGTH = 1_048_576;

export async function runStdio({ input = process.stdin, output = process.stdout, home } = {}) {
  const executor = createNovaToolExecutor({ home });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    let id = null;
    try {
      if (Buffer.byteLength(line) > MAX_LINE_LENGTH) throw new Error(`Tool call exceeds ${MAX_LINE_LENGTH} bytes.`);
      const call = JSON.parse(line);
      id = call.id ?? null;
      if (call.method === 'tools/list') {
        output.write(`${JSON.stringify({ id, result: { tools: executor.listTools() } })}\n`);
      } else {
        const toolCall = call.method === 'tools/call' ? call.params : call;
        const result = await executor.callTool(toolCall);
        output.write(`${JSON.stringify({ id, result })}\n`);
      }
    } catch (error) {
      const exposed = publicError(error);
      output.write(`${JSON.stringify({ id, error: { code: exposed.body.error, message: exposed.body.message, details: exposed.body.details } })}\n`);
    }
  }
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  runStdio({ home: process.env.NOVA_HOME }).catch(error => {
    const exposed = publicError(error);
    process.stderr.write(`${JSON.stringify(exposed.body)}\n`);
    process.exitCode = 2;
  });
}
