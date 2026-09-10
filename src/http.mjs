import http from 'node:http';

import { randomId } from './canonical.mjs';
import { assert, fail, publicError } from './errors.mjs';
import { createNovaService } from './service.mjs';

export const DEFAULT_BODY_LIMIT = 1_048_576;

function sendJson(response, status, body, requestId, headers = {}) {
  const encoded = Buffer.from(`${JSON.stringify(body)}\n`);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': encoded.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-request-id': requestId,
    ...headers,
  });
  response.end(encoded);
}

async function readJson(request, bodyLimit) {
  const declaredLength = Number(request.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > bodyLimit) {
    request.resume();
    fail('body_too_large', `JSON request bodies are limited to ${bodyLimit} bytes.`, 413);
  }

  const chunks = [];
  let received = 0;
  for await (const chunk of request) {
    received += chunk.length;
    if (received > bodyLimit) {
      request.resume();
      fail('body_too_large', `JSON request bodies are limited to ${bodyLimit} bytes.`, 413);
    }
    chunks.push(chunk);
  }
  if (received === 0) return {};
  assert(request.headers['content-type']?.split(';', 1)[0].trim().toLowerCase() === 'application/json', 'unsupported_media_type', 'Requests with bodies must use application/json.', 415);
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    assert(value && typeof value === 'object' && !Array.isArray(value), 'invalid_json_body', 'The JSON body must be an object.');
    return value;
  } catch (error) {
    if (error?.code === 'invalid_json_body') throw error;
    fail('invalid_json', 'The request body is not valid JSON.');
  }
}

function bearerToken(request) {
  const authorization = request.headers.authorization;
  assert(typeof authorization === 'string', 'authorization_required', 'A Bearer token is required.', 401);
  const match = /^Bearer ([^\s]+)$/i.exec(authorization);
  assert(match && match[1].length >= 43 && match[1].length <= 256, 'invalid_authorization', 'Bearer tokens must contain between 43 and 256 characters.', 401);
  return match[1];
}

function routeCredentialStatus(pathname) {
  const match = /^\/v1\/credentials\/([^/]+)\/status$/.exec(pathname);
  if (!match) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    fail('invalid_path', 'The credential identifier is not valid URL encoding.');
  }
}

function assertProductionWorkflow(input) {
  const objectClaims = input?.claims && typeof input.claims === 'object' && !Array.isArray(input.claims);
  assert(!objectClaims && input?.fixtures === undefined, 'fixture_workflow_forbidden', 'HTTP production routes do not accept fixture data or self-asserted claim objects.', 403);
}

export function createHttpHandler({ service, bodyLimit = DEFAULT_BODY_LIMIT } = {}) {
  assert(service, 'service_required', 'A NovaService instance is required.', 500);
  assert(Number.isSafeInteger(bodyLimit) && bodyLimit >= 1024 && bodyLimit <= 16 * 1024 * 1024, 'invalid_body_limit', 'Body limit must be between 1024 and 16777216 bytes.', 500);

  return async function novaHttpHandler(request, response) {
    const requestId = randomId('request');
    try {
      const url = new URL(request.url, 'http://nova-one.local');
      if (url.pathname === '/health' && (request.method === 'GET' || request.method === 'HEAD')) {
        const health = service.health();
        if (request.method === 'HEAD') {
          response.writeHead(health.ok ? 200 : 503, { 'cache-control': 'no-store', 'x-request-id': requestId });
          response.end();
          return;
        }
        sendJson(response, health.ok ? 200 : 503, health, requestId);
        return;
      }

      assert(url.pathname.startsWith('/v1/'), 'route_not_found', 'The requested route does not exist.', 404);
      assert(service.authenticate(bearerToken(request)), 'invalid_token', 'The Bearer token is not valid.', 401);

      let result;
      if (url.pathname === '/v1/status' && request.method === 'GET') {
        result = service.status();
      } else if (url.pathname === '/v1/credentials/issue' && request.method === 'POST') {
        result = await service.issueCredential(await readJson(request, bodyLimit));
      } else if (url.pathname === '/v1/credentials/verify' && request.method === 'POST') {
        result = service.verifyCredential(await readJson(request, bodyLimit));
      } else if (routeCredentialStatus(url.pathname) && request.method === 'GET') {
        result = service.credentialStatus(routeCredentialStatus(url.pathname));
      } else if (routeCredentialStatus(url.pathname) && request.method === 'POST') {
        const input = await readJson(request, bodyLimit);
        result = await service.changeCredentialStatus(routeCredentialStatus(url.pathname), input.state, input.actor);
      } else if (url.pathname === '/v1/credentials/presentations/challenges' && request.method === 'POST') {
        result = await service.createPresentationChallenge(await readJson(request, bodyLimit));
      } else if (url.pathname === '/v1/credentials/presentations/create' && request.method === 'POST') {
        result = service.createCredentialPresentation(await readJson(request, bodyLimit));
      } else if (url.pathname === '/v1/credentials/presentations/verify' && request.method === 'POST') {
        result = await service.verifyCredentialPresentation(await readJson(request, bodyLimit));
      } else if (url.pathname === '/v1/privacy/selective-disclosures/issue' && request.method === 'POST') {
        result = await service.issueSelectiveDisclosure(await readJson(request, bodyLimit));
      } else if (url.pathname === '/v1/privacy/selective-disclosures/present' && request.method === 'POST') {
        result = await service.presentSelectiveDisclosure(await readJson(request, bodyLimit));
      } else if (url.pathname === '/v1/privacy/predicate-proofs/capabilities' && request.method === 'GET') {
        result = service.predicateProofCapabilities();
      } else if (url.pathname.startsWith('/v1/privacy/zkp/') && request.method === 'POST') {
        await readJson(request, bodyLimit);
        fail('experimental_proof_disabled', 'The former custom proof-of-possession API has been removed. Configure an independently reviewed predicate-proof provider before enabling business proofs.', 410);
      } else if (url.pathname === '/v1/workflows/run' && request.method === 'POST') {
        const input = await readJson(request, bodyLimit);
        assertProductionWorkflow(input);
        result = await service.runWorkflow(input, { allowFixtures: false });
      } else if (url.pathname === '/v1/tools/call' && request.method === 'POST') {
        const input = await readJson(request, bodyLimit);
        assert(input.name !== 'nova_demo', 'fixture_workflow_forbidden', 'The local demo tool is not exposed by the HTTP production route.', 403);
        if (input.name === 'nova_run_workflow') assertProductionWorkflow(input.input);
        result = await service.executeTool(input.name, input.input || {}, { allowFixtures: false });
      } else if (url.pathname === '/v1/demo' && request.method === 'POST') {
        await readJson(request, bodyLimit);
        fail('fixture_workflow_forbidden', 'The local fixture demo is available from the CLI only and is not exposed by the HTTP production route.', 403);
      } else {
        const knownPath = url.pathname === '/v1/status'
          || url.pathname === '/v1/credentials/issue'
          || url.pathname === '/v1/credentials/verify'
          || Boolean(routeCredentialStatus(url.pathname))
          || url.pathname === '/v1/credentials/presentations/challenges'
          || url.pathname === '/v1/credentials/presentations/create'
          || url.pathname === '/v1/credentials/presentations/verify'
          || url.pathname === '/v1/privacy/selective-disclosures/issue'
          || url.pathname === '/v1/privacy/selective-disclosures/present'
          || url.pathname === '/v1/privacy/predicate-proofs/capabilities'
          || url.pathname.startsWith('/v1/privacy/zkp/')
          || url.pathname === '/v1/workflows/run'
          || url.pathname === '/v1/tools/call'
          || url.pathname === '/v1/demo';
        fail(knownPath ? 'method_not_allowed' : 'route_not_found', knownPath ? 'The HTTP method is not allowed for this route.' : 'The requested route does not exist.', knownPath ? 405 : 404);
      }
      sendJson(response, 200, { ok: true, result }, requestId);
    } catch (error) {
      const exposed = publicError(error);
      sendJson(response, exposed.status, { ok: false, ...exposed.body, requestId }, requestId, exposed.status === 401 ? { 'www-authenticate': 'Bearer realm="nova-one"' } : {});
    }
  };
}

export function createNovaHttpServer(options = {}) {
  const service = options.service || createNovaService(options);
  const server = http.createServer(createHttpHandler({ service, bodyLimit: options.bodyLimit }));
  server.requestTimeout = options.requestTimeout ?? 30_000;
  server.headersTimeout = options.headersTimeout ?? 15_000;
  server.keepAliveTimeout = options.keepAliveTimeout ?? 5_000;
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  return server;
}

export async function startNovaHttpServer({ host = '127.0.0.1', port = 8787, ...options } = {}) {
  assert(typeof host === 'string' && host.length > 0 && host.length <= 255, 'invalid_host', 'A bounded host is required.');
  assert(host === '127.0.0.1' || host === '::1', 'loopback_host_required', 'The built-in plaintext server may bind only to a literal loopback address. Use a trusted TLS gateway for remote access.', 403);
  assert(Number.isInteger(port) && port >= 0 && port <= 65535, 'invalid_port', 'Port must be an integer from 0 through 65535.');
  const server = createNovaHttpServer(options);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  return {
    server,
    host,
    port: typeof address === 'object' && address ? address.port : port,
    url: `http://${host.includes(':') ? `[${host}]` : host}:${typeof address === 'object' && address ? address.port : port}`,
    close: () => new Promise((resolve, reject) => {
      server.closeIdleConnections?.();
      server.close(error => error ? reject(error) : resolve());
    }),
  };
}
