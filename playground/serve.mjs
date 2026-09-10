import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const requestedPort = Number(process.env.PORT || 18935);
if (!Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535) throw new Error('Use an integer port from 0 to 65535; 0 selects a random port.');
const publicFiles = new Set(['index.html', 'styles.css', 'app.mjs', 'proof.mjs']);
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8' };
const server = http.createServer(async (request, response) => {
  if (!['GET', 'HEAD'].includes(request.method)) { response.writeHead(405, { Allow: 'GET, HEAD' }); response.end('Method not allowed'); return; }
  const url = new URL(request.url, 'http://127.0.0.1');
  const requested = url.pathname === '/' || url.pathname === '/nova-one/' ? 'index.html' : url.pathname.replace(/^\/nova-one\//, '').replace(/^\//, '');
  if (!publicFiles.has(requested)) { response.writeHead(404); response.end('Not found'); return; }
  try {
    const body = await fs.readFile(path.join(root, requested));
    response.writeHead(200, { 'Content-Type': mime[path.extname(requested)], 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'" });
    response.end(request.method === 'HEAD' ? undefined : body);
  } catch { response.writeHead(500); response.end('Static asset unavailable'); }
});
server.on('error', error => { console.error(error.message); process.exitCode = 1; });
server.listen(requestedPort, '127.0.0.1', () => console.log(`NOVA Playground: http://127.0.0.1:${server.address().port}/nova-one/`));
