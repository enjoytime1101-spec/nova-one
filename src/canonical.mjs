import crypto from 'node:crypto';

export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

export function sha256(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex');
}

export function randomId(prefix = 'nova') {
  return `${prefix}_${crypto.randomUUID()}`;
}

export function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

export function decodeBase64url(value) {
  return Buffer.from(value, 'base64url');
}

export function timestamp(now = Date.now()) {
  return new Date(now).toISOString();
}

export function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
