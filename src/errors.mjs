export class NovaError extends Error {
  constructor(code, message, status = 400, details) {
    super(message);
    this.name = 'NovaError';
    this.code = code;
    this.status = status;
    if (details !== undefined) this.details = details;
  }
}

export function fail(code, message, status = 400, details) {
  throw new NovaError(code, message, status, details);
}

export function assert(condition, code, message, status = 400, details) {
  if (!condition) fail(code, message, status, details);
}

export function publicError(error) {
  if (error instanceof NovaError) {
    return { status: error.status, body: { error: error.code, message: error.message, details: error.details } };
  }
  return { status: 500, body: { error: 'internal_error', message: 'The request could not be completed.' } };
}
