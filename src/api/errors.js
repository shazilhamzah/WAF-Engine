'use strict';

const STATUS_BY_CODE = Object.freeze({
  VALIDATION_FAILED: 400,
  MALFORMED_JSON: 400,
  AUTH_REQUIRED: 401,
  AUTH_INVALID: 401,
  SESSION_EXPIRED: 401,
  FORBIDDEN: 403,
  CSRF_INVALID: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  IDEMPOTENCY_IN_PROGRESS: 409,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA_TYPE: 415,
  IDEMPOTENCY_KEY_REUSED: 422,
  CONFIRMATION_REQUIRED: 428,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
});

const DEFAULT_MESSAGES = Object.freeze({
  VALIDATION_FAILED: 'The request did not pass validation.',
  MALFORMED_JSON: 'The request body is not valid JSON.',
  AUTH_REQUIRED: 'Authentication is required.',
  AUTH_INVALID: 'Invalid username or password.',
  SESSION_EXPIRED: 'Your session has expired. Please sign in again.',
  FORBIDDEN: 'You do not have permission to perform this action.',
  CSRF_INVALID: 'Missing or invalid CSRF token.',
  NOT_FOUND: 'The requested resource was not found.',
  CONFLICT: 'The request conflicts with the current state of the resource.',
  IDEMPOTENCY_IN_PROGRESS: 'A request with this Idempotency-Key is still being processed; retry shortly.',
  IDEMPOTENCY_KEY_REUSED: 'This Idempotency-Key was already used with a different request body.',
  PAYLOAD_TOO_LARGE: 'The request body is too large.',
  UNSUPPORTED_MEDIA_TYPE: 'Request bodies must be sent as application/json.',
  CONFIRMATION_REQUIRED: 'This is a high-impact action; resend with "confirm": true.',
  RATE_LIMITED: 'Too many requests. Please wait and try again.',
  INTERNAL_ERROR: 'An internal error occurred.',
});

class ApiError extends Error {
  constructor(code, message, extra = {}) {
    super(message || DEFAULT_MESSAGES[code] || 'Error');
    if (!STATUS_BY_CODE[code]) throw new Error(`Unknown API error code ${code}`);
    this.name = 'ApiError';
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.details = extra.details;
    this.retryAfterSeconds = extra.retryAfterSeconds;
    this.expose = true;
  }
}

const err = (code, message, extra) => new ApiError(code, message, extra);
const validationError = (details, message) => new ApiError('VALIDATION_FAILED', message, { details });
const notFound = (message) => new ApiError('NOT_FOUND', message);
const forbidden = (message) => new ApiError('FORBIDDEN', message);
const conflict = (message) => new ApiError('CONFLICT', message);
const confirmationRequired = (message) => new ApiError('CONFIRMATION_REQUIRED', message);
const rateLimited = (retryAfterSeconds, message) => new ApiError('RATE_LIMITED', message, { retryAfterSeconds });

function sendError(res, apiError, requestId) {
  const body = { error: { code: apiError.code, message: apiError.message, requestId: requestId || null } };
  if (Array.isArray(apiError.details) && apiError.details.length) body.error.details = apiError.details.slice(0, 50);
  if (apiError.code === 'RATE_LIMITED') {
    const s = Math.max(1, Math.ceil(apiError.retryAfterSeconds || 1));
    body.error.retryAfterSeconds = s;
    body.retryAfterSeconds = s;
    res.setHeader('Retry-After', String(s));
  }
  res.status(apiError.status).type('application/json').send(JSON.stringify(body));
}

module.exports = {
  ApiError, STATUS_BY_CODE, DEFAULT_MESSAGES, err, validationError, notFound, forbidden, conflict,
  confirmationRequired, rateLimited, sendError,
};
