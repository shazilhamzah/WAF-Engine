export const ERROR_MESSAGES = Object.freeze({
  VALIDATION_FAILED: 'Some fields are not valid. Check the highlighted values and try again.',
  MALFORMED_JSON: 'The request could not be read. Please try again.',
  AUTH_REQUIRED: 'Please sign in to continue.',
  AUTH_INVALID: 'Invalid username or password.',
  SESSION_EXPIRED: 'Your session has expired. Please sign in again.',
  FORBIDDEN: 'This action is not available for your role.',
  CSRF_INVALID: 'Your session security token is out of date. Reload the page and try again.',
  NOT_FOUND: 'The requested record was not found.',
  CONFLICT: 'This change conflicts with the current state (for example the id already exists, or you cannot review your own request).',
  IDEMPOTENCY_IN_PROGRESS: 'The same request is still being processed. Please wait a moment.',
  IDEMPOTENCY_KEY_REUSED: 'The form changed while a previous attempt was being saved. Submit again.',
  PAYLOAD_TOO_LARGE: 'The submitted data is too large.',
  UNSUPPORTED_MEDIA_TYPE: 'The request format is not supported.',
  CONFIRMATION_REQUIRED: 'This high-impact action needs explicit confirmation.',
  RATE_LIMITED: 'Too many requests. Please wait and try again.',
  INTERNAL_ERROR: 'Something went wrong on the server. The error was logged.',
  NETWORK_ERROR: 'Cannot reach the WAF Studio server. Is it running?',
  BAD_RESPONSE: 'The server returned an unexpected response.',
});

export function messageFor(code, status) {
  if (code && Object.prototype.hasOwnProperty.call(ERROR_MESSAGES, code)) return ERROR_MESSAGES[code];
  if (status === 401) return ERROR_MESSAGES.AUTH_REQUIRED;
  if (status === 403) return ERROR_MESSAGES.FORBIDDEN;
  if (status === 404) return ERROR_MESSAGES.NOT_FOUND;
  if (status === 429) return ERROR_MESSAGES.RATE_LIMITED;
  if (status >= 500) return ERROR_MESSAGES.INTERNAL_ERROR;
  return 'The request failed.';
}

// 403 stays generic and login failures never reveal whether a username exists
export function describeError(err) {
  if (!err) return 'Unknown error.';
  const status = err.status || 0;
  const code = err.code || null;
  if (status === 403 || code === 'FORBIDDEN') return ERROR_MESSAGES.FORBIDDEN;
  let msg = messageFor(code, status);
  if (code === 'VALIDATION_FAILED' && Array.isArray(err.details) && err.details.length) {
    const parts = err.details.slice(0, 5).map((d) => (d && d.field ? `${d.field}: ${d.message}` : String((d && d.message) || d)));
    msg = `Validation failed — ${parts.join('; ')}`;
  } else if (code === 'CONFLICT' && err.serverMessage) {
    msg = `Conflict — ${err.serverMessage}`;
  }
  if ((status === 429 || code === 'RATE_LIMITED') && Number.isFinite(err.retryAfter) && err.retryAfter > 0) {
    msg = `Too many requests. Try again in ${Math.ceil(err.retryAfter)} seconds.`;
  }
  if (err.requestId) msg += ` (reference ${err.requestId})`;
  return msg;
}
