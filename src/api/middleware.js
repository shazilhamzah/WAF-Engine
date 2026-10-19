'use strict';
/**
 * Cross-cutting HTTP middleware for the Studio console: request ids, security headers, Host/Origin
 * checks, JSON-only bodies, and the central error handler (no stack traces, stable codes).
 */
const crypto = require('node:crypto');
const { ApiError, sendError } = require('./errors');

const CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:", "connect-src 'self'",
  "font-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'",
].join('; ');

const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self)',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
});

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

/** Request id + client pseudonym + security headers on every response. */
function requestContext({ identifyClient }) {
  return function context(req, res, next) {
    req.requestId = 'req_' + crypto.randomUUID();
    req.clientId = identifyClient(req.socket && req.socket.remoteAddress);
    res.setHeader('X-Request-Id', req.requestId);
    for (const [k, val] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, val);
    next();
  };
}

function apiNoStore(req, res, next) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
}

/**
 * DNS-rebinding / cross-site defence in depth: the console only answers Host names that point at the
 * loopback interface, and state-changing requests carrying an Origin header must be same-origin.
 */
function hostAndOriginGuard({ allowedHosts = LOCAL_HOSTS } = {}) {
  return function guard(req, res, next) {
    const host = String(req.headers.host || '');
    const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0];
    if (!allowedHosts.has(hostname.toLowerCase())) return next(new ApiError('FORBIDDEN', 'Requests must be addressed to the local console.'));
    const origin = req.headers.origin;
    if (origin && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const expected = `${req.secure ? 'https' : 'http'}://${host}`.toLowerCase();
      if (String(origin).toLowerCase() !== expected) return next(new ApiError('CSRF_INVALID', 'Cross-origin requests are not allowed.'));
    }
    return next();
  };
}

function hasBody(req) {
  const len = req.headers['content-length'];
  if (req.headers['transfer-encoding']) return true;
  return len !== undefined && len !== '0';
}

/** Bodies must be application/json (contract §5: else 415). */
function requireJsonBody(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) || !hasBody(req)) return next();
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  const mime = ct.split(';')[0].trim();
  if (mime !== 'application/json') return next(new ApiError('UNSUPPORTED_MEDIA_TYPE'));
  const charset = /charset\s*=\s*"?([\w-]+)/.exec(ct);
  if (charset && !['utf-8', 'utf8'].includes(charset[1])) return next(new ApiError('UNSUPPORTED_MEDIA_TYPE', 'Only UTF-8 JSON is accepted.'));
  return next();
}

/** The JSON parser accepts only objects/arrays; route schemas require objects. */
function ensureObjectBody(req, res, next) {
  if (req.body === undefined || req.body === null || (typeof req.body === 'object' && !Buffer.isBuffer(req.body))) {
    if (req.body === undefined || req.body === null) req.body = {};
    return next();
  }
  return next(new ApiError('VALIDATION_FAILED', 'The request body must be a JSON object.'));
}

const REJECT_AUDIT = new Set(['VALIDATION_FAILED', 'MALFORMED_JSON', 'PAYLOAD_TOO_LARGE', 'UNSUPPORTED_MEDIA_TYPE']);

/** Maps any error to the contract envelope; logs internals; audits rejected input and server errors. */
function errorHandler({ logger, audit }) {
  // Bound how many system.error audit entries a burst of failures can create.
  let lastSystemErrorAudit = 0;
  // eslint-disable-next-line no-unused-vars
  return function handle(error, req, res, next) {
    let apiError;
    if (error instanceof ApiError) apiError = error;
    else if (error && error.type === 'entity.parse.failed') apiError = new ApiError('MALFORMED_JSON');
    else if (error && error.type === 'entity.too.large') apiError = new ApiError('PAYLOAD_TOO_LARGE');
    else if (error && (error.type === 'encoding.unsupported' || error.type === 'charset.unsupported')) apiError = new ApiError('UNSUPPORTED_MEDIA_TYPE');
    else if (error && (error.type === 'request.aborted' || error.code === 'ECONNABORTED')) { return undefined; }
    else if (error instanceof URIError || (error && error.status === 400 && /decode param/i.test(error.message || ''))) {
      apiError = new ApiError('VALIDATION_FAILED', 'The request URL is malformed.');
    } else if (error && (error.status === 400 || error.statusCode === 400) && error.expose) {
      apiError = new ApiError('VALIDATION_FAILED');
    } else {
      apiError = new ApiError('INTERNAL_ERROR');
      logger.error('unhandled API error', { requestId: req.requestId, method: req.method, path: req.path, err: error });
      const now = Date.now();
      if (now - lastSystemErrorAudit > 1000) {
        lastSystemErrorAudit = now;
        audit(req, 'system.error', { outcome: 'failure', targetType: 'api', targetId: `${req.method} ${req.path}`.slice(0, 120), details: { code: 'INTERNAL_ERROR' } });
      }
    }
    if (REJECT_AUDIT.has(apiError.code)) {
      audit(req, 'request.rejected', {
        outcome: 'failure', targetType: 'api', targetId: `${req.method} ${req.path}`.slice(0, 120),
        details: { code: apiError.code, fields: (apiError.details || []).map((d) => d.field).slice(0, 10) },
      });
    }
    if (res.headersSent) { try { res.end(); } catch { /* ignore */ } return undefined; }
    if (apiError.code === 'SESSION_EXPIRED' || apiError.code === 'AUTH_REQUIRED') res.setHeader('Cache-Control', 'no-store');
    return sendError(res, apiError, req.requestId);
  };
}

/** Wraps async route handlers so rejections reach the error handler. */
const asyncHandler = (fn) => (req, res, next) => {
  try {
    const p = fn(req, res, next);
    if (p && typeof p.catch === 'function') p.catch(next);
  } catch (e) { next(e); }
};

module.exports = {
  CSP, SECURITY_HEADERS, requestContext, apiNoStore, hostAndOriginGuard, requireJsonBody, ensureObjectBody,
  errorHandler, asyncHandler, LOCAL_HOSTS,
};
