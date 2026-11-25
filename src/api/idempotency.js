'use strict';
const crypto = require('node:crypto');
const { ApiError } = require('./errors');

// endpoints that create a record; a retried request with the same Idempotency-Key gets the first
// response back instead of creating a second rule, exception, user, event or import batch
const CREATE_ROUTES = Object.freeze([
  /^\/api\/rules\/?$/,
  /^\/api\/exceptions\/?$/,
  /^\/api\/users\/?$/,
  /^\/api\/analyze\/?$/,
  /^\/api\/import\/?$/,
  /^\/api\/events\/[^/]+\/replay\/?$/,
]);

const KEY_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;
const HEADER = 'idempotency-key';

function fingerprint(body) {
  let text;
  try { text = JSON.stringify(body === undefined ? null : body); } catch { text = ''; }
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Keys are scoped to the signed-in user (or the client id before sign-in) plus method and path,
 * so one user's key can never replay another user's response. Only 2xx responses are kept: a
 * failed attempt can be retried with the same key. Entries live in memory for ttlMs.
 */
function createIdempotency({ clock = () => Date.now(), ttlMs = 24 * 60 * 60 * 1000, maxEntries = 2000 } = {}) {
  const entries = new Map();

  function sweep(now) {
    for (const [k, e] of entries) {
      if (e.expiresAt > now) break;
      entries.delete(k);
    }
    while (entries.size > maxEntries) entries.delete(entries.keys().next().value);
  }

  function middleware(req, res, next) {
    if (req.method !== 'POST') return next();
    const path = (req.originalUrl || req.url || '').split('?')[0];
    if (!CREATE_ROUTES.some((re) => re.test(path))) return next();
    const key = req.headers[HEADER];
    if (key === undefined) return next();
    if (typeof key !== 'string' || !KEY_PATTERN.test(key)) {
      return next(new ApiError('VALIDATION_FAILED', 'Idempotency-Key must be 8-128 letters, digits, "-" or "_".',
        { details: [{ field: 'Idempotency-Key', message: 'invalid format' }] }));
    }
    const now = clock();
    sweep(now);
    const owner = req.auth && req.auth.user ? `u:${req.auth.user.id}` : `c:${req.clientId || 'anon'}`;
    const id = `${owner} ${req.method} ${path} ${key}`;
    const print = fingerprint(req.body);
    const existing = entries.get(id);
    if (existing) {
      if (existing.fingerprint !== print) {
        return next(new ApiError('IDEMPOTENCY_KEY_REUSED'));
      }
      if (existing.state === 'pending') {
        res.setHeader('Retry-After', '1');
        return next(new ApiError('IDEMPOTENCY_IN_PROGRESS'));
      }
      res.setHeader('Idempotent-Replayed', 'true');
      res.setHeader('Idempotency-Key', key);
      if (existing.body === undefined) return res.status(existing.status).end();
      return res.status(existing.status).type('application/json').send(existing.body);
    }

    const entry = { state: 'pending', fingerprint: print, status: 0, body: undefined, expiresAt: now + ttlMs };
    entries.set(id, entry);
    res.setHeader('Idempotency-Key', key);

    const send = res.send.bind(res);
    res.send = function captureSend(body) {
      if (entry.state === 'pending' && res.statusCode >= 200 && res.statusCode < 300) {
        entry.body = Buffer.isBuffer(body) ? body.toString('utf8') : typeof body === 'string' ? body : JSON.stringify(body);
      }
      return send(body);
    };
    res.on('finish', () => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        entry.state = 'done';
        entry.status = res.statusCode;
      } else if (entries.get(id) === entry) {
        entries.delete(id);
      }
    });
    res.on('close', () => {
      if (entry.state === 'pending' && entries.get(id) === entry) entries.delete(id);
    });
    return next();
  }

  return { middleware, size: () => entries.size, clear: () => entries.clear() };
}

module.exports = { createIdempotency, CREATE_ROUTES };
