'use strict';
/**
 * Cookie sessions (contract §5, NFR-2/3).
 *  - token: 32 random bytes (base64url) in cookie `waf_sid` (HttpOnly, SameSite=Strict, Path=/, Secure on HTTPS)
 *  - only SHA-256(token) is stored; a database leak does not reveal usable cookies
 *  - CSRF synchronizer token (32 random bytes) per session
 *  - 30-minute idle timeout, 8-hour absolute lifetime; rotated on login, deleted on logout/password change
 */
const crypto = require('node:crypto');

const COOKIE_NAME = 'waf_sid';
const IDLE_MS = 30 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** Minimal RFC 6265 cookie header parser (first occurrence wins). */
function parseCookies(header) {
  const out = {};
  if (typeof header !== 'string' || header.length > 8192) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    if (!(name in out)) out[name] = value;
  }
  return out;
}

function serializeCookie(value, { secure = false, clear = false } = {}) {
  const attrs = [`${COOKIE_NAME}=${clear ? '' : value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (secure) attrs.push('Secure');
  if (clear) attrs.push('Max-Age=0', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  return attrs.join('; ');
}

/** Constant-time comparison of two strings of possibly different length. */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
}

/**
 * @param {{ db, clock?: () => number, idleMs?: number, absoluteMs?: number }} deps
 */
function createSessionManager({ db, clock = () => Date.now(), idleMs = IDLE_MS, absoluteMs = ABSOLUTE_MS }) {
  function effectiveExpiry(session) {
    const idle = Date.parse(session.lastSeenAt) + idleMs;
    const abs = Date.parse(session.expiresAt);
    return Math.min(idle, abs);
  }

  return {
    COOKIE_NAME, idleMs, absoluteMs,
    /** Creates a session. Returns the raw token (cookie value) — never persisted. */
    create(userId, clientId = null) {
      const now = clock();
      const token = randomToken();
      const csrfToken = randomToken();
      const session = db.sessions.create({
        tokenHash: hashToken(token), userId, csrfToken, clientId,
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + absoluteMs).toISOString(),
      });
      return { token, csrfToken, session, expiresAt: new Date(effectiveExpiry(session)).toISOString() };
    },
    /**
     * Validates a cookie token. Returns
     *   { status: 'missing' } | { status: 'expired' } | { status: 'ok', session, user, csrfToken, expiresAt }
     * Expired sessions are deleted. Disabled/missing users invalidate the session.
     */
    validate(token, { touch = true } = {}) {
      if (!token) return { status: 'missing' };
      if (!TOKEN_RE.test(token)) return { status: 'expired' };
      const tokenHash = hashToken(token);
      const session = db.sessions.get(tokenHash);
      if (!session) return { status: 'expired' };
      const now = clock();
      if (now >= effectiveExpiry(session)) {
        db.sessions.delete(tokenHash);
        return { status: 'expired' };
      }
      const user = db.users.findById(session.userId);
      if (!user || user.disabled) {
        db.sessions.delete(tokenHash);
        return { status: 'expired' };
      }
      if (touch) {
        const nowIso = new Date(now).toISOString();
        db.sessions.touch(tokenHash, nowIso);
        session.lastSeenAt = nowIso;
      }
      return { status: 'ok', session, user, tokenHash, csrfToken: session.csrfToken, expiresAt: new Date(effectiveExpiry(session)).toISOString() };
    },
    destroy(token) { return token ? db.sessions.delete(hashToken(token)) : false; },
    destroyByHash(tokenHash) { return db.sessions.delete(tokenHash); },
    destroyAllForUser(userId) { return db.sessions.deleteForUser(userId); },
    purgeExpired() {
      const now = clock();
      return db.sessions.deleteExpired(new Date(now).toISOString(), new Date(now - idleMs).toISOString());
    },
    /** CSRF synchronizer check (timing-safe). */
    checkCsrf(session, headerValue) {
      return Boolean(session && typeof headerValue === 'string' && headerValue.length > 0 && headerValue.length <= 256
        && safeEqual(headerValue, session.csrfToken));
    },
  };
}

module.exports = { COOKIE_NAME, IDLE_MS, ABSOLUTE_MS, createSessionManager, hashToken, parseCookies, serializeCookie, safeEqual, randomToken };
