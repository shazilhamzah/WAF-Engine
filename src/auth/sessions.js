'use strict';
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

function safeEqual(a, b) {
  // hash first so the comparison does not leak the length
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
}

function createSessionManager({ db, clock = () => Date.now(), idleMs = IDLE_MS, absoluteMs = ABSOLUTE_MS }) {
  function effectiveExpiry(session) {
    const idle = Date.parse(session.lastSeenAt) + idleMs;
    const abs = Date.parse(session.expiresAt);
    return Math.min(idle, abs);
  }

  return {
    COOKIE_NAME, idleMs, absoluteMs,
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
    checkCsrf(session, headerValue) {
      return Boolean(session && typeof headerValue === 'string' && headerValue.length > 0 && headerValue.length <= 256
        && safeEqual(headerValue, session.csrfToken));
    },
  };
}

module.exports = { COOKIE_NAME, IDLE_MS, ABSOLUTE_MS, createSessionManager, hashToken, parseCookies, serializeCookie, safeEqual, randomToken };
