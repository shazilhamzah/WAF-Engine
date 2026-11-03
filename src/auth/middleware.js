'use strict';
const { ApiError } = require('../api/errors');
const { parseCookies, serializeCookie, COOKIE_NAME } = require('./sessions');

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function createAuthMiddleware({ sessions, audit, csrfExempt = ['/api/auth/login'] }) {
  const exempt = new Set(csrfExempt);

  function loadSession(req, res, next) {
    req.auth = null;
    req.sessionStatus = 'missing';
    const cookies = parseCookies(req.headers.cookie);
    const token = cookies[COOKIE_NAME];
    req.sessionToken = token || null;
    if (!token) return next();
    const result = sessions.validate(token);
    req.sessionStatus = result.status;
    if (result.status === 'ok') {
      req.auth = { user: result.user, session: result.session, tokenHash: result.tokenHash, csrfToken: result.csrfToken, expiresAt: result.expiresAt };
    } else {
      res.append('Set-Cookie', serializeCookie('', { clear: true, secure: req.secure }));
    }
    return next();
  }

  function requireAuth(req, res, next) {
    if (req.auth && req.auth.user) return next();
    return next(new ApiError(req.sessionStatus === 'expired' ? 'SESSION_EXPIRED' : 'AUTH_REQUIRED'));
  }

  function requireRole(...roles) {
    const allowed = new Set(roles.flat());
    return function roleGuard(req, res, next) {
      if (!req.auth || !req.auth.user) return requireAuth(req, res, next);
      if (allowed.has(req.auth.user.role)) return next();
      audit(req, 'auth.denied', {
        outcome: 'denied', targetType: 'endpoint', targetId: `${req.method} ${req.baseUrl || ''}${req.route ? req.route.path : req.path}`,
        details: { method: req.method, path: (req.originalUrl || '').split('?')[0].slice(0, 200), requiredRoles: [...allowed] },
      });
      return next(new ApiError('FORBIDDEN'));
    };
  }

  function requireCsrf(req, res, next) {
    if (!STATE_CHANGING.has(req.method)) return next();
    const p = (req.originalUrl || req.url || '').split('?')[0];
    if (exempt.has(p)) return next();
    if (!req.auth) return next(); // unauthenticated requests get their 401 from the auth check first
    if (sessions.checkCsrf(req.auth.session, req.get('x-csrf-token'))) return next();
    audit(req, 'auth.denied', {
      outcome: 'denied', targetType: 'endpoint', targetId: `${req.method} ${p.slice(0, 200)}`,
      details: { reason: 'csrf_invalid', method: req.method, path: p.slice(0, 200) },
    });
    return next(new ApiError('CSRF_INVALID'));
  }

  return { loadSession, requireAuth, requireRole, requireCsrf };
}

module.exports = { createAuthMiddleware, STATE_CHANGING };
