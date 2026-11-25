'use strict';
/**
 * Express middleware for authentication, role-based authorization and CSRF (contract §2, §5).
 *
 *   const auth = createAuthMiddleware({ sessions, audit });
 *   app.use(auth.loadSession);             // attaches req.auth = { user, session, csrfToken, expiresAt } or null
 *   router.get('/x', auth.requireAuth, auth.requireRole('admin', 'operator'), handler)
 *   app.use('/api', auth.requireCsrf)      // state-changing methods need a valid X-CSRF-Token
 */
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
      // Tell the browser to drop the stale cookie.
      res.append('Set-Cookie', serializeCookie('', { clear: true, secure: req.secure }));
    }
    return next();
  }

  function requireAuth(req, res, next) {
    if (req.auth && req.auth.user) return next();
    return next(new ApiError(req.sessionStatus === 'expired' ? 'SESSION_EXPIRED' : 'AUTH_REQUIRED'));
  }

  /** Generic 403 for wrong roles + `auth.denied` audit event (no record content revealed). */
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
    if (!req.auth) return next(); // unauthenticated: requireAuth answers 401 first
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
