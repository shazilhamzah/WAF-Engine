'use strict';
/**
 * /api/auth/* and /api/health (contract §5.2).
 */
const express = require('express');
const { ApiError, rateLimited } = require('../errors');
const { v, validate } = require('../validation');
const { asyncHandler } = require('../middleware');
const { verifyPassword, dummyVerify, hashPassword, checkPasswordPolicy, MAX_LENGTH } = require('../../auth/passwords');
const { serializeCookie } = require('../../auth/sessions');
const { createSlidingWindowLimiter } = require('../../auth/rateLimit');
const { publicUser } = require('../../db/repositories/users');

const loginSchema = v.object({
  username: v.string({ min: 1, max: 64 }),
  password: v.string({ min: 1, max: 1024 }),
});

const passwordSchema = v.object({
  currentPassword: v.string({ min: 1, max: 1024 }),
  newPassword: v.string({ min: 1, max: 1024 }),
});

function sessionUser(u) { return { id: u.id, username: u.username, role: u.role }; }

function createAuthRouter({ db, sessions, throttle, audit, auth, version, clock }) {
  const router = express.Router();
  // Wrong current-password attempts on the password-change endpoint (per user).
  const passwordChangeLimiter = createSlidingWindowLimiter({ windowMs: 15 * 60 * 1000, max: 5, clock });

  router.get('/health', (req, res) => {
    res.json({ status: 'ok', version });
  });

  router.post('/auth/login', asyncHandler(async (req, res) => {
    const { username, password } = validate(loginSchema, req.body);
    const attempted = username.trim().slice(0, 64);

    // 1. per-client attempt limit (20/min)
    const client = throttle.checkClient(req.clientId);
    if (client.limited) {
      audit(req, 'auth.login.failure', { outcome: 'failure', targetType: 'user', details: { username: attempted, reason: 'client_rate_limited' }, actor: null });
      throw rateLimited(client.retryAfterSeconds, 'Too many login attempts. Please wait and try again.');
    }

    const creds = db.users.findCredentials(attempted);
    // 2. per-username lockout (5 failures / 15 min -> 15 min); unknown names are tracked identically
    const lock = throttle.lockStatus(attempted, creds ? creds.user.lockedUntil : null);
    if (lock.locked) {
      audit(req, 'auth.login.failure', { outcome: 'failure', targetType: 'user', targetId: creds ? creds.user.id : null, details: { username: attempted, reason: 'locked' }, actor: null });
      throw rateLimited(lock.retryAfterSeconds, 'Too many failed attempts for this account. Please wait and try again.');
    }

    // 3. credential check — same work and same answer for unknown user / wrong password / disabled
    let ok = false;
    if (creds && password.length <= MAX_LENGTH) ok = await verifyPassword(password, creds.passwordHash);
    else await dummyVerify(password);
    const user = creds ? creds.user : null;

    if (!ok || !user || user.disabled) {
      const f = throttle.recordFailure(attempted);
      const reason = !user ? 'unknown_user' : (!ok ? 'bad_password' : 'disabled');
      if (user) db.users.setFailureState(user.id, user.failedAttempts + 1, f.lockedNow ? f.lockedUntil : user.lockedUntil);
      audit(req, 'auth.login.failure', { outcome: 'failure', targetType: 'user', targetId: user ? user.id : null, details: { username: attempted, reason }, actor: null });
      if (f.lockedNow) {
        audit(req, 'auth.lockout', { outcome: 'failure', targetType: 'user', targetId: user ? user.id : null, details: { username: attempted, failures: f.failures, lockedUntil: f.lockedUntil }, actor: null });
      }
      throw new ApiError('AUTH_INVALID');
    }

    // 4. success: rotate (drop any session presented with the request), reset counters, new session
    if (req.sessionToken) sessions.destroy(req.sessionToken);
    sessions.purgeExpired();
    throttle.recordSuccess(attempted);
    if (user.failedAttempts || user.lockedUntil) db.users.resetFailures(user.id);
    const s = sessions.create(user.id, req.clientId);
    res.setHeader('Set-Cookie', serializeCookie(s.token, { secure: req.secure }));
    audit(req, 'auth.login.success', { targetType: 'user', targetId: user.id, actor: user });
    res.status(200).json({ user: sessionUser(user), csrfToken: s.csrfToken, expiresAt: s.expiresAt });
  }));

  // Logout is idempotent: 204 even without a valid session (CSRF still enforced when a session exists).
  router.post('/auth/logout', (req, res) => {
    if (req.auth) {
      sessions.destroyByHash(req.auth.tokenHash);
      audit(req, 'auth.logout', { targetType: 'user', targetId: req.auth.user.id });
    }
    res.setHeader('Set-Cookie', serializeCookie('', { clear: true, secure: req.secure }));
    res.status(204).end();
  });

  router.get('/auth/me', auth.requireAuth, (req, res) => {
    res.json({ user: sessionUser(req.auth.user), csrfToken: req.auth.csrfToken, expiresAt: req.auth.expiresAt });
  });

  router.post('/auth/password', auth.requireAuth, asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = validate(passwordSchema, req.body);
    const user = req.auth.user;
    const problems = checkPasswordPolicy(newPassword, user.username);
    if (problems.length) throw new ApiError('VALIDATION_FAILED', undefined, { details: problems.map((m) => ({ field: 'newPassword', message: m })) });
    if (newPassword === currentPassword) {
      throw new ApiError('VALIDATION_FAILED', undefined, { details: [{ field: 'newPassword', message: 'must differ from the current password' }] });
    }
    const limit = passwordChangeLimiter.hit(user.id);
    if (limit.limited) throw rateLimited(limit.retryAfterSeconds);
    const ok = await verifyPassword(currentPassword, db.users.getPasswordHash(user.id));
    if (!ok) {
      audit(req, 'auth.password.change', { outcome: 'failure', targetType: 'user', targetId: user.id, details: { reason: 'bad_current_password' } });
      throw new ApiError('VALIDATION_FAILED', 'The current password is incorrect.', { details: [{ field: 'currentPassword', message: 'is incorrect' }] });
    }
    passwordChangeLimiter.reset(user.id);
    db.users.setPasswordHash(user.id, await hashPassword(newPassword));
    // Every session of this user (including this one) is invalidated; the client must sign in again.
    const revoked = sessions.destroyAllForUser(user.id);
    audit(req, 'auth.password.change', { targetType: 'user', targetId: user.id, details: { sessionsRevoked: revoked } });
    res.setHeader('Set-Cookie', serializeCookie('', { clear: true, secure: req.secure }));
    res.status(204).end();
  }));

  return router;
}

module.exports = { createAuthRouter, sessionUser, publicUser };
