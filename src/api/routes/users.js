'use strict';
const express = require('express');
const { ApiError, notFound, conflict, confirmationRequired } = require('../errors');
const { v, validate, ROLES, USERNAME_RE } = require('../validation');
const { asyncHandler } = require('../middleware');
const { hashPassword, checkPasswordPolicy } = require('../../auth/passwords');
const { publicUser } = require('../../db/repositories/users');
const { isId } = require('../../db/util');

const createSchema = v.object({
  username: v.string({ min: 3, max: 32, pattern: USERNAME_RE, patternMessage: '3–32 characters: letters, digits, _ . -' }),
  password: v.string({ min: 1, max: 1024 }),
  role: v.enumOf(ROLES),
});
const updateSchema = v.object({
  role: v.enumOf(ROLES, { optional: true }),
  disabled: v.boolean({ optional: true }),
  password: v.string({ min: 1, max: 1024, optional: true }),
  confirm: v.boolean({ optional: true }),
});

function policyError(problems) {
  return new ApiError('VALIDATION_FAILED', undefined, { details: problems.map((m) => ({ field: 'password', message: m })) });
}

function createUsersRouter({ db, sessions, throttle, audit, auth }) {
  const router = express.Router();
  router.use(auth.requireAuth, auth.requireRole('admin'));

  router.get('/', (req, res) => {
    res.json({ items: db.users.list().map(publicUser) });
  });

  router.post('/', asyncHandler(async (req, res) => {
    const body = validate(createSchema, req.body);
    const problems = checkPasswordPolicy(body.password, body.username);
    if (problems.length) throw policyError(problems);
    if (db.users.findByUsername(body.username)) throw conflict('A user with that username already exists.');
    let user;
    const hash = await hashPassword(body.password);
    try {
      user = db.users.create({ username: body.username, passwordHash: hash, role: body.role });
    } catch (e) {
      if (/UNIQUE/i.test(String(e.message))) throw conflict('A user with that username already exists.');
      throw e;
    }
    audit(req, 'user.create', { targetType: 'user', targetId: user.id, details: { username: user.username, role: user.role } });
    res.status(201).json({ user: publicUser(user) });
  }));

  router.put('/:id', asyncHandler(async (req, res) => {
    const body = validate(updateSchema, req.body);
    if (!isId(req.params.id, 'usr_')) throw notFound();
    const target = db.users.findById(req.params.id);
    if (!target) throw notFound();
    const changes = [];
    if (body.role !== undefined && body.role !== target.role) changes.push('role');
    if (body.disabled !== undefined && body.disabled !== target.disabled) changes.push(body.disabled ? 'disable' : 'enable');
    if (body.password !== undefined) changes.push('password');
    if (changes.length === 0) return res.json({ user: publicUser(target) });

    if (body.password !== undefined) {
      const problems = checkPasswordPolicy(body.password, target.username);
      if (problems.length) throw policyError(problems);
    }
    const losesAdmin = target.role === 'admin' && !target.disabled && ((changes.includes('role') && body.role !== 'admin') || changes.includes('disable'));
    if (losesAdmin && db.users.countActiveAdmins() <= 1) throw conflict('At least one active administrator must remain.');
    // role changes and disabling need confirmation
    if ((changes.includes('role') || changes.includes('disable')) && body.confirm !== true) throw confirmationRequired();

    const passwordHash = body.password !== undefined ? await hashPassword(body.password) : null;
    db.transaction(() => {
      if (changes.includes('role')) db.users.setRole(target.id, body.role);
      if (changes.includes('disable') || changes.includes('enable')) db.users.setDisabled(target.id, body.disabled);
      if (passwordHash) db.users.setPasswordHash(target.id, passwordHash); // also clears lockout state
    });
    if (passwordHash || changes.includes('enable')) throttle.unlock(target.username);
    // role changes apply on the next request since roles are read every time
    let sessionsRevoked = 0;
    if (changes.includes('disable') || passwordHash) sessionsRevoked = sessions.destroyAllForUser(target.id);
    const updated = db.users.findById(target.id);
    audit(req, 'user.update', {
      targetType: 'user', targetId: target.id,
      details: { username: target.username, changes, ...(changes.includes('role') ? { fromRole: target.role, toRole: updated.role } : {}), sessionsRevoked },
    });
    return res.json({ user: publicUser(updated) });
  }));

  return router;
}

module.exports = { createUsersRouter };
