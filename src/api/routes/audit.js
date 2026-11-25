'use strict';
const express = require('express');
const { v, validate } = require('../validation');

const listQuery = v.object({
  action: v.string({ max: 64, pattern: /^[a-z0-9_.-]+$/i, patternMessage: 'must be an action name such as auth.login.failure', optional: true }),
  actor: v.string({ max: 64, optional: true }),
  outcome: v.enumOf(['success', 'failure', 'denied'], { optional: true }),
  from: v.isoDate({ optional: true }),
  to: v.isoDate({ optional: true }),
  limit: v.integer({ min: 1, max: 200, coerce: true, clamp: true, optional: true }),
  offset: v.integer({ min: 0, max: 10_000_000, coerce: true, optional: true }),
});

function createAuditRouter({ db, auth }) {
  const router = express.Router();
  router.use(auth.requireAuth, auth.requireRole('admin'));

  router.get('/', (req, res) => {
    const q = validate(listQuery, req.query, 'query');
    const { items, total } = db.audit.list(q);
    res.json({ items, total, limit: q.limit || 50, offset: q.offset || 0 });
  });

  router.get('/verify', (req, res) => {
    res.json(db.audit.verifyChain());
  });

  return router;
}

module.exports = { createAuditRouter };
