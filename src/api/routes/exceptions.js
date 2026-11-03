'use strict';
const express = require('express');
const { ApiError, notFound, conflict, confirmationRequired } = require('../errors');
const { v, validate, scopeSchema, ruleIdSchema } = require('../validation');
const { isId } = require('../../db/util');
const { STATUSES } = require('../../db/repositories/exceptions');

const SUMMARY_KEYS = ['id', 'ts', 'source', 'label', 'method', 'path', 'verdict', 'action', 'score', 'mode', 'matchedRuleIds', 'latencyMs'];
const toSummary = (e) => Object.fromEntries(SUMMARY_KEYS.map((k) => [k, e[k] ?? null]));

const listQuery = v.object({ status: v.enumOf(STATUSES, { optional: true }) });
const previewSchema = v.object({ ruleId: ruleIdSchema, scope: scopeSchema });
const requestSchema = v.object({
  ruleId: ruleIdSchema,
  scope: scopeSchema,
  reason: v.string({ min: 3, max: 500, trim: true }),
  sourceEventId: v.string({ max: 64, optional: true, nullable: true }),
  expiresAt: v.isoDate({ future: true, optional: true, nullable: true }),
});
const reviewSchema = v.object({ confirm: v.boolean({ optional: true }), note: v.string({ max: 500, trim: true, optional: true, nullable: true }) });

function normScope(scope) {
  return { pathPrefix: scope.pathPrefix ?? null, location: scope.location ?? null, method: scope.method ?? null };
}

function scopeMatches(scope, { path, method, location }) {
  if (scope.pathPrefix !== null && !(typeof path === 'string' && path.startsWith(scope.pathPrefix))) return false;
  if (scope.location !== null && location !== scope.location) return false;
  if (scope.method !== null && method !== scope.method) return false;
  return true;
}

function createExceptionsRouter({ db, engineState, audit, auth }) {
  const router = express.Router();
  router.use(auth.requireAuth);
  const AO = auth.requireRole('admin', 'operator');
  const ADMIN = auth.requireRole('admin');

  function load(id) {
    const x = isId(id, 'exc_') ? db.exceptions.get(id) : null;
    if (!x) throw notFound('Exception not found.');
    return x;
  }

  function preview(ruleId, scope) {
    const events = db.events.recentWithRule(ruleId, 1000);
    const affected = [];
    for (const e of events) {
      const d = e.decision || {};
      const path = (d.request && d.request.path) || e.path;
      const method = (d.request && d.request.method) || e.method;
      const hit = (d.matches || []).some((m) => Number(m.ruleId) === ruleId && !m.suppressedBy && scopeMatches(scope, { path, method, location: m.location }));
      if (hit) affected.push(e);
    }
    return { affectedEvents: affected.length, scanned: events.length, sample: affected.slice(0, 10).map(toSummary) };
  }

  router.get('/', AO, (req, res) => {
    const q = validate(listQuery, req.query, 'query');
    res.json({ items: db.exceptions.list({ status: q.status }) });
  });

  router.post('/preview', AO, (req, res) => {
    const body = validate(previewSchema, req.body);
    res.json(preview(body.ruleId, normScope(body.scope)));
  });

  router.post('/', AO, (req, res) => {
    const body = validate(requestSchema, req.body);
    const scope = normScope(body.scope);
    const details = [];
    if (scope.pathPrefix === null && scope.location === null && scope.method === null) {
      details.push({ field: 'scope', message: 'at least one of pathPrefix, location or method is required (an unscoped exception would disable the rule)' });
    }
    if (!db.rules.get(body.ruleId)) details.push({ field: 'ruleId', message: 'no such rule' });
    let sourceEventId = null;
    if (body.sourceEventId) {
      if (!isId(body.sourceEventId, 'evt_') || !db.events.get(body.sourceEventId)) details.push({ field: 'sourceEventId', message: 'no such event' });
      else sourceEventId = body.sourceEventId;
    }
    if (details.length) throw new ApiError('VALIDATION_FAILED', undefined, { details });
    const exception = db.exceptions.create({
      ruleId: body.ruleId, scope, reason: body.reason, requestedBy: req.auth.user.id, sourceEventId, expiresAt: body.expiresAt || null,
    });
    const impact = preview(body.ruleId, scope);
    audit(req, 'exception.request', {
      targetType: 'exception', targetId: exception.id,
      details: { ruleId: exception.ruleId, scope, reason: exception.reason, sourceEventId, expiresAt: exception.expiresAt, previewAffected: impact.affectedEvents },
    });
    res.status(201).json({ exception });
  });

  function review(action, { from, to, needsConfirm, separationOfDuties }) {
    return (req, res) => {
      const body = validate(reviewSchema, req.body);
      const x = load(req.params.id);
      if (separationOfDuties && x.requestedById === req.auth.user.id) {
        audit(req, `exception.${action}`, { outcome: 'denied', targetType: 'exception', targetId: x.id, details: { reason: 'separation_of_duties' } });
        throw new ApiError('FORBIDDEN', `Separation of duties: you cannot ${action} an exception you requested yourself; another administrator must review it.`);
      }
      if (x.status !== from) throw conflict(`Only ${from} exceptions can be ${to}; this one is ${x.status}.`);
      if (action === 'approve' && x.expiresAt && Date.parse(x.expiresAt) <= Date.now()) throw conflict('This exception request has already expired.');
      if (needsConfirm && body.confirm !== true) throw confirmationRequired(`${action[0].toUpperCase()}${action.slice(1)} is a high-impact action; resend with "confirm": true.`);
      const updated = db.exceptions.transition(x.id, from, to, req.auth.user.id, body.note || null);
      if (!updated) throw conflict('The exception was changed by someone else; reload and try again.');
      const st = (from === 'approved' || to === 'approved') ? engineState.reload() : null;
      audit(req, `exception.${action}`, {
        targetType: 'exception', targetId: x.id,
        details: { ruleId: x.ruleId, scope: x.scope, from, to, note: updated.reviewNote, requestedBy: x.requestedBy, ...(st ? { activeExceptions: st.activeExceptions } : {}) },
      });
      res.json({ exception: updated });
    };
  }

  router.post('/:id/approve', ADMIN, review('approve', { from: 'pending', to: 'approved', needsConfirm: true, separationOfDuties: true }));
  router.post('/:id/reject', ADMIN, review('reject', { from: 'pending', to: 'rejected', needsConfirm: false, separationOfDuties: true }));
  router.post('/:id/revoke', ADMIN, review('revoke', { from: 'approved', to: 'revoked', needsConfirm: true, separationOfDuties: false }));

  return router;
}

module.exports = { createExceptionsRouter, scopeMatches };
