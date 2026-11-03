'use strict';
const express = require('express');
const { buildReport, FORMATS } = require('../../reports/export');

const ALLOWED_ROLES = new Set(['admin', 'operator']);
const ALLOWED_PARAMS = new Set(['format', 'from', 'to', 'verdict', 'ids']);
const VERDICTS = new Set(['allow', 'flag', 'block']);
const ID_RE = /^[A-Za-z0-9_-]{1,100}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
const MAX_IDS = 500;
const MAX_EVENTS = 1000;
const PAGE = 200;          // repository page size cap

let ApiErrorCtor = null;
try { ({ ApiError: ApiErrorCtor } = require('../errors')); } catch { ApiErrorCtor = null; }

function apiError(code, status, message, details) {
  if (ApiErrorCtor) {
    const e = new ApiErrorCtor(code, message, details ? { details } : {});
    return e;
  }
  const e = new Error(message || code);
  e.code = code; e.status = status; e.details = details; e.expose = true;
  return e;
}

function currentUser(req) {
  return (req.auth && req.auth.user) || req.user || null;
}

function validateQuery(query) {
  const errors = [];
  const q = query || {};
  for (const key of Object.keys(q)) {
    if (!ALLOWED_PARAMS.has(key)) errors.push({ field: key, message: 'unknown parameter' });
  }
  for (const key of ALLOWED_PARAMS) {
    if (q[key] !== undefined && typeof q[key] !== 'string') errors.push({ field: key, message: 'must be a single value' });
  }
  if (errors.length) return { value: null, errors };

  const format = (q.format || 'html').toLowerCase();
  if (!FORMATS.includes(format)) errors.push({ field: 'format', message: `must be one of ${FORMATS.join(', ')}` });

  const value = { format };
  for (const key of ['from', 'to']) {
    if (q[key] === undefined || q[key] === '') continue;
    const t = Date.parse(q[key]);
    if (q[key].length > 40 || !ISO_RE.test(q[key]) || Number.isNaN(t)) errors.push({ field: key, message: 'must be an ISO 8601 date' });
    else value[key] = new Date(t).toISOString();
  }
  if (value.from && value.to && value.from > value.to) errors.push({ field: 'from', message: 'must not be after "to"' });

  if (q.verdict !== undefined && q.verdict !== '') {
    if (!VERDICTS.has(q.verdict)) errors.push({ field: 'verdict', message: 'must be allow, flag or block' });
    else value.verdict = q.verdict;
  }

  if (q.ids !== undefined && q.ids !== '') {
    if (q.ids.length > MAX_IDS * 101) {
      errors.push({ field: 'ids', message: `at most ${MAX_IDS} ids` });
    } else {
      const ids = [...new Set(q.ids.split(',').map((s) => s.trim()).filter(Boolean))];
      if (ids.length > MAX_IDS) errors.push({ field: 'ids', message: `at most ${MAX_IDS} ids` });
      else if (ids.some((id) => !ID_RE.test(id))) errors.push({ field: 'ids', message: 'ids may only contain letters, digits, _ and -' });
      else value.ids = ids;
    }
  }
  return { value: errors.length ? null : value, errors };
}

function readFromRepository(db, filters) {
  const base = {};
  if (filters.from) base.from = filters.from;
  if (filters.to) base.to = filters.to;
  if (filters.verdict) base.verdict = filters.verdict;
  const out = [];
  if (filters.ids) {
    for (let i = 0; i < filters.ids.length; i += PAGE) {
      const chunk = filters.ids.slice(i, i + PAGE);
      const res = db.events.list({ ...base, ids: chunk, full: true, limit: PAGE, offset: 0 });
      out.push(...(res.items || []));
    }
    out.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
    return out;
  }
  for (let offset = 0; offset < MAX_EVENTS; offset += PAGE) {
    const res = db.events.list({ ...base, full: true, limit: Math.min(PAGE, MAX_EVENTS - offset), offset });
    const items = res.items || [];
    out.push(...items);
    if (items.length < PAGE || out.length >= (res.total || 0)) break;
  }
  return out.slice(0, MAX_EVENTS);
}

function createReportsRouter(options = {}) {
  const { db, engineState, audit, listEventsForReport } = options;
  const now = typeof options.now === 'function' ? options.now : () => Date.now();
  const auditFn = typeof audit === 'function' ? audit : () => {};
  const router = express.Router();

  router.get('/export', async (req, res, next) => {
    try {
      const user = currentUser(req);
      if (!user) throw apiError('AUTH_REQUIRED', 401);
      if (!ALLOWED_ROLES.has(user.role)) {
        auditFn(req, 'auth.denied', {
          outcome: 'denied', targetType: 'endpoint', targetId: 'GET /api/reports/export',
          details: { method: 'GET', path: '/api/reports/export', requiredRoles: [...ALLOWED_ROLES] },
        });
        throw apiError('FORBIDDEN', 403);
      }

      const { value, errors } = validateQuery(req.query);
      if (errors.length) {
        auditFn(req, 'request.rejected', {
          outcome: 'failure', targetType: 'endpoint', targetId: 'GET /api/reports/export',
          details: { fields: errors.map((e) => String(e.field).slice(0, 40)).slice(0, 10) },
        });
        throw apiError('VALIDATION_FAILED', 400, 'The report request is not valid.', errors.slice(0, 20));
      }
      const { format, ...filters } = value;

      let events;
      if (typeof listEventsForReport === 'function') {
        events = await listEventsForReport({ ...filters, max: MAX_EVENTS });
      } else if (db && db.events && typeof db.events.list === 'function') {
        events = readFromRepository(db, filters);
      } else {
        throw new Error('reports router: no event source configured');
      }
      events = Array.isArray(events) ? events.slice(0, MAX_EVENTS) : [];

      const es = engineState || {};
      const report = buildReport({
        events,
        config: typeof es.getConfig === 'function' ? es.getConfig() : null,
        rulesetVersion: typeof es.getRulesetVersion === 'function' ? es.getRulesetVersion() : null,
        configVersion: typeof es.getConfigVersion === 'function' ? es.getConfigVersion() : null,
        generatedBy: { username: user.username, role: user.role },
        generatedAt: new Date(now()).toISOString(),
        filters: { ...filters, ...(filters.ids ? { ids: `${filters.ids.length} id(s)` } : {}) },
      }, format);

      auditFn(req, 'report.export', {
        outcome: 'success', targetType: 'report', targetId: format,
        details: {
          format,
          count: report.count,
          filters: {
            from: filters.from || null, to: filters.to || null, verdict: filters.verdict || null,
            idCount: filters.ids ? filters.ids.length : 0,
          },
        },
      });

      res.status(200);
      res.setHeader('Content-Type', report.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
      res.send(report.body);
    } catch (err) {
      next(err);
    }
  });

  return router;
}

module.exports = { createReportsRouter, validateQuery, MAX_IDS, MAX_EVENTS };
