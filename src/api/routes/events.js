'use strict';
const express = require('express');
const { ApiError, notFound, conflict, rateLimited } = require('../errors');
const { v, validate, sampleSchema, sampleSizeProblems } = require('../validation');
const { analyzeSample } = require('../../services/analysis');
const { isId } = require('../../db/util');
const { SOURCES, VERDICTS, ACTIONS } = require('../../db/repositories/events');

const SUMMARY_KEYS = ['id', 'ts', 'source', 'label', 'method', 'path', 'verdict', 'action', 'score', 'mode', 'matchedRuleIds', 'latencyMs'];
const toSummary = (e) => Object.fromEntries(SUMMARY_KEYS.map((k) => [k, e[k] ?? null]));

const statsQuery = v.object({ hours: v.integer({ min: 1, max: 720, coerce: true, optional: true }) });

const listQuery = v.object({
  verdict: v.enumOf(VERDICTS, { optional: true }),
  action: v.enumOf(ACTIONS, { optional: true }),
  source: v.enumOf(SOURCES, { optional: true }),
  ruleId: v.integer({ min: 1, max: 999999, coerce: true, optional: true }),
  q: v.string({ max: 200, optional: true }),
  from: v.isoDate({ optional: true }),
  to: v.isoDate({ optional: true }),
  limit: v.integer({ min: 1, max: 200, coerce: true, clamp: true, optional: true }),
  offset: v.integer({ min: 0, max: 1_000_000, coerce: true, optional: true }),
});

const analyzeSchema = v.object({
  label: v.string({ max: 200, trim: true, optional: true, nullable: true }),
  sample: sampleSchema,
});

const importSchema = v.object({
  filename: v.string({ min: 6, max: 128, pattern: /^[A-Za-z0-9 _.()-]+\.json$/i, patternMessage: 'must be a plain file name ending in .json' }),
  samples: v.array(v.any(), { min: 1, max: 100 }),
});

const compareQuery = v.object({ a: v.string({ min: 1, max: 100 }), b: v.string({ min: 1, max: 100 }) });

function normalizeImportItem(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    throw new ApiError('VALIDATION_FAILED', 'Each sample must be an object.');
  }
  const inner = item.sample && typeof item.sample === 'object' && !Array.isArray(item.sample) ? item.sample : item;
  const label = [item.label, item.name, item.id].find((x) => typeof x === 'string' && x.trim()) || null;
  const candidate = { method: inner.method, path: inner.path };
  if (inner.headers !== undefined) candidate.headers = inner.headers;
  if (inner.body !== undefined) candidate.body = inner.body;
  const sample = validate(sampleSchema, candidate, 'sample');
  const size = sampleSizeProblems(sample);
  if (size.length) throw new ApiError('VALIDATION_FAILED', 'Sample body is larger than 1 MiB.', { details: size });
  return { sample, label: label ? label.trim().slice(0, 200) : null };
}

function diffEvents(a, b) {
  const ra = new Set(a.matchedRuleIds.map(Number));
  const rb = new Set(b.matchedRuleIds.map(Number));
  return {
    verdictChanged: a.verdict !== b.verdict,
    actionChanged: a.action !== b.action,
    scoreDelta: Math.round((Number(b.score) - Number(a.score)) * 1000) / 1000,
    rulesAdded: [...rb].filter((id) => !ra.has(id)).sort((x, y) => x - y),
    rulesRemoved: [...ra].filter((id) => !rb.has(id)).sort((x, y) => x - y),
    rulesetChanged: (a.rulesetVersion || null) !== (b.rulesetVersion || null),
    configChanged: (a.configVersion ?? null) !== (b.configVersion ?? null),
  };
}

function createEventsRouter({ db, engineState, audit, auth, analysisLimiter }) {
  const router = express.Router();
  const AO = auth.requireRole('admin', 'operator');
  const ALL = auth.requireRole('admin', 'operator', 'viewer');

  function limitSubmissions(req) {
    const r = analysisLimiter.hit(req.auth.user.id);
    if (r.limited) {
      audit(req, 'request.rejected', { outcome: 'failure', targetType: 'api', targetId: `${req.method} ${req.path}`, details: { code: 'RATE_LIMITED' } });
      throw rateLimited(r.retryAfterSeconds, 'Too many analysis submissions. Please wait and try again.');
    }
  }

  router.get('/stats', auth.requireAuth, ALL, (req, res) => {
    const q = validate(statsQuery, req.query, 'query');
    const stats = db.events.stats({ hours: q.hours || 24 });
    const st = engineState.status();
    res.json({
      totals: stats.totals, byCategory: stats.byCategory, topRules: stats.topRules, latency: stats.latency,
      mode: st.mode, rulesetVersion: st.rulesetVersion, configVersion: st.configVersion, timeline: stats.timeline,
      hours: stats.hours,
    });
  });

  router.get('/events', auth.requireAuth, ALL, (req, res) => {
    const q = validate(listQuery, req.query, 'query');
    const { items, total } = db.events.list({ ...q, full: false });
    res.json({ items, total, limit: q.limit || 50, offset: q.offset || 0 });
  });

  // this route must come before the one with an id
  router.get('/events/compare', auth.requireAuth, AO, (req, res) => {
    const q = validate(compareQuery, req.query, 'query');
    const a = isId(q.a, 'evt_') ? db.events.get(q.a) : null;
    const b = isId(q.b, 'evt_') ? db.events.get(q.b) : null;
    if (!a || !b) throw notFound('One or both events were not found.');
    res.json({ a, b, diff: diffEvents(a, b) });
  });

  router.get('/events/:id', auth.requireAuth, AO, (req, res) => {
    const event = isId(req.params.id, 'evt_') ? db.events.get(req.params.id) : null;
    if (!event) throw notFound('Event not found.');
    res.json({ event });
  });

  router.post('/analyze', auth.requireAuth, AO, (req, res) => {
    const body = validate(analyzeSchema, req.body);
    const size = sampleSizeProblems(body.sample);
    if (size.length) throw new ApiError('VALIDATION_FAILED', undefined, { details: size });
    limitSubmissions(req);
    const event = analyzeSample({
      db, engineState, sample: body.sample, label: body.label || null, source: 'console', user: req.auth.user, clientId: req.clientId,
    });
    audit(req, 'analysis.submit', {
      targetType: 'event', targetId: event.id,
      details: { label: event.label, verdict: event.verdict, action: event.action, score: event.score, matchedRuleIds: event.matchedRuleIds },
    });
    res.status(201).json({ event });
  });

  router.post('/import', auth.requireAuth, AO, (req, res) => {
    const body = validate(importSchema, req.body);
    limitSubmissions(req);
    const events = [];
    const rejected = [];
    body.samples.forEach((item, index) => {
      let normalized;
      try {
        normalized = normalizeImportItem(item);
      } catch (e) {
        const detail = e.details && e.details[0] ? `${e.details[0].field} ${e.details[0].message}` : e.message;
        rejected.push({ index, code: 'VALIDATION_FAILED', message: String(detail).slice(0, 200) });
        return;
      }
      const event = analyzeSample({
        db, engineState, sample: normalized.sample, label: normalized.label || `${body.filename}#${index + 1}`,
        source: 'import', user: req.auth.user, clientId: req.clientId,
      });
      events.push(toSummary(event));
    });
    audit(req, 'import.submit', {
      targetType: 'import', targetId: body.filename,
      details: { filename: body.filename, submitted: body.samples.length, imported: events.length, rejected: rejected.length, eventIds: events.slice(0, 20).map((e) => e.id) },
    });
    res.status(201).json({ imported: events.length, events, rejected });
  });

  router.post('/events/:id/replay', auth.requireAuth, AO, (req, res) => {
    validate(v.object({}), req.body);
    const original = isId(req.params.id, 'evt_') ? db.events.get(req.params.id) : null;
    if (!original) throw notFound('Event not found.');
    if (original.source === 'proxy' || !original.sample) throw conflict('Only console or import events (which keep their redacted sample) can be replayed.');
    limitSubmissions(req);
    const sample = validate(sampleSchema, original.sample, 'sample');
    const event = analyzeSample({
      db, engineState, sample, label: original.label, source: 'replay', user: req.auth.user, clientId: req.clientId, replayOf: original.id,
    });
    const previous = db.events.getSummary(original.id);
    audit(req, 'event.replay', {
      targetType: 'event', targetId: original.id,
      details: { replayEventId: event.id, previousVerdict: original.verdict, newVerdict: event.verdict, rulesetVersion: event.rulesetVersion, configVersion: event.configVersion },
    });
    res.status(201).json({ event, previous });
  });

  return router;
}

module.exports = { createEventsRouter, diffEvents, normalizeImportItem };
