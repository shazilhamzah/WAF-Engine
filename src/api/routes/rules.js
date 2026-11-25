'use strict';
const express = require('express');
const { ApiError, notFound, conflict, confirmationRequired } = require('../errors');
const { v, validate } = require('../validation');

const SOURCE_MAX = 16384;
const validateSchema = v.object({ source: v.string({ min: 1, max: SOURCE_MAX }) });
const createSchema = v.object({ source: v.string({ min: 1, max: SOURCE_MAX }), enabled: v.boolean({ optional: true }) });
const updateSchema = v.object({
  source: v.string({ min: 1, max: SOURCE_MAX, optional: true }),
  enabled: v.boolean({ optional: true }),
  confirm: v.boolean({ optional: true }),
});
const deleteSchema = v.object({ confirm: v.boolean({ optional: true }) });

function parseRuleIdParam(raw) {
  if (!/^\d{4,6}$/.test(String(raw))) return null;
  const n = Number(raw);
  return n >= 1000 && n <= 999999 ? n : null;
}

function dslErrorDetails(errors) {
  return (errors || []).slice(0, 20).map((e) => ({
    field: 'source',
    message: `${e.line ? `line ${e.line}${e.col ? `, col ${e.col}` : ''}: ` : ''}${String(e.message || 'invalid rule').slice(0, 300)}`,
    ...(e.line ? { line: e.line } : {}),
    ...(e.col ? { col: e.col } : {}),
  }));
}

function createRulesRouter({ db, engineState, audit, auth }) {
  const router = express.Router();
  const engine = engineState.engine;
  router.use(auth.requireAuth);
  const AO = auth.requireRole('admin', 'operator');
  const ADMIN = auth.requireRole('admin');

  function checkSource(source) {
    const r = engine.validateRuleSource(source) || {};
    if (!r.ok || !r.rule) throw new ApiError('VALIDATION_FAILED', 'The rule does not compile.', { details: dslErrorDetails(r.errors) });
    const id = Number(r.rule.id);
    if (!Number.isInteger(id) || id < 1000 || id > 999999) {
      throw new ApiError('VALIDATION_FAILED', undefined, { details: [{ field: 'source', message: 'rule id must be an integer between 1000 and 999999' }] });
    }
    return { id, name: String(r.rule.name || `Rule ${id}`).slice(0, 200), severity: r.rule.severity ?? null, category: r.rule.category ?? null };
  }

  router.get('/', AO, (req, res) => {
    const st = engineState.status();
    res.json({ items: db.rules.list(), rulesetVersion: st.rulesetVersion, compileErrors: st.compileErrors });
  });

  router.post('/validate', AO, (req, res) => {
    const { source } = validate(validateSchema, req.body);
    const r = engine.validateRuleSource(source) || {};
    res.json({ ok: Boolean(r.ok), rule: r.rule || null, errors: r.errors || [] });
  });

  router.get('/:id/history', AO, (req, res) => {
    const id = parseRuleIdParam(req.params.id);
    const items = id ? db.rules.history(id) : [];
    if (!items.length) throw notFound('Rule not found.');
    res.json({ items });
  });

  router.post('/', ADMIN, (req, res) => {
    const body = validate(createSchema, req.body);
    const meta = checkSource(body.source);
    if (db.rules.get(meta.id)) throw conflict(`Rule ${meta.id} already exists; edit it instead.`);
    const enabled = body.enabled !== false;
    const rule = db.rules.create({ ...meta, source: body.source, enabled }, req.auth.user.id);
    const st = engineState.reload();
    audit(req, 'rule.create', { targetType: 'rule', targetId: rule.id, details: { name: rule.name, version: rule.version, enabled, rulesetVersion: st.rulesetVersion } });
    res.status(201).json({ rule });
  });

  router.put('/:id', ADMIN, (req, res) => {
    const body = validate(updateSchema, req.body);
    const id = parseRuleIdParam(req.params.id);
    const current = id ? db.rules.get(id) : null;
    if (!current) throw notFound('Rule not found.');
    if (body.source === undefined && body.enabled === undefined) {
      throw new ApiError('VALIDATION_FAILED', undefined, { details: [{ field: 'source', message: 'provide source and/or enabled' }] });
    }
    let meta = null;
    if (body.source !== undefined && body.source !== current.source) {
      meta = checkSource(body.source);
      if (meta.id !== current.id) {
        throw new ApiError('VALIDATION_FAILED', undefined, { details: [{ field: 'source', message: `rule id in source (${meta.id}) must match the edited rule (${current.id})` }] });
      }
    }
    const enabledChanged = body.enabled !== undefined && body.enabled !== current.enabled;
    if (!meta && !enabledChanged) return res.json({ rule: current });
    if (enabledChanged && body.enabled === false && body.confirm !== true) throw confirmationRequired('Disabling a rule is a high-impact action; resend with "confirm": true.');

    const change = meta ? 'update' : (body.enabled ? 'enable' : 'disable');
    const patch = { ...(meta ? { source: body.source, name: meta.name, severity: meta.severity, category: meta.category } : {}), ...(enabledChanged ? { enabled: body.enabled } : {}) };
    const rule = db.rules.update(current.id, patch, req.auth.user.id, change);
    const st = engineState.reload();
    const base = { targetType: 'rule', targetId: rule.id };
    if (meta) audit(req, 'rule.update', { ...base, details: { fromVersion: current.version, toVersion: rule.version, name: rule.name, rulesetVersion: st.rulesetVersion } });
    if (enabledChanged) audit(req, body.enabled ? 'rule.enable' : 'rule.disable', { ...base, details: { version: rule.version, rulesetVersion: st.rulesetVersion } });
    return res.json({ rule });
  });

  router.delete('/:id', ADMIN, (req, res) => {
    const body = validate(deleteSchema, req.body);
    const id = parseRuleIdParam(req.params.id);
    const current = id ? db.rules.get(id) : null;
    if (!current) throw notFound('Rule not found.');
    if (body.confirm !== true) throw confirmationRequired('Deleting a rule is a high-impact action; resend with "confirm": true.');
    db.rules.delete(current.id, req.auth.user.id);
    const st = engineState.reload();
    audit(req, 'rule.delete', { targetType: 'rule', targetId: current.id, details: { name: current.name, lastVersion: current.version, rulesetVersion: st.rulesetVersion } });
    res.status(204).end();
  });

  return router;
}

module.exports = { createRulesRouter, parseRuleIdParam };
