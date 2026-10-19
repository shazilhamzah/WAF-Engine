'use strict';
/** /api/config (contract §5.2). Reads: admin+operator. Changes: admin, always with "confirm": true. */
const express = require('express');
const { ApiError, confirmationRequired } = require('../errors');
const { v, validate } = require('../validation');
const { canonicalJson } = require('../../db/util');

const updateSchema = v.object({
  config: v.object({}, { allowUnknown: true }),
  reason: v.string({ max: 500, trim: true, optional: true }),
  confirm: v.boolean({ optional: true }),
});

/** Flat list of changed leaf paths between two configs, for the audit record. */
function configChanges(before, after, prefix = '') {
  const out = [];
  const keys = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  for (const k of keys) {
    const a = before ? before[k] : undefined;
    const b = after ? after[k] : undefined;
    const p = prefix ? `${prefix}.${k}` : k;
    if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) out.push(...configChanges(a, b, p));
    else if (canonicalJson(a) !== canonicalJson(b)) out.push({ field: p, from: a ?? null, to: b ?? null });
  }
  return out;
}

function createConfigRouter({ db, engineState, audit, auth }) {
  const router = express.Router();
  const engine = engineState.engine;
  router.use(auth.requireAuth);
  const AO = auth.requireRole('admin', 'operator');
  const ADMIN = auth.requireRole('admin');

  router.get('/', AO, (req, res) => {
    const rec = engineState.getConfigRecord();
    res.json({ config: rec.config, version: rec.version, changedAt: rec.changedAt, changedBy: rec.changedBy });
  });

  router.get('/history', AO, (req, res) => {
    res.json({ items: db.configs.history(200).map((c) => ({ version: c.version, config: c.config, changedBy: c.changedBy, changedAt: c.changedAt, reason: c.reason })) });
  });

  router.put('/', ADMIN, (req, res) => {
    const body = validate(updateSchema, req.body);
    const result = typeof engine.validateConfig === 'function' ? engine.validateConfig(body.config) : { ok: true, config: body.config };
    if (!result || !result.ok) {
      const details = ((result && result.errors) || []).slice(0, 50).map((e) => ({ field: `config.${e.field || ''}`.replace(/\.$/, ''), message: String(e.message || 'invalid') }));
      throw new ApiError('VALIDATION_FAILED', 'The configuration is invalid.', { details: details.length ? details : [{ field: 'config', message: 'invalid configuration' }] });
    }
    if (body.confirm !== true) throw confirmationRequired('Changing the engine configuration is a high-impact action; resend with "confirm": true.');
    const before = engineState.getConfigRecord();
    const changes = configChanges(before.config, result.config);
    const rec = db.configs.append(result.config, req.auth.user.id, body.reason || '');
    engineState.reload();
    audit(req, 'config.update', {
      targetType: 'config', targetId: rec.version,
      details: { fromVersion: before.version, toVersion: rec.version, reason: rec.reason, changes: changes.slice(0, 30) },
    });
    res.json({ config: rec.config, version: rec.version, changedAt: rec.changedAt, changedBy: rec.changedBy });
  });

  return router;
}

module.exports = { createConfigRouter, configChanges };
