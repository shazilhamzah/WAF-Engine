'use strict';
const { newId, nowIso } = require('../util');

const STATUSES = Object.freeze(['pending', 'approved', 'rejected', 'revoked']);

function mapException(row) {
  if (!row) return null;
  return {
    id: row.id,
    ruleId: row.rule_id,
    scope: { pathPrefix: row.path_prefix ?? null, location: row.location ?? null, method: row.method ?? null },
    reason: row.reason,
    status: row.status,
    requestedBy: row.requested_by_name ?? null,
    requestedById: row.requested_by,
    reviewedBy: row.reviewed_by_name ?? null,
    reviewedById: row.reviewed_by ?? null,
    reviewNote: row.review_note ?? null,
    sourceEventId: row.source_event_id ?? null,
    createdAt: row.created_at,
    reviewedAt: row.reviewed_at ?? null,
    expiresAt: row.expires_at ?? null,
  };
}

function toEngineException(x) {
  return { id: x.id, ruleId: x.ruleId, scope: { ...x.scope }, reason: x.reason, status: x.status, expiresAt: x.expiresAt };
}

function createExceptionsRepository({ raw, clock }) {
  const SELECT = `SELECT x.*, ru.username AS requested_by_name, rv.username AS reviewed_by_name FROM exceptions x
                  LEFT JOIN users ru ON ru.id = x.requested_by LEFT JOIN users rv ON rv.id = x.reviewed_by`;
  const stmts = {
    insert: raw.prepare(`INSERT INTO exceptions (id, rule_id, path_prefix, location, method, reason, status, requested_by,
                           source_event_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`),
    get: raw.prepare(`${SELECT} WHERE x.id = ?`),
    listAll: raw.prepare(`${SELECT} ORDER BY x.created_at DESC, x.rowid DESC`),
    listStatus: raw.prepare(`${SELECT} WHERE x.status = ? ORDER BY x.created_at DESC, x.rowid DESC`),
    active: raw.prepare(`${SELECT} WHERE x.status = 'approved' AND (x.expires_at IS NULL OR x.expires_at > ?) ORDER BY x.created_at`),
    transition: raw.prepare(`UPDATE exceptions SET status = ?, reviewed_by = ?, review_note = ?, reviewed_at = ?
                             WHERE id = ? AND status = ?`),
  };
  return {
    STATUSES,
    create({ ruleId, scope = {}, reason, requestedBy, sourceEventId = null, expiresAt = null }) {
      const id = newId('exc_');
      stmts.insert.run(id, Number(ruleId), scope.pathPrefix ?? null, scope.location ?? null, scope.method ?? null,
        String(reason), requestedBy, sourceEventId, nowIso(clock), expiresAt);
      return mapException(stmts.get.get(id));
    },
    get(id) { return mapException(stmts.get.get(String(id))); },
    list({ status } = {}) {
      return (status ? stmts.listStatus.all(String(status)) : stmts.listAll.all()).map(mapException);
    },
    listActive(atMs) {
      const at = new Date(atMs === undefined ? clock() : atMs).toISOString();
      return stmts.active.all(at).map((r) => toEngineException(mapException(r)));
    },
    transition(id, from, to, reviewerId, note = null) {
      if (!STATUSES.includes(to)) throw new Error('invalid status');
      // the status in the where clause stops two reviewers both winning
      const changed = stmts.transition.run(to, reviewerId, note, nowIso(clock), String(id), from).changes;
      return changed ? mapException(stmts.get.get(String(id))) : null;
    },
  };
}

module.exports = { createExceptionsRepository, toEngineException, STATUSES };
