'use strict';
const { newId, nowIso, canonicalJson, sha256Hex, parseJson, escapeLike } = require('../util');
const { redact } = require('../../services/redact');

const GENESIS_HASH = '0'.repeat(64);
const OUTCOMES = Object.freeze(['success', 'failure', 'denied']);
const MAX_LIMIT = 200;
const MAX_DETAILS_BYTES = 8192;

function entryFromRow(row) {
  return {
    seq: row.seq,
    id: row.id,
    ts: row.ts,
    actorId: row.actor_id ?? null,
    actorName: row.actor_name,
    actorRole: row.actor_role ?? null,
    action: row.action,
    targetType: row.target_type ?? null,
    targetId: row.target_id ?? null,
    outcome: row.outcome,
    clientId: row.client_id ?? null,
    details: parseJson(row.details_json, {}),
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

function computeHash(entry) {
  const { hash, ...rest } = entry; // eslint-disable-line no-unused-vars
  const body = {
    seq: rest.seq, id: rest.id, ts: rest.ts, actorId: rest.actorId ?? null, actorName: rest.actorName,
    actorRole: rest.actorRole ?? null, action: rest.action, targetType: rest.targetType ?? null,
    targetId: rest.targetId ?? null, outcome: rest.outcome, clientId: rest.clientId ?? null,
    details: rest.details ?? {}, prevHash: rest.prevHash,
  };
  return sha256Hex(rest.prevHash + canonicalJson(body));
}

function sanitizeDetails(details) {
  let d = redact(details && typeof details === 'object' ? details : {});
  // round trip through json so the hash covers exactly what is stored
  let json = JSON.stringify(d);
  if (json.length > MAX_DETAILS_BYTES) {
    d = { truncated: true, note: 'details exceeded 8 KB and were dropped' };
    json = JSON.stringify(d);
  }
  return JSON.parse(json);
}

function createAuditRepository({ raw, clock, transaction }) {
  const stmts = {
    last: raw.prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1'),
    insert: raw.prepare(`INSERT INTO audit_log (seq, id, ts, actor_id, actor_name, actor_role, action, target_type, target_id,
                           outcome, client_id, details_json, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    get: raw.prepare('SELECT * FROM audit_log WHERE seq = ?'),
    count: raw.prepare('SELECT COUNT(*) AS n FROM audit_log'),
    iterate: raw.prepare('SELECT * FROM audit_log ORDER BY seq ASC'),
  };

  return {
    GENESIS_HASH, OUTCOMES, MAX_LIMIT,
    append({ actorId = null, actorName, actorRole = null, action, targetType = null, targetId = null,
      outcome = 'success', clientId = null, details = {} }) {
      if (!action || typeof action !== 'string') throw new Error('audit action required');
      if (!OUTCOMES.includes(outcome)) throw new Error('invalid audit outcome');
      return transaction(() => {
        const last = stmts.last.get();
        const entry = {
          seq: last ? last.seq + 1 : 1,
          id: newId('aud_'),
          ts: nowIso(clock),
          actorId: actorId ?? null,
          actorName: String(actorName || (actorId ? 'unknown' : 'anonymous')).slice(0, 64),
          actorRole: actorRole ?? null,
          action: action.slice(0, 64),
          targetType: targetType === null || targetType === undefined ? null : String(targetType).slice(0, 64),
          targetId: targetId === null || targetId === undefined ? null : String(targetId).slice(0, 128),
          outcome,
          clientId: clientId ?? null,
          details: sanitizeDetails(details),
          prevHash: last ? last.hash : GENESIS_HASH,
        };
        entry.hash = computeHash(entry);
        stmts.insert.run(entry.seq, entry.id, entry.ts, entry.actorId, entry.actorName, entry.actorRole, entry.action,
          entry.targetType, entry.targetId, entry.outcome, entry.clientId, JSON.stringify(entry.details), entry.prevHash, entry.hash);
        return entry;
      });
    },
    get(seq) { const r = stmts.get.get(Number(seq)); return r ? entryFromRow(r) : null; },
    count() { return stmts.count.get().n; },
    list(f = {}) {
      const where = [];
      const params = [];
      if (f.action) {
        where.push("(action = ? OR action LIKE ? ESCAPE '\\')");
        params.push(String(f.action), `${escapeLike(String(f.action))}.%`);
      }
      if (f.actor) { where.push('actor_name = ? COLLATE NOCASE'); params.push(String(f.actor)); }
      if (f.outcome) { where.push('outcome = ?'); params.push(String(f.outcome)); }
      if (f.from) { where.push('ts >= ?'); params.push(String(f.from)); }
      if (f.to) { where.push('ts <= ?'); params.push(String(f.to)); }
      const sql = where.length ? ' WHERE ' + where.join(' AND ') : '';
      const limit = Math.min(Math.max(parseInt(f.limit, 10) || 50, 1), MAX_LIMIT);
      const offset = Math.max(parseInt(f.offset, 10) || 0, 0);
      const total = raw.prepare(`SELECT COUNT(*) AS n FROM audit_log${sql}`).get(...params).n;
      const items = raw.prepare(`SELECT * FROM audit_log${sql} ORDER BY seq DESC LIMIT ? OFFSET ?`).all(...params, limit, offset)
        .map(entryFromRow);
      return { items, total };
    },
    verifyChain() {
      let prevHash = GENESIS_HASH;
      let expectedSeq = 1;
      let checked = 0;
      for (const row of stmts.iterate.iterate()) {
        const entry = entryFromRow(row);
        // a row whose details cannot be parsed counts as tampered
        const detailsOk = parseJson(row.details_json, undefined) !== undefined;
        const seqOk = entry.seq === expectedSeq;
        if (!detailsOk || !seqOk || entry.prevHash !== prevHash || computeHash(entry) !== entry.hash) {
          return { ok: false, checked, brokenAt: entry.seq };
        }
        checked += 1;
        prevHash = entry.hash;
        expectedSeq = entry.seq + 1;
      }
      return { ok: true, checked, brokenAt: null };
    },
  };
}

module.exports = { createAuditRepository, computeHash, GENESIS_HASH, OUTCOMES };
