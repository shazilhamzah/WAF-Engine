'use strict';
/** Engine configuration versions. The row with the highest version is the active configuration. */
const { nowIso, parseJson } = require('../util');

function mapConfig(row) {
  if (!row) return null;
  return {
    version: row.version,
    config: parseJson(row.config_json, null),
    changedBy: row.changed_by_name || (row.changed_by ? null : 'system'),
    changedAt: row.changed_at,
    reason: row.reason,
  };
}

function createConfigRepository({ raw, clock, transaction }) {
  const SELECT = `SELECT c.*, u.username AS changed_by_name FROM config_versions c LEFT JOIN users u ON u.id = c.changed_by`;
  const stmts = {
    latest: raw.prepare(`${SELECT} ORDER BY c.version DESC LIMIT 1`),
    get: raw.prepare(`${SELECT} WHERE c.version = ?`),
    history: raw.prepare(`${SELECT} ORDER BY c.version DESC LIMIT ?`),
    maxVersion: raw.prepare('SELECT MAX(version) AS v FROM config_versions'),
    insert: raw.prepare('INSERT INTO config_versions (version, config_json, changed_by, changed_at, reason) VALUES (?, ?, ?, ?, ?)'),
  };
  return {
    latest() { return mapConfig(stmts.latest.get()); },
    get(version) { return mapConfig(stmts.get.get(Number(version))); },
    history(limit = 100) { return stmts.history.all(Math.min(Math.max(Number(limit) || 100, 1), 1000)).map(mapConfig); },
    /** Appends a new version; returns the stored record. */
    append(config, userId = null, reason = '') {
      return transaction(() => {
        const version = (stmts.maxVersion.get().v || 0) + 1;
        stmts.insert.run(version, JSON.stringify(config), userId, nowIso(clock), String(reason || ''));
        return mapConfig(stmts.get.get(version));
      });
    },
  };
}

module.exports = { createConfigRepository };
