'use strict';
/**
 * Rules (current state) + rule_versions (immutable change history, one row per change).
 * Versions keep increasing across delete/re-create of the same DSL id so history stays unambiguous.
 */
const { nowIso, toBool } = require('../util');

function mapRule(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    source: row.source,
    enabled: toBool(row.enabled),
    version: row.version,
    severity: row.severity || null,
    category: row.category || null,
    updatedAt: row.updated_at,
    updatedBy: row.updated_by_name || null,
  };
}

function mapVersion(row) {
  return {
    ruleId: row.rule_id,
    version: row.version,
    source: row.source,
    enabled: toBool(row.enabled),
    changedBy: row.changed_by_name || null,
    changedAt: row.changed_at,
    change: row.change,
  };
}

function createRulesRepository({ raw, clock, transaction }) {
  const SELECT = `SELECT r.*, u.username AS updated_by_name FROM rules r LEFT JOIN users u ON u.id = r.updated_by`;
  const stmts = {
    list: raw.prepare(`${SELECT} ORDER BY r.id`),
    get: raw.prepare(`${SELECT} WHERE r.id = ?`),
    count: raw.prepare('SELECT COUNT(*) AS n FROM rules'),
    maxVersion: raw.prepare('SELECT MAX(version) AS v FROM rule_versions WHERE rule_id = ?'),
    insert: raw.prepare(`INSERT INTO rules (id, name, source, enabled, version, severity, category, updated_at, updated_by)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    update: raw.prepare(`UPDATE rules SET name = ?, source = ?, enabled = ?, version = ?, severity = ?, category = ?,
                         updated_at = ?, updated_by = ? WHERE id = ?`),
    del: raw.prepare('DELETE FROM rules WHERE id = ?'),
    insertVersion: raw.prepare(`INSERT INTO rule_versions (rule_id, version, source, enabled, changed_by, changed_at, change)
                                VALUES (?, ?, ?, ?, ?, ?, ?)`),
    history: raw.prepare(`SELECT v.*, u.username AS changed_by_name FROM rule_versions v
                          LEFT JOIN users u ON u.id = v.changed_by WHERE v.rule_id = ? ORDER BY v.version DESC`),
  };

  function nextVersion(id) {
    const row = stmts.maxVersion.get(id);
    return (row && row.v ? row.v : 0) + 1;
  }

  return {
    list() { return stmts.list.all().map(mapRule); },
    get(id) { return mapRule(stmts.get.get(Number(id))); },
    count() { return stmts.count.get().n; },
    /** Records for engine.compileRules (contract §3). */
    listForCompile() {
      return stmts.list.all().map((r) => ({ id: r.id, source: r.source, enabled: toBool(r.enabled), version: r.version }));
    },
    create({ id, name, source, enabled = true, severity = null, category = null }, userId = null) {
      return transaction(() => {
        const version = nextVersion(id);
        const ts = nowIso(clock);
        stmts.insert.run(id, name, source, enabled ? 1 : 0, version, severity, category, ts, userId);
        stmts.insertVersion.run(id, version, source, enabled ? 1 : 0, userId, ts, 'create');
        return mapRule(stmts.get.get(id));
      });
    },
    /**
     * Applies a change. `change` is 'update' | 'enable' | 'disable'.
     * @returns updated rule or null when the rule does not exist
     */
    update(id, patch, userId = null, change = 'update') {
      return transaction(() => {
        const current = stmts.get.get(Number(id));
        if (!current) return null;
        const next = {
          name: patch.name ?? current.name,
          source: patch.source ?? current.source,
          enabled: patch.enabled === undefined ? toBool(current.enabled) : Boolean(patch.enabled),
          severity: patch.severity === undefined ? current.severity : patch.severity,
          category: patch.category === undefined ? current.category : patch.category,
        };
        const version = nextVersion(current.id);
        const ts = nowIso(clock);
        stmts.update.run(next.name, next.source, next.enabled ? 1 : 0, version, next.severity, next.category, ts, userId, current.id);
        stmts.insertVersion.run(current.id, version, next.source, next.enabled ? 1 : 0, userId, ts, change);
        return mapRule(stmts.get.get(current.id));
      });
    },
    /** Deletes the rule, keeping its history (a final 'delete' version row). */
    delete(id, userId = null) {
      return transaction(() => {
        const current = stmts.get.get(Number(id));
        if (!current) return false;
        stmts.insertVersion.run(current.id, nextVersion(current.id), current.source, 0, userId, nowIso(clock), 'delete');
        stmts.del.run(current.id);
        return true;
      });
    },
    history(id) { return stmts.history.all(Number(id)).map(mapVersion); },
  };
}

module.exports = { createRulesRepository };
