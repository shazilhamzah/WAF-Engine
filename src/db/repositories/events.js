'use strict';
const { newId, nowIso, parseJson, escapeLike } = require('../util');

const MAX_LIMIT = 200;
const SUMMARY_PATH_MAX = 200;
const SOURCES = Object.freeze(['proxy', 'console', 'import', 'replay']);
const VERDICTS = Object.freeze(['allow', 'flag', 'block']);
const ACTIONS = Object.freeze(['allowed', 'blocked', 'logged']);

function truncate(s, n) {
  if (s === null || s === undefined) return null;
  const str = String(s);
  return str.length > n ? str.slice(0, n - 1) + '…' : str;
}

function mapSummary(row) {
  return {
    id: row.id,
    ts: row.ts,
    source: row.source,
    label: row.label ?? null,
    method: row.method ?? null,
    path: truncate(row.path, SUMMARY_PATH_MAX),
    verdict: row.verdict,
    action: row.action,
    score: row.score,
    mode: row.mode ?? null,
    matchedRuleIds: parseJson(row.matched_rule_ids, []),
    latencyMs: row.latency_ms ?? null,
  };
}

function mapEvent(row) {
  if (!row) return null;
  return {
    ...mapSummary(row),
    decision: parseJson(row.decision_json, null),
    sample: parseJson(row.sample_json, null),
    rulesetVersion: row.ruleset_version ?? null,
    configVersion: row.config_version ?? null,
    clientId: row.client_id ?? null,
    submittedBy: row.submitted_by_name ?? null,
    replayOf: row.replay_of ?? null,
  };
}

function columnsFromDecision(decision, fallback = {}) {
  const d = decision || {};
  const active = Array.isArray(d.matches) ? d.matches.filter((m) => m && !m.suppressedBy) : [];
  const ruleIds = [...new Set(active.map((m) => Number(m.ruleId)).filter(Number.isFinite))];
  const categories = [...new Set(active.map((m) => m.category).filter((c) => typeof c === 'string' && c))];
  const req = d.request || {};
  let pathOnly = typeof req.path === 'string' ? req.path : null;
  if (pathOnly === null && typeof fallback.url === 'string') pathOnly = fallback.url.split('?')[0];
  const verdict = VERDICTS.includes(d.verdict) ? d.verdict : 'block';
  const action = ACTIONS.includes(d.action) ? d.action : (verdict === 'block' ? 'blocked' : 'allowed');
  return {
    method: truncate(req.method || fallback.method || null, 16),
    path: truncate(pathOnly, 2048),
    verdict,
    action,
    score: d.score && Number.isFinite(Number(d.score.total)) ? Number(d.score.total) : 0,
    mode: d.mode || null,
    matchedRuleIds: ruleIds,
    categories,
    rulesetVersion: (d.engine && d.engine.rulesetVersion) || fallback.rulesetVersion || null,
    configVersion: (d.engine && Number.isInteger(d.engine.configVersion)) ? d.engine.configVersion : (fallback.configVersion ?? null),
  };
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}
const round3 = (n) => Math.round(n * 1000) / 1000;

function createEventsRepository({ raw, clock }) {
  const SELECT_FULL = `SELECT e.*, u.username AS submitted_by_name FROM events e LEFT JOIN users u ON u.id = e.submitted_by`;
  const stmts = {
    insert: raw.prepare(`INSERT INTO events (id, ts, source, label, client_id, method, path, verdict, action, score, mode,
                           matched_rule_ids, categories, decision_json, sample_json, ruleset_version, config_version,
                           latency_ms, submitted_by, replay_of)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
    get: raw.prepare(`${SELECT_FULL} WHERE e.id = ?`),
    count: raw.prepare('SELECT COUNT(*) AS n FROM events'),
    prune: raw.prepare('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts DESC, rowid DESC LIMIT -1 OFFSET ?)'),
    withRule: raw.prepare(`${SELECT_FULL} WHERE EXISTS (SELECT 1 FROM json_each(e.matched_rule_ids) j WHERE j.value = ?)
                           ORDER BY e.ts DESC, e.rowid DESC LIMIT ?`),
  };

  function buildWhere(f = {}) {
    const where = [];
    const params = [];
    if (f.verdict) { where.push('e.verdict = ?'); params.push(String(f.verdict)); }
    if (f.action) { where.push('e.action = ?'); params.push(String(f.action)); }
    if (f.source) { where.push('e.source = ?'); params.push(String(f.source)); }
    if (f.ruleId !== undefined && f.ruleId !== null && f.ruleId !== '') {
      where.push('EXISTS (SELECT 1 FROM json_each(e.matched_rule_ids) j WHERE j.value = ?)');
      params.push(Number(f.ruleId));
    }
    if (f.q) {
      const like = `%${escapeLike(String(f.q))}%`;
      where.push("(e.path LIKE ? ESCAPE '\\' OR e.label LIKE ? ESCAPE '\\' OR e.id = ? OR e.method = ?)");
      params.push(like, like, String(f.q), String(f.q).toUpperCase());
    }
    if (f.from) { where.push('e.ts >= ?'); params.push(String(f.from)); }
    if (f.to) { where.push('e.ts <= ?'); params.push(String(f.to)); }
    if (Array.isArray(f.ids)) {
      const ids = f.ids.slice(0, MAX_LIMIT).map(String);
      if (ids.length === 0) where.push('0');
      else { where.push(`e.id IN (${ids.map(() => '?').join(',')})`); params.push(...ids); }
    }
    return { sql: where.length ? ' WHERE ' + where.join(' AND ') : '', params };
  }

  return {
    SOURCES, VERDICTS, ACTIONS, MAX_LIMIT,
    record({ source, decision, label = null, clientId = null, sample = null, latencyMs = null, submittedBy = null, replayOf = null, fallback = {} }) {
      if (!SOURCES.includes(source)) throw new Error('invalid event source');
      const c = columnsFromDecision(decision, fallback);
      const id = newId('evt_');
      stmts.insert.run(
        id, nowIso(clock), source, truncate(label, 200), clientId, c.method, c.path, c.verdict, c.action, c.score, c.mode,
        JSON.stringify(c.matchedRuleIds), JSON.stringify(c.categories), JSON.stringify(decision || {}),
        sample ? JSON.stringify(sample) : null, c.rulesetVersion, c.configVersion,
        Number.isFinite(latencyMs) ? round3(latencyMs) : null, submittedBy, replayOf,
      );
      return mapEvent(stmts.get.get(id));
    },
    get(id) { return mapEvent(stmts.get.get(String(id))); },
    getSummary(id) { const row = stmts.get.get(String(id)); return row ? mapSummary(row) : null; },
    count() { return stmts.count.get().n; },
    list(filters = {}) {
      const { sql, params } = buildWhere(filters);
      const limit = Math.min(Math.max(parseInt(filters.limit, 10) || 50, 1), MAX_LIMIT);
      const offset = Math.max(parseInt(filters.offset, 10) || 0, 0);
      const total = raw.prepare(`SELECT COUNT(*) AS n FROM events e${sql}`).get(...params).n;
      const rows = raw.prepare(`${SELECT_FULL}${sql} ORDER BY e.ts DESC, e.rowid DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
      return { items: rows.map(filters.full ? mapEvent : mapSummary), total };
    },
    recentWithRule(ruleId, limit = 1000) {
      return stmts.withRule.all(Number(ruleId), Math.min(Math.max(Number(limit) || 1000, 1), 5000)).map(mapEvent);
    },
    stats({ hours = 24 } = {}) {
      const now = clock();
      const h = Math.min(Math.max(parseInt(hours, 10) || 24, 1), 720);
      const since = new Date(now - h * 3600_000).toISOString();
      const t = raw.prepare(`SELECT COUNT(*) AS requests,
              SUM(action = 'allowed') AS allowed, SUM(action = 'logged') AS logged, SUM(action = 'blocked') AS blocked,
              SUM(verdict = 'flag') AS flagged, AVG(latency_ms) AS avgMs
            FROM events WHERE ts >= ?`).get(since);
      const byCategory = {};
      for (const r of raw.prepare(`SELECT j.value AS category, COUNT(*) AS n FROM events e, json_each(e.categories) j
                                   WHERE e.ts >= ? GROUP BY j.value ORDER BY n DESC`).all(since)) {
        byCategory[r.category] = r.n;
      }
      const topRules = raw.prepare(`SELECT j.value AS ruleId, COUNT(*) AS count, r.name AS name
            FROM events e, json_each(e.matched_rule_ids) j LEFT JOIN rules r ON r.id = j.value
            WHERE e.ts >= ? GROUP BY j.value ORDER BY count DESC, j.value ASC LIMIT 10`).all(since)
        .map((r) => ({ ruleId: Number(r.ruleId), name: r.name || `Rule ${r.ruleId}`, count: r.count }));
      const lat = raw.prepare('SELECT latency_ms AS v FROM events WHERE ts >= ? AND latency_ms IS NOT NULL ORDER BY latency_ms')
        .all(since).map((r) => r.v);
      const buckets = new Map();
      const startHour = Math.floor((now - (h - 1) * 3600_000) / 3600_000) * 3600_000;
      for (let i = 0; i < h; i += 1) {
        const hour = new Date(startHour + i * 3600_000).toISOString();
        buckets.set(hour.slice(0, 13), { hour, allowed: 0, logged: 0, blocked: 0 });
      }
      for (const r of raw.prepare(`SELECT substr(ts, 1, 13) AS hk, action, COUNT(*) AS n FROM events WHERE ts >= ? GROUP BY hk, action`).all(since)) {
        const b = buckets.get(r.hk);
        if (b && r.action in b) b[r.action] += r.n;
      }
      return {
        hours: h,
        totals: {
          requests: t.requests || 0, allowed: t.allowed || 0, logged: t.logged || 0,
          blocked: t.blocked || 0, flagged: t.flagged || 0,
        },
        byCategory,
        topRules,
        latency: { avgMs: round3(t.avgMs || 0), p50Ms: round3(percentile(lat, 50)), p95Ms: round3(percentile(lat, 95)) },
        timeline: [...buckets.values()],
      };
    },
    prune(maxRows) {
      const n = Math.max(parseInt(maxRows, 10) || 0, 0);
      if (!n) return 0;
      return stmts.prune.run(n).changes;
    },
  };
}

module.exports = { createEventsRepository, columnsFromDecision, mapSummary, SOURCES, VERDICTS, ACTIONS, MAX_LIMIT };
