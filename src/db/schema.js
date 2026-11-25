'use strict';
/**
 * Schema migrations, applied in order and tracked with `PRAGMA user_version` (contract §4).
 * Each migration runs inside a transaction. Never edit a shipped migration: append a new one.
 */

const MIGRATIONS = [
  {
    version: 1,
    name: 'initial schema',
    sql: `
CREATE TABLE users (
  id               TEXT PRIMARY KEY CHECK (id LIKE 'usr\\_%' ESCAPE '\\'),
  username         TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 32),
  password_hash    TEXT NOT NULL,
  role             TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
  disabled         INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
  failed_attempts  INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until     TEXT,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
) STRICT;

CREATE TABLE sessions (
  token_hash    TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token    TEXT NOT NULL,
  client_id     TEXT,
  created_at    TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL,
  expires_at    TEXT NOT NULL
) STRICT;
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE rules (
  id          INTEGER PRIMARY KEY CHECK (id BETWEEN 1000 AND 999999),
  name        TEXT NOT NULL,
  source      TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  version     INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  severity    TEXT,
  category    TEXT,
  updated_at  TEXT NOT NULL,
  updated_by  TEXT REFERENCES users(id)
) STRICT;

CREATE TABLE rule_versions (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id     INTEGER NOT NULL,
  version     INTEGER NOT NULL,
  source      TEXT NOT NULL,
  enabled     INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  changed_by  TEXT REFERENCES users(id),
  changed_at  TEXT NOT NULL,
  change      TEXT NOT NULL CHECK (change IN ('create', 'update', 'enable', 'disable', 'delete')),
  UNIQUE (rule_id, version)
) STRICT;

CREATE TABLE config_versions (
  version      INTEGER PRIMARY KEY CHECK (version >= 1),
  config_json  TEXT NOT NULL CHECK (json_valid(config_json)),
  changed_by   TEXT REFERENCES users(id),
  changed_at   TEXT NOT NULL,
  reason       TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE events (
  id                TEXT PRIMARY KEY CHECK (id LIKE 'evt\\_%' ESCAPE '\\'),
  ts                TEXT NOT NULL,
  source            TEXT NOT NULL CHECK (source IN ('proxy', 'console', 'import', 'replay')),
  label             TEXT,
  client_id         TEXT,
  method            TEXT,
  path              TEXT,
  verdict           TEXT NOT NULL CHECK (verdict IN ('allow', 'flag', 'block')),
  action            TEXT NOT NULL CHECK (action IN ('allowed', 'blocked', 'logged')),
  score             REAL NOT NULL DEFAULT 0,
  mode              TEXT,
  matched_rule_ids  TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(matched_rule_ids)),
  categories        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(categories)),
  decision_json     TEXT NOT NULL CHECK (json_valid(decision_json)),
  sample_json       TEXT CHECK (sample_json IS NULL OR json_valid(sample_json)),
  ruleset_version   TEXT,
  config_version    INTEGER,
  latency_ms        REAL,
  submitted_by      TEXT REFERENCES users(id),
  replay_of         TEXT REFERENCES events(id) ON DELETE SET NULL
) STRICT;
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_verdict_ts ON events(verdict, ts);
CREATE INDEX idx_events_action_ts ON events(action, ts);
CREATE INDEX idx_events_source_ts ON events(source, ts);
CREATE INDEX idx_events_replay_of ON events(replay_of);

CREATE TABLE exceptions (
  id               TEXT PRIMARY KEY CHECK (id LIKE 'exc\\_%' ESCAPE '\\'),
  rule_id          INTEGER NOT NULL CHECK (rule_id BETWEEN 1000 AND 999999),
  path_prefix      TEXT,
  location         TEXT,
  method           TEXT,
  reason           TEXT NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
  requested_by     TEXT NOT NULL REFERENCES users(id),
  reviewed_by      TEXT REFERENCES users(id),
  review_note      TEXT,
  source_event_id  TEXT REFERENCES events(id) ON DELETE SET NULL,
  created_at       TEXT NOT NULL,
  reviewed_at      TEXT,
  expires_at       TEXT,
  -- separation of duties enforced again at the storage layer
  CHECK (status NOT IN ('approved') OR (reviewed_by IS NOT NULL AND reviewed_by <> requested_by))
) STRICT;
CREATE INDEX idx_exceptions_status ON exceptions(status);
CREATE INDEX idx_exceptions_rule ON exceptions(rule_id);

CREATE TABLE audit_log (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  id            TEXT NOT NULL UNIQUE CHECK (id LIKE 'aud\\_%' ESCAPE '\\'),
  ts            TEXT NOT NULL,
  actor_id      TEXT,
  actor_name    TEXT NOT NULL,
  actor_role    TEXT,
  action        TEXT NOT NULL,
  target_type   TEXT,
  target_id     TEXT,
  outcome       TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  client_id     TEXT,
  details_json  TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json)),
  prev_hash     TEXT NOT NULL CHECK (length(prev_hash) = 64),
  hash          TEXT NOT NULL UNIQUE CHECK (length(hash) = 64)
) STRICT;
CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_actor ON audit_log(actor_name);

-- Append-only audit log: any UPDATE or DELETE aborts the statement.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only');
END;
`,
  },
];

const LATEST_VERSION = MIGRATIONS[MIGRATIONS.length - 1].version;

/**
 * Applies pending migrations to a DatabaseSync instance.
 * @returns {{ from: number, to: number }}
 */
function migrate(raw) {
  const from = raw.prepare('PRAGMA user_version').get().user_version;
  if (from > LATEST_VERSION) {
    throw new Error(`Database schema version ${from} is newer than this build supports (${LATEST_VERSION})`);
  }
  for (const m of MIGRATIONS) {
    if (m.version <= from) continue;
    raw.exec('BEGIN IMMEDIATE');
    try {
      raw.exec(m.sql);
      raw.exec(`PRAGMA user_version = ${Number(m.version)}`);
      raw.exec('COMMIT');
    } catch (err) {
      raw.exec('ROLLBACK');
      throw err;
    }
  }
  return { from, to: LATEST_VERSION };
}

module.exports = { MIGRATIONS, LATEST_VERSION, migrate };
