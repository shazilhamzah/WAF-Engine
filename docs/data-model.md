# WAF Studio — Data Model

Owner: Shazil (A). Implements contract §4 (`docs/02-architecture.md`). Code: `src/db/`.

The repository is SQLite through Node's built-in `node:sqlite` (`DatabaseSync`). There is no ORM and no
string-built SQL: every statement is a prepared statement with `?` parameters. All identifiers are
generated on the server (`crypto.randomUUID()` with a type prefix).

## 1. Opening the database

```js
const { openDatabase } = require('./src/db');
const db = openDatabase('data/waf-studio.db');   // or ':memory:' for tests
db.users / db.sessions / db.rules / db.configs / db.events / db.exceptions / db.audit
db.transaction(() => { ... })                     // BEGIN IMMEDIATE … COMMIT (nested calls use SAVEPOINTs)
db.close()
```

On open:

| Setting | Value | Why |
|---|---|---|
| `PRAGMA foreign_keys` | `ON` | referential integrity (sessions → users, events → users, …) |
| `PRAGMA journal_mode` | `WAL` (files only) | crash-safe writes, readers do not block the proxy |
| `PRAGMA synchronous` | `NORMAL` | safe with WAL, lower latency on the proxy path |
| `PRAGMA busy_timeout` | 5000 ms | tolerate a concurrent reader (e.g. a test opening the file) |
| `PRAGMA quick_check` | must be `ok` | a corrupt file is refused with a pointer to the recovery steps |
| file mode | `0600` (best effort on Windows) | owner-only access to the database |

### Migrations

`src/db/schema.js` holds an ordered list of migrations; the applied version is stored in
`PRAGMA user_version`. Each migration runs in its own transaction. A database whose `user_version` is newer
than the code is refused (prevents an old build from corrupting a newer schema). Shipped migrations are never
edited — new ones are appended.

| Version | Content |
|---|---|
| 1 | All tables, indexes and the audit-log triggers below |

## 2. Tables

All tables are `STRICT` (SQLite enforces column types). Timestamps are ISO-8601 UTC strings
(`2026-10-19T10:00:00.000Z`), which sort correctly as text.

### `users`

| Column | Type | Constraints / notes |
|---|---|---|
| `id` | TEXT | PK, `usr_<uuid>` |
| `username` | TEXT | UNIQUE, `COLLATE NOCASE`, 3–32 chars (API also restricts to `[A-Za-z0-9_.-]`) |
| `password_hash` | TEXT | `scrypt$N$r$p$salt$key` — never returned by any API |
| `role` | TEXT | CHECK `admin` / `operator` / `viewer` |
| `disabled` | INTEGER | 0/1 |
| `failed_attempts` | INTEGER | ≥ 0, informational counter |
| `locked_until` | TEXT | ISO or NULL; persisted so a lockout survives restarts |
| `created_at`, `updated_at` | TEXT | |

### `sessions`

| Column | Type | Constraints / notes |
|---|---|---|
| `token_hash` | TEXT | PK, exactly 64 hex chars = SHA-256 of the cookie token (raw token never stored) |
| `user_id` | TEXT | FK → `users.id` `ON DELETE CASCADE` |
| `csrf_token` | TEXT | synchronizer token for this session |
| `client_id` | TEXT | pseudonymous client at login (`c_…`) |
| `created_at`, `last_seen_at`, `expires_at` | TEXT | idle = `last_seen_at + 30 min`, absolute = `expires_at` (`created_at + 8 h`) |

Indexes: `user_id`, `expires_at`.

### `rules` and `rule_versions`

`rules` holds the current state of each DSL rule; `rule_versions` is the immutable change history (one row per
create/update/enable/disable/delete). Versions keep increasing across delete + re-create of the same id.

| `rules` column | Notes |
|---|---|
| `id` INTEGER PK | DSL rule id, CHECK 1000–999999 |
| `name`, `source` | name from the compiled rule; full DSL source |
| `enabled` | 0/1 — disabled rules are not compiled into the running engine |
| `version` | current version number |
| `severity`, `category` | copied from the rule metadata for listing/filtering |
| `updated_at`, `updated_by` | `updated_by` FK → users (NULL = system/seed) |

| `rule_versions` column | Notes |
|---|---|
| `seq` INTEGER PK AUTOINCREMENT | |
| `rule_id`, `version` | UNIQUE (`rule_id`, `version`) |
| `source`, `enabled` | snapshot after the change |
| `changed_by`, `changed_at` | FK → users |
| `change` | CHECK `create` / `update` / `enable` / `disable` / `delete` |

### `config_versions`

| Column | Notes |
|---|---|
| `version` INTEGER PK | 1, 2, 3 … — the highest is the active configuration |
| `config_json` | normalized `EngineConfig` (CHECK `json_valid`) |
| `changed_by`, `changed_at`, `reason` | `changed_by` NULL = system default |

### `events`

| Column | Notes |
|---|---|
| `id` | PK `evt_<uuid>` |
| `ts` | ISO time |
| `source` | CHECK `proxy` / `console` / `import` / `replay` |
| `label` | ≤ 200 chars, console/import only |
| `client_id` | HMAC pseudonym `c_…` — never the IP |
| `method`, `path` | from the engine's sanitized request summary (path **without** the query string) |
| `verdict` | CHECK `allow` / `flag` / `block` |
| `action` | CHECK `allowed` / `blocked` / `logged` |
| `score`, `mode` | |
| `matched_rule_ids` | JSON array of active (non-suppressed) rule ids |
| `categories` | JSON array of matched categories (dashboard `byCategory`) |
| `decision_json` | the full engine Decision (sanitized by the engine: ≤120-char redacted excerpts) |
| `sample_json` | console/import/replay only: the **redacted** Sample (enables replay); NULL for proxy events |
| `ruleset_version`, `config_version` | state the decision was made with (traceability) |
| `latency_ms` | engine processing time |
| `submitted_by` | FK → users (console/import/replay) |
| `replay_of` | FK → events `ON DELETE SET NULL` |

Indexes: `ts`, (`verdict`,`ts`), (`action`,`ts`), (`source`,`ts`), `replay_of`.

### `exceptions`

| Column | Notes |
|---|---|
| `id` | PK `exc_<uuid>` |
| `rule_id` | CHECK 1000–999999 |
| `path_prefix`, `location`, `method` | scope (NULL = any); the API requires at least one non-NULL field |
| `reason`, `review_note` | |
| `status` | CHECK `pending` / `approved` / `rejected` / `revoked` |
| `requested_by`, `reviewed_by` | FK → users |
| `source_event_id` | FK → events `ON DELETE SET NULL` |
| `created_at`, `reviewed_at`, `expires_at` | `expires_at` NULL = no expiry |
| table CHECK | `status = 'approved'` ⇒ `reviewed_by IS NOT NULL AND reviewed_by <> requested_by` — separation of duties is enforced by the storage layer as well as the API |

State machine: `pending → approved | rejected`, `approved → revoked`. Transitions are conditional updates
(`… WHERE id = ? AND status = ?`) so two admins cannot both act on the same request.

### `audit_log` (append-only, hash-chained)

| Column | Notes |
|---|---|
| `seq` INTEGER PK AUTOINCREMENT | gap-free sequence (checked by verification) |
| `id` | UNIQUE `aud_<uuid>` |
| `ts` | |
| `actor_id`, `actor_name`, `actor_role` | `actor_name` is `anonymous` / `system` when there is no user |
| `action` | e.g. `auth.login.failure`, `config.update` (list in contract §4.1) |
| `target_type`, `target_id` | e.g. `config` / `8`, `exception` / `exc_…` |
| `outcome` | CHECK `success` / `failure` / `denied` |
| `client_id` | pseudonym, never the IP |
| `details_json` | redacted, ≤ 8 KB |
| `prev_hash`, `hash` | 64-hex SHA-256; `hash` UNIQUE |

Triggers `audit_log_no_update` / `audit_log_no_delete` execute `RAISE(ABORT, 'audit_log is append-only')`.

Hash chain:

```
hash = SHA-256( prevHash + canonicalJSON({ seq, id, ts, actorId, actorName, actorRole, action, targetType,
                                           targetId, outcome, clientId, details, prevHash }) )
```

`canonicalJSON` sorts object keys recursively, so the hash does not depend on property order. The first entry
uses `prevHash = "0" × 64`. `db.audit.verifyChain()` walks the log in `seq` order and returns
`{ ok, checked, brokenAt }` — `brokenAt` is the first `seq` whose hash, link or sequence number is wrong.

## 3. Entity relationships (text ER diagram)

```
users 1───* sessions            (ON DELETE CASCADE)
users 1───* rules.updated_by
users 1───* rule_versions.changed_by
users 1───* config_versions.changed_by
users 1───* events.submitted_by
users 1───* exceptions.requested_by
users 1───* exceptions.reviewed_by
rules 1┄┄┄* rule_versions       (logical link by rule_id; history outlives a deleted rule)
rules 1┄┄┄* exceptions          (logical link by rule_id)
events 1──* events.replay_of    (ON DELETE SET NULL)
events 1──* exceptions.source_event_id (ON DELETE SET NULL)
audit_log                       (stand-alone; refers to other records only by target_type/target_id text)
```

## 4. Repository API (used by the API, the proxy, reports and the evaluation harness)

| Repository | Main methods |
|---|---|
| `db.users` | `create({username,passwordHash,role})`, `findById`, `findByUsername`, `findCredentials` (internal), `list`, `count`, `countActiveAdmins`, `setPasswordHash`, `setRole`, `setDisabled`, `setFailureState`, `resetFailures` |
| `db.sessions` | `create`, `get(tokenHash)`, `touch`, `delete`, `deleteForUser`, `deleteExpired`, `countForUser` |
| `db.rules` | `list`, `get`, `count`, `listForCompile`, `create(meta, userId)`, `update(id, patch, userId, change)`, `delete(id, userId)`, `history(id)` |
| `db.configs` | `latest`, `get(version)`, `history(limit)`, `append(config, userId, reason)` |
| `db.events` | `record({source, decision, label, clientId, sample, latencyMs, submittedBy, replayOf})`, `get(id)` (full Event), `getSummary(id)`, `list(filters)` → `{items, total}` (summaries; `full: true` for full Events), `recentWithRule(ruleId)`, `stats({hours})`, `prune(maxRows)`, `count` |
| `db.exceptions` | `create`, `get`, `list({status})`, `listActive(atMs)` (engine shape, approved + unexpired), `transition(id, from, to, reviewerId, note)` |
| `db.audit` | `append(entry)`, `get(seq)`, `list(filters)` → `{items, total}`, `verifyChain()`, `count` |

`db.events.list` filters: `verdict`, `action`, `source`, `ruleId`, `q` (substring of path/label; LIKE wildcards
escaped; also exact id/method), `from`, `to`, `ids` (array, ≤ 200), `limit` (1–200, clamped), `offset`.
`db.audit.list` filters: `action` (exact or dotted family prefix, e.g. `auth` or `auth.login`), `actor`, `outcome`,
`from`, `to`, `limit` (≤ 200), `offset`.

## 5. Data minimization and retention

| Data | What is kept | What is never kept |
|---|---|---|
| Client identity | `c_` + first 16 hex of HMAC-SHA256(secret, IP) | raw IP addresses |
| Proxy traffic | engine Decision: method, path (no query string), parameter **names**, ≤ 120-char redacted excerpts | request bodies, header values, cookies, query values outside excerpts |
| Console samples | redacted Sample (authorization/cookie/API-key headers and password-/token-like fields masked) | the secrets themselves |
| Credentials | scrypt hash | passwords (plain or reversible) |
| Sessions | SHA-256 of the token | the cookie value |
| Audit details | redacted metadata (≤ 8 KB) | passwords (including attempted ones), tokens, secrets |

Retention: events are capped at the newest **100 000** rows (`db.events.prune`, run at start-up and every 1 000
proxied requests); expired sessions are purged at every login. The audit log is never pruned (append-only by
design); `npm run reset -- --yes` deletes the whole database for a fresh start (see `docs/security-controls.md`).

Note: because samples are stored redacted, a replay of a sample whose attack was inside a masked field (e.g. a
`password=` parameter) re-runs on the masked value and may not reproduce the original decision. This is the
deliberate privacy trade-off of contract §4.2.
