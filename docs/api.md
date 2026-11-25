# WAF Studio — Studio API Reference

Owner: Shazil (A). Implements contract §2 and §5 (`docs/02-architecture.md`). Code: `src/api/`.

Base URL: `http://127.0.0.1:3000/api` (Studio console; bound to loopback only).

## 1. Conventions

* **JSON only.** Requests with a body must send `Content-Type: application/json` (UTF-8) → otherwise `415`.
  Body limit **256 KB** (`413`), except `POST /api/analyze` and `POST /api/import` which accept **2 MiB** so a
  1 MiB sample body fits (see §5 clarifications). Bodies must be JSON objects; unknown fields are rejected.
* **Session.** `POST /api/auth/login` sets cookie `waf_sid` (`HttpOnly; SameSite=Strict; Path=/`, plus `Secure`
  over HTTPS). Idle timeout 30 min, absolute lifetime 8 h.
* **CSRF.** Every `POST`/`PUT`/`PATCH`/`DELETE` except login must send `X-CSRF-Token: <csrfToken>` (from login or
  `GET /api/auth/me`). Missing/wrong → `403 CSRF_INVALID`. A cross-origin `Origin` header → `403 CSRF_INVALID`.
* **Host check.** Only `Host: 127.0.0.1|localhost|[::1]` (any port) is answered (DNS-rebinding defence) → else `403`.
* **Order of checks:** host → content type/body parsing → session → CSRF → role → body validation → resource
  lookup → state checks → confirmation. So an unauthenticated request always gets `401`, a wrong role always gets
  a generic `403` (and an `auth.denied` audit event) before any validation or record lookup.
* **Confirmation.** High-impact actions need `"confirm": true` → otherwise `428 CONFIRMATION_REQUIRED`.
* **Headers on every response:** `Content-Security-Policy` (contract CSP), `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`, `X-Request-Id: req_…`; `/api` responses also `Cache-Control: no-store`.
  `X-Powered-By` is disabled.
* **Query strings** use the simple parser: repeating a parameter (`?verdict=a&verdict=b`) or bracket syntax is a
  validation error. `limit` values above 200 are clamped to 200.

### Error envelope (contract §5.1)

```json
{ "error": { "code": "VALIDATION_FAILED", "message": "The request did not pass validation.",
             "details": [ { "field": "sample.path", "message": "must start with '/' and contain no whitespace" } ],
             "requestId": "req_2b0c…" } }
```

| HTTP | code | Typical cause |
|---|---|---|
| 400 | `VALIDATION_FAILED` | schema/type/size/policy failure (`details` lists fields) |
| 400 | `MALFORMED_JSON` | body is not JSON |
| 401 | `AUTH_REQUIRED` | no session cookie |
| 401 | `AUTH_INVALID` | login failed (same message for unknown user, wrong password, disabled user) |
| 401 | `SESSION_EXPIRED` | cookie present but session expired/revoked (cookie is cleared) |
| 403 | `FORBIDDEN` | role not allowed (generic), separation-of-duties violation, foreign Host |
| 403 | `CSRF_INVALID` | missing/wrong `X-CSRF-Token`, cross-origin `Origin` |
| 404 | `NOT_FOUND` | unknown id/route (forged ids never cause 500) |
| 409 | `CONFLICT` | duplicate username/rule id, wrong exception state, last active admin, replaying a proxy event |
| 409 | `IDEMPOTENCY_IN_PROGRESS` | a request with the same `Idempotency-Key` is still running (`Retry-After: 1`) |
| 413 | `PAYLOAD_TOO_LARGE` | body over the limit |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | non-JSON body or non-UTF-8 charset |
| 422 | `IDEMPOTENCY_KEY_REUSED` | an `Idempotency-Key` already used with a different body |
| 428 | `CONFIRMATION_REQUIRED` | high-impact action without `"confirm": true` |
| 429 | `RATE_LIMITED` | login throttling, analysis rate limit; `Retry-After` header + `retryAfterSeconds` (in `error` and top level) |
| 500 | `INTERNAL_ERROR` | unexpected failure — logged internally with redaction, `system.error` audited, never a stack trace |

Rejected input (`VALIDATION_FAILED`, `MALFORMED_JSON`, `PAYLOAD_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE`) is audited as
`request.rejected` (field names only, never values).

### Idempotency keys

Record-creating calls (`POST /api/rules`, `/api/exceptions`, `/api/users`, `/api/analyze`, `/api/import`,
`/api/events/:id/replay`) accept an optional `Idempotency-Key` header (8–128 of `A-Z a-z 0-9 - _`; the console
sends a UUID per submit and reuses it for every retry). A repeat with the same key, user, path and body returns
the first `2xx` response with `Idempotent-Replayed: true` and creates nothing new. The same key with a different
body is `422 IDEMPOTENCY_KEY_REUSED`; a repeat while the first is still running is `409 IDEMPOTENCY_IN_PROGRESS`.
Only successful responses are kept (in memory, 24 h, scoped per signed-in user), so a failed attempt can be
retried with the same key. Requests without the header behave exactly as before. Implementation:
`src/api/idempotency.js`; tests: `test/unit/api/idempotency.test.js`.

### Shapes

* **EventSummary** `{ id, ts, source, label, method, path (≤200), verdict, action, score, mode, matchedRuleIds, latencyMs }`
* **Event** = EventSummary + `{ decision, sample (redacted, console/import/replay only), rulesetVersion, configVersion, clientId, submittedBy (username), replayOf }`
* **Rule** `{ id, name, source, enabled, version, severity, category, updatedAt, updatedBy }`
* **RuleVersion** `{ ruleId, version, source, enabled, changedBy, changedAt, change }`
* **ExceptionRecord** `{ id, ruleId, scope: { pathPrefix, location, method }, reason, status, requestedBy, requestedById, reviewedBy, reviewedById, reviewNote, sourceEventId, createdAt, reviewedAt, expiresAt }`
* **AuditEvent** `{ seq, id, ts, actorId, actorName, actorRole, action, targetType, targetId, outcome, clientId, details, prevHash, hash }`
* **User** `{ id, username, role, disabled, lockedUntil, createdAt }` (never a password hash)

## 2. Endpoints

Roles: **A** admin, **O** operator, **V** viewer.

### Health and authentication

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/health` | public | — | `200 { status: "ok", version }` |
| `POST /api/auth/login` | public | `{ username, password }` | `200 { user: {id, username, role}, csrfToken, expiresAt }` + `Set-Cookie` |
| `POST /api/auth/logout` | any | — | `204` (idempotent; clears the cookie; CSRF required when a session exists) |
| `GET /api/auth/me` | A O V | — | `200 { user, csrfToken, expiresAt }` |
| `POST /api/auth/password` | A O V | `{ currentPassword, newPassword }` | `204` — **all sessions of the user end; sign in again** |

Login behaviour:

1. Body validation (`username` 1–64 chars, `password` 1–1024 chars).
2. Per client (pseudonymous IP): more than **20 attempts per minute** → `429`.
3. Per username: after **5 failures within 15 minutes** the name is locked for **15 minutes** → `429` even with the
   right password (`auth.lockout` audited once). Unknown names are tracked the same way (no enumeration).
4. Unknown user, wrong password and disabled account all return the same `401 AUTH_INVALID` after the same scrypt work.
5. Success rotates the session (any session presented with the request is destroyed) and resets the counters.

```http
POST /api/auth/login
Content-Type: application/json

{"username":"operator","password":"…"}
```
```json
{ "user": { "id": "usr_…", "username": "operator", "role": "operator" },
  "csrfToken": "Vb1…", "expiresAt": "2026-10-19T10:30:00.000Z" }
```

Password change: `newPassword` must satisfy the policy (12–256 chars, not the username, not a single repeated
character, different from the current one) → `400` with `details[].field = "newPassword"`. A wrong
`currentPassword` → `400 VALIDATION_FAILED` with `details[].field = "currentPassword"` (not `401`, so the UI does not
treat it as a lost session); 5 wrong attempts per 15 min → `429`.

### Dashboard and events

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/stats` | A O V | `?hours=24` (1–720) | `{ totals: {requests, allowed, logged, blocked, flagged}, byCategory, topRules: [{ruleId, name, count}], latency: {avgMs, p50Ms, p95Ms}, mode, rulesetVersion, configVersion, timeline: [{hour, allowed, logged, blocked}], hours }` |
| `GET /api/events` | A O V | `?verdict=&action=&source=&ruleId=&q=&from=&to=&limit=50&offset=0` | `{ items: EventSummary[], total, limit, offset }` |
| `GET /api/events/compare` | A O | `?a=evt_…&b=evt_…` | `{ a: Event, b: Event, diff: { verdictChanged, actionChanged, scoreDelta (b−a), rulesAdded, rulesRemoved, rulesetChanged, configChanged } }` |
| `GET /api/events/:id` | A O | — | `{ event: Event }` |

`timeline` always has one bucket per hour of the window (oldest first, `hour` = ISO start of the hour).
`byCategory` counts events per matched category. Viewers only ever receive EventSummary objects.

### Analysis

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `POST /api/analyze` | A O | `{ label?, sample: Sample }` | `201 { event: Event }` — audit `analysis.submit` |
| `POST /api/import` | A O | `{ filename: "*.json", samples: [...] }` (1–100) | `201 { imported, events: EventSummary[], rejected: [{index, code, message}] }` — audit `import.submit` |
| `POST /api/events/:id/replay` | A O | — (empty body) | `201 { event: Event, previous: EventSummary }` — audit `event.replay` |

**Sample**: `{ method: GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS, path: "/…" (≤ 4096, no whitespace), headers: {name: value} (≤ 50, names [A-Za-z0-9-] ≤ 64, values ≤ 4096; default {}), body: string|null (≤ 1 MiB UTF-8; default null) }`.

Import items may be a bare Sample (optionally with `label`) or a fixture-style wrapper `{ label|name|id, sample }`;
other wrapper fields (e.g. `expected`) are ignored. Invalid items do not fail the batch; they are reported in
`rejected` by index. `filename` must be a plain name (`[A-Za-z0-9 _.()-]`) ending in `.json`.

Replay re-runs the stored (redacted) sample of a `console`, `import` or `replay` event with the **current** rules,
config and exceptions, stores a new event with `source: "replay"` and `replayOf` = original id. Proxy events have no
sample → `409 CONFLICT`.

Console analysis never uses the proxy rate limiter. Submissions (analyze, import, replay) are limited to
**60 per minute per user** → `429`.

```json
POST /api/analyze
{ "label": "union probe", "sample": { "method": "GET", "path": "/products?id=1%20UNION%20SELECT%201", "headers": {}, "body": null } }
→ 201 { "event": { "id": "evt_…", "source": "console", "verdict": "block", "action": "blocked", "score": 8,
                    "matchedRuleIds": [942100], "decision": { … }, "sample": { … }, "rulesetVersion": "…", "configVersion": 1, … } }
```

### Rules

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/rules` | A O | — | `{ items: Rule[], rulesetVersion, compileErrors }` |
| `GET /api/rules/:id/history` | A O | — | `{ items: RuleVersion[] }` (newest first; works for deleted rules) |
| `POST /api/rules/validate` | A O | `{ source }` | `200 { ok, rule, errors: [{line, col, message}] }` (nothing saved) |
| `POST /api/rules` | A | `{ source, enabled? = true }` | `201 { rule }` — audit `rule.create`; `409` if the id exists |
| `PUT /api/rules/:id` | A | `{ source?, enabled?, confirm? }` | `200 { rule }` — audit `rule.update` / `rule.enable` / `rule.disable` |
| `DELETE /api/rules/:id` | A | `{ confirm: true }` | `204` — audit `rule.delete` |

Invalid DSL → `400 VALIDATION_FAILED` with `details: [{ field: "source", message: "line 2, col 8: …", line, col }]`.
The rule id inside an edited `source` must equal `:id`. Disabling (`enabled: false`) and deleting require
`confirm: true`. Every change bumps the rule version, appends a `rule_versions` row and immediately reloads the
shared engine state used by the proxy. A `PUT` that changes nothing returns the rule unchanged.

### Configuration

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/config` | A O | — | `{ config, version, changedAt, changedBy }` |
| `PUT /api/config` | A | `{ config: EngineConfig, reason?, confirm: true }` | `200 { config, version, changedAt, changedBy }` — audit `config.update` (`targetId` = new version, `details.changes` = changed fields) |
| `GET /api/config/history` | A O | — | `{ items: [{ version, config, changedBy, changedAt, reason }] }` |

The configuration is validated by `engine.validateConfig` (errors → `400` with `details[].field = "config.<path>"`),
then `confirm: true` is required (`428`). Any configuration change takes effect for the next proxied request.
Changing `rateLimit` restarts the proxy rate-limit windows so the new limit is observable immediately.

### Exceptions (tuning workflow)

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/exceptions` | A O | `?status=pending|approved|rejected|revoked` | `{ items: ExceptionRecord[] }` |
| `POST /api/exceptions/preview` | A O | `{ ruleId, scope }` | `{ affectedEvents, scanned, sample: EventSummary[] (≤10) }` |
| `POST /api/exceptions` | A O | `{ ruleId, scope: {pathPrefix, location, method}, reason, sourceEventId?, expiresAt? }` | `201 { exception }` (status `pending`) — audit `exception.request` |
| `POST /api/exceptions/:id/approve` | A (≠ requester) | `{ confirm: true, note? }` | `200 { exception }` — audit `exception.approve` |
| `POST /api/exceptions/:id/reject` | A (≠ requester) | `{ note? }` | `200 { exception }` — audit `exception.reject` |
| `POST /api/exceptions/:id/revoke` | A | `{ confirm: true, note? }` | `200 { exception }` — audit `exception.revoke` |

Scope fields may be `null`, but at least one must be set (an unscoped exception would silently disable the rule).
`pathPrefix` starts with `/`; `location` is a match location (`path`, `query.<name>`, `body.<name>`, `header.<name>`,
`cookie.<name>`, `body`, `method`, `query_names`, `body_names`); `method` is an HTTP method. `ruleId` must exist;
`sourceEventId` must exist; `expiresAt` must be in the future.

Preview scans the 1 000 most recent events in which the rule matched and counts those whose match would be
suppressed (same semantics as the engine: rule id equal and every non-null scope field matching).

Review order: `404` → separation of duties (`403 FORBIDDEN`, message "Separation of duties: …", audited as
`exception.approve`/`exception.reject` with outcome `denied`) → state (`409` unless pending for approve/reject,
approved for revoke) → confirmation (`428`). Approve and revoke reload the engine state immediately.

### Audit

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/audit` | A | `?action=&actor=&outcome=&from=&to=&limit=&offset=` | `{ items: AuditEvent[], total, limit, offset }` (newest first) |
| `GET /api/audit/verify` | A | — | `{ ok, checked, brokenAt: seq|null }` |

`action` matches exactly or as a dotted family (`auth` matches `auth.login.failure`, `auth.lockout`, …).

### Reports (route owned by Wahaj, mounted here)

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/reports/export` | A O | `?format=json|csv|html&from=&to=&verdict=&ids=evt_a,evt_b` | file download (`Content-Disposition: attachment`), audit `report.export` |

Mounted at `/api/reports` behind `requireAuth` + `requireRole('admin','operator')`; the factory receives
`{ db, engineState, audit, logger }` (`src/api/routes/reports.js`, `createReportsRouter`).

### Users

| Method & path | Roles | Request | Success |
|---|---|---|---|
| `GET /api/users` | A | — | `{ items: User[] }` |
| `POST /api/users` | A | `{ username, password, role }` | `201 { user }` — audit `user.create`; `409` on duplicate (case-insensitive) |
| `PUT /api/users/:id` | A | `{ role?, disabled?, password?, confirm? }` | `200 { user }` — audit `user.update` (`details.changes`) |

Role changes and disabling need `confirm: true`. Disabling a user or setting a new password ends that user's
sessions immediately; a password set by an admin also clears a lockout. The last active admin cannot be disabled or
demoted (`409`). Role changes take effect on the user's next request.

## 3. Audit actions emitted

`auth.login.success`, `auth.login.failure` (details: attempted username, reason), `auth.lockout`, `auth.logout`,
`auth.denied` (wrong role or CSRF failure), `auth.password.change`, `config.update`, `rule.create`, `rule.update`,
`rule.enable`, `rule.disable`, `rule.delete`, `analysis.submit`, `import.submit`, `event.replay`,
`exception.request`, `exception.approve`, `exception.reject`, `exception.revoke`, `report.export` (reports route),
`user.create`, `user.update`, `system.start`, `system.error` (API 500s, proxy target down, engine failure),
`request.rejected`.

## 4. Factories (contract §10)

```js
const { createStudioApp } = require('./src/api/app');      // Express app, not listening
createStudioApp({ db, engineState, secret, logger, clock?, publicDir?, options? })
//   options: { analysisPerMinute = 60, loginThrottle: { maxFailures, windowMs, lockMs, perClientMax, perClientWindowMs },
//              idleMs, absoluteMs }
const { createProxyServer } = require('./src/proxy/server');
createProxyServer({ db, engineState, targetUrl, secret, logger?, audit?, retention? })   // http.Server
const { createEngineState } = require('./src/services/engineState');
createEngineState({ db, engine, logger? })   // { getContext, reload, status, getConfig, getConfigVersion, getRulesetVersion, … }
const { openDatabase } = require('./src/db');
const { seedDatabase } = require('./src/services/seed');
await seedDatabase(db, engine, { passwords, includeAdmin2?, resetPasswords?, rulesText? })  // → { passwords, created, updated, rules, config }
const { startAll } = require('./src/index');
await startAll({ studioPort, proxyPort, targetPort, dbPath, dataDir, startTarget = true, targetUrl?, quiet, engine? })
//   → { studio, proxy, target, db, engineState, ports, urls, close() }
```

## 5. Contract clarifications (decisions where the contract was silent or ambiguous)

1. **Body limit vs 1 MiB sample:** the 256 KB JSON limit applies everywhere except `/api/analyze` and `/api/import`
   (2 MiB), otherwise the contract's 1 MiB sample body could never be submitted.
2. **Lockout response:** the 5th failure still answers `401`; attempts *after* it answer `429` (even with the right
   password) until the 15-minute lock expires. Malformed login bodies (`400`) do not count as attempts.
3. **Wrong current password** on `POST /api/auth/password` → `400 VALIDATION_FAILED` (field `currentPassword`), not 401.
4. **Password change ends every session** of the user, including the current one (`204` + cleared cookie).
5. **Logout is idempotent** (`204` without a session).
6. **Separation of duties** applies to approve **and** reject (the requester cannot review their own request);
   revoke is allowed to any admin because it only removes an exemption (safety action).
7. **Unscoped exceptions** are refused (at least one scope field required).
8. **Events `path`** is stored without the query string (minimization); the full path is in the console sample.
9. **`limit` > 200** is clamped (not rejected), so clients asking for "everything" still work.
10. **Oversized proxy bodies** are never forwarded, even in monitor mode (the proxy only buffers `maxBodyBytes + 1`
    bytes); such events are stored as `action: "blocked"`, `blockReason: "BODY_TOO_LARGE"`, status `413`.
11. **Engine failure in the proxy** fails closed (`503`, `system.error`), nothing is forwarded.
12. **Seeding:** `seedDatabase` creates admin/operator/viewer; `admin2` only with `includeAdmin2: true`
    (`npm run setup` passes it), so tests can create their own second admin.
13. **Rate-limit reconfiguration** resets the proxy's rate-limit windows.
