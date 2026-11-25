# Progress — Shazil (A: backend / data / authentication)

Scope: `src/index.js`, `src/config.js`, `src/db/**`, `src/auth/**`, `src/services/**`, `src/proxy/**`,
`src/api/**` (except `routes/reports.js`), `scripts/setup.js`, `scripts/reset.js`, `test/unit/{db,auth,api}/**`,
`docs/data-model.md`, `docs/api.md`, `docs/security-controls.md`.

## Log

| Date | Entry |
|---|---|
| 2026-10-19 | Read proposal 44, requirements and the integration contract (§2, §4, §5, §6, §10 are mine; engine §3 consumed as specified). |
| 2026-10-19 | Runtime config (`src/config.js`): env vars of §1, loopback-only host, secret from `WAF_SECRET` or generated `<dataDir>/secret.key` (32 random bytes, hex, `0600`, exclusive create). Redacting injectable logger, service-layer redaction, HMAC client pseudonyms. |
| 2026-10-19 | Repository layer: `openDatabase()` (WAL, foreign keys, busy timeout, integrity check, `user_version` migrations), STRICT tables with CHECK constraints, repositories for users, sessions, rules + rule_versions, config_versions, events (filters, LIKE escaping, limit cap 200, stats with p50/p95 and hourly timeline, retention prune), exceptions (conditional state transitions, SoD CHECK), audit (append-only triggers, SHA-256 chain over canonical JSON, `verifyChain`). |
| 2026-10-19 | Auth: scrypt hashing (N=16384, r=8, p=1, 64-byte key, 16-byte salt) with `timingSafeEqual` and dummy verification for unknown users; password policy; hashed-token sessions with 30-min idle / 8-h absolute expiry; CSRF synchronizer token; login throttle (5/15 min per username → 15-min lock, persisted; 20/min per client); `requireAuth` / `requireRole` / `requireCsrf` middleware with `auth.denied` audit. |
| 2026-10-19 | Services: shared engine state (compile enabled rules, latest config seeded from `DEFAULT_CONFIG`, approved+unexpired exceptions, shared proxy rate limiter reconfigured/reset on change), console analysis service, idempotent `seedDatabase`. |
| 2026-10-19 | API: `createStudioApp` with security headers/CSP, request ids, Host/Origin guard, JSON-only bodies (256 KB / 2 MiB for analyze+import), central error handler (stable codes, no stack traces, `request.rejected` / `system.error` audit), strict schema validator, every endpoint of §5.2, Wahaj's reports router mounted (tolerant if missing), static SPA with fallback. |
| 2026-10-19 | Reverse proxy: bounded body buffering (`maxBodyBytes + 1`), inspect with shared state, event storage, block page with event id only (HTML/JSON), forwarding with re-streamed body, hop-by-hop stripping, XFF, 502/503 safe pages, `system.error` audit, upgrades refused. Bootstrap `startAll()` + direct run with graceful shutdown. |
| 2026-10-19 | `scripts/setup.js` (idempotent; env or generated passwords printed once; `--reset-passwords`) and `scripts/reset.js` (`--yes`, `--new-secret`). |
| 2026-10-19 | Tests: 224 in `test/unit/{db,auth,api}` (fake engine harness, 120-case role × endpoint matrix, proxy against a stub upstream, real-engine smoke) — all pass. |
| 2026-10-19 | Ran Saad's integration + security suites against the full stack with Nufil's engine and Saad's target: 235/236 pass; the remaining failure (`/files?name=../secret/flag.txt` scores 3 < block 5) is a default-rule scoring issue in `src/rules/default.rules` (engine owner). Evaluation harness test: 11/11. |
| 2026-10-19 | Fixes found by integration: console samples now mask secret-looking **query parameters** in the stored path (canary test); migration failure releases the DB file handle; sample paths reject control characters (aligned with the UI validator). |
| 2026-10-19 | Docs: `docs/data-model.md`, `docs/api.md`, `docs/security-controls.md`. |

## Contract clarifications

Decisions taken where the contract was silent or ambiguous (also listed in `docs/api.md` §5):

1. JSON body limit is 256 KB except `/api/analyze` and `/api/import` (2 MiB) so the contract's 1 MiB sample body fits.
2. Lockout: the 5th failure still returns `401`; later attempts return `429` until the 15-minute lock expires. Malformed login bodies are not counted as attempts.
3. Wrong `currentPassword` on `POST /api/auth/password` → `400 VALIDATION_FAILED` (field `currentPassword`), so the UI does not treat it as a lost session.
4. Password change ends **all** sessions of the user including the current one (`204` + cleared cookie).
5. Logout is idempotent (`204` even without a session).
6. Separation of duties applies to approve and reject; revoke may be done by any admin (it only removes an exemption).
7. Exceptions must have at least one non-null scope field.
8. `events.path` is stored without the query string (data minimization); the console sample keeps the (redacted) full path.
9. `limit` > 200 is clamped instead of rejected.
10. Oversized proxy bodies are never forwarded, even in monitor mode (stored as blocked / `BODY_TOO_LARGE` / 413).
11. If `engine.inspect` throws in the proxy, the proxy fails closed with `503` and audits `system.error`.
12. `seedDatabase` creates admin/operator/viewer; `admin2` only with `includeAdmin2: true` (setup passes it) so tests can create their own second admin.
13. Changing the rate-limit configuration resets the proxy's rate-limit windows.
14. Sample paths may not contain spaces or control characters (URL-encode them), matching the UI validator.

## Open items / hand-over notes

**Final reconciliation (2026-10-20):** the two historical engine items below are resolved. Rule 930105
now scores 5 and the single-level traversal proxy test passes; the SQL-comment/whitespace/backslash
parser test also passes. All 779 tests and current secret-redaction security checks pass. The harmless
http-proxy deprecation warning remains. See `../test-results.md` and `../evaluation/check-summary.json`.

* `src/rules/default.rules`: path traversal `../secret/flag.txt` currently scores 3 (flag) — integration test expects a block (Nufil).
* `test/unit/engine/parser.test.js` "SQL comment, whitespace, lowercase and backslash variants" fails at the time of writing (Nufil).
* ~~http-proxy 1.18.1 prints a Node `DEP0060 util._extend` deprecation warning~~ — resolved 2026-11-25: filtered (DEP0060 only) in `src/proxy/silenceDep0060.js`.
