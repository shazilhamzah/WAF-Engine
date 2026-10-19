# WAF Studio — Security Controls (backend, data, authentication)

Owner: Shazil (A). Covers the Studio API, repository, sessions, proxy data plane and bootstrap.
Requirement ids refer to `docs/01-requirements.md`; tests are under `test/unit/{db,auth,api}`.

| # | Control | Implementation | Evidence (tests) |
|---|---|---|---|
| 1 | Password hashing | scrypt N=16384, r=8, p=1, 64-byte key, 16-byte random salt per user; self-describing format `scrypt$N$r$p$salt$key`; `timingSafeEqual`; input normalized NFKC; hostile stored parameters refused | `auth/auth.test.js` "password hashing" |
| 2 | Password policy | 12–256 chars, not the username, not one repeated character; enforced on create, admin reset, self change and seeding | `auth.test.js`, `api.test.js` password change / users |
| 3 | No user enumeration | identical `401 AUTH_INVALID` for unknown user, wrong password, disabled account; a dummy scrypt verification runs for unknown users so timing matches; lockout applies to unknown names too | `api.test.js` "share one generic 401", lockout test |
| 4 | Brute-force protection | 5 failures / 15 min per username → 15-min lock (persisted in `users.locked_until`, survives restart) + `auth.lockout` audit; 20 attempts / min per client → `429` + `Retry-After` | `auth.test.js` throttling, `api.test.js` login throttling |
| 5 | Session tokens | 32 random bytes (base64url) in `waf_sid`; only SHA-256(token) stored; `HttpOnly; SameSite=Strict; Path=/` (+`Secure` on HTTPS); session cookie (no persistent expiry) | `auth.test.js` sessions, `api.test.js` cookie flags |
| 6 | Session lifetime | 30-min idle (sliding) and 8-h absolute expiry, enforced server-side on every request; expired rows deleted; disabled users' sessions rejected | `auth.test.js` (injected clock), `api.test.js` idle expiry |
| 7 | Session fixation | new token at every login; any session presented with the login request is destroyed | `api.test.js` rotation |
| 8 | Session termination | logout deletes the row; password change deletes all of the user's sessions; disabling a user or admin password reset deletes theirs | `api.test.js` logout/password/users |
| 9 | CSRF | synchronizer token per session, `X-CSRF-Token` compared in constant time (SHA-256 digests + `timingSafeEqual`) on all POST/PUT/PATCH/DELETE except login; `SameSite=Strict`; JSON-only bodies (HTML forms cannot send `application/json`); cross-origin `Origin` refused | `auth/middleware.test.js`, `api.test.js` |
| 10 | Authorization | server-side role check on every route (`requireRole`), generic `403 FORBIDDEN` with no record content + `auth.denied` audit; viewers receive EventSummary objects only; operators cannot change users/roles | `api/authz.test.js` (30 endpoints × 4 roles) |
| 11 | Separation of duties | an admin cannot approve/reject their own exception request (API `403` + audited denial) and the DB has a CHECK forbidding `reviewed_by = requested_by` on approved rows | `api.test.js` exception workflow, `db/repositories.test.js` |
| 12 | High-impact confirmation | `"confirm": true` required for config changes, disabling/deleting rules, approving/revoking exceptions, disabling users, role changes (`428`) | `api.test.js` |
| 13 | Input validation | strict schemas (`src/api/validation.js`): types, lengths, enums, patterns, counts, unknown fields rejected, prototype keys inert; ids validated by format before lookup; JSON body 256 KB (2 MiB analyze/import); `415` for non-JSON | `api.test.js` validation/transport |
| 14 | Injection safety | every SQL statement is prepared with `?` parameters; LIKE wildcards escaped; no string-built SQL with user data | `db/repositories.test.js` "SQL metacharacters", `api.test.js` hostile filters |
| 15 | Safe errors | central handler maps everything to stable codes; `500 INTERNAL_ERROR` never includes stack traces, SQL errors or paths; internal details go to the local log (redacted); `system.error` audited | `api.test.js` "server error" |
| 16 | Security headers | strict CSP (`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`), nosniff, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, `Permissions-Policy`, COOP/CORP, `Cache-Control: no-store` on `/api`, no `X-Powered-By` | `api.test.js` headers |
| 17 | Network exposure | all three listeners bind `127.0.0.1`; Host header allow-list (loopback names) against DNS rebinding; server header/request timeouts (slowloris) | `api.test.js` foreign Host |
| 18 | Abuse limits | 60 analysis submissions / min / user; proxy rate limiter (engine) per pseudonymous client | `api.test.js`, `proxy.test.js` |
| 19 | Audit trail | append-only `audit_log` (SQLite triggers abort UPDATE/DELETE) + SHA-256 hash chain over canonical JSON; `GET /api/audit/verify` recomputes every hash, link and sequence number | `db/audit.test.js` (triggers, raw-file tamper, gap, forged hash) |
| 20 | Privacy / minimization | IPs → HMAC pseudonyms; proxy events keep only the sanitized decision; console samples redacted; audit details redacted and size-capped; events retention cap (100 000) | `proxy.test.js` "no bodies or raw IPs", `services.test.js` |
| 21 | Secrets | `WAF_SECRET` or a generated 32-byte key in `<dataDir>/secret.key` (mode 0600, created exclusively); never logged, never returned; logger redacts secret-looking keys | `services.test.js` config/secrets, logger |
| 22 | Proxy safety | body buffered to at most `maxBodyBytes + 1`; oversize never forwarded (any mode); block pages show the event id only; hop-by-hop and proxy-credential headers stripped; upstream `X-Powered-By` removed; upgrades refused; engine failure fails closed (`503`); target failure → safe `502` + `system.error`; proxy errors cannot crash the process | `api/proxy.test.js` |

## 1. Threats addressed (backend view)

| Threat | Mitigation (rows above) |
|---|---|
| Credential stuffing / brute force on the console | 1, 3, 4 |
| Stolen database file reveals passwords or live sessions | 1, 5 |
| Session hijacking / fixation / CSRF | 5–9, 17 |
| Privilege escalation (viewer → evidence, operator → config) | 10, 12 |
| Insider self-approval of an exception | 11, 19 |
| Tampering with the audit trail | 19 |
| SQL injection via filters / ids | 13, 14 |
| Information leakage through errors or block pages | 15, 22 |
| Clickjacking / XSS impact in the console | 16 |
| Remote access to the lab or DNS-rebinding | 17 |
| Resource exhaustion (large bodies, floods) | 13, 18, 22 |
| Over-collection of personal data | 20 |

## 2. Secrets handling

* The secret is used for client pseudonyms (HMAC). Precedence: `WAF_SECRET` (≥ 16 chars) → `<WAF_DATA_DIR>/secret.key`.
* `secret.key` is generated with `crypto.randomBytes(32)` and written with flag `wx` and mode `0600`; a corrupt file is
  refused with a clear message (delete it to regenerate — pseudonyms change).
* Seed passwords come from `WAF_ADMIN_PASSWORD`, `WAF_OPERATOR_PASSWORD`, `WAF_VIEWER_PASSWORD`, `WAF_ADMIN2_PASSWORD`
  or are generated and printed **once** by `npm run setup`; they are never written to disk.
* `data/` (database, WAL files, secret) is git-ignored.

## 3. Recovery

State lives in the SQLite database (WAL mode) and survives restarts: users, sessions, rules and their history,
configuration versions, events, exceptions and the audit log.

| Situation | What to do |
|---|---|
| Normal restart | `npm start` — the active config, rules and approved exceptions are reloaded; sessions remain valid until their idle/absolute expiry; persisted lockouts remain |
| Process killed / power loss | `npm start`; SQLite WAL replays committed transactions automatically |
| Forgot all passwords | stop WAF Studio, `npm run setup -- --reset-passwords` (new passwords printed once; their sessions end) |
| Locked-out user | wait 15 minutes, or an admin sets a new password for the user (clears the lock) |
| `Database integrity check failed` at start | stop WAF Studio, keep a copy of `data/waf-studio.db*` for analysis, then `npm run reset -- --yes` and `npm run setup` |
| Audit verification fails (`GET /api/audit/verify` → `ok: false`) | treat as an incident: export the audit log, preserve the DB file, note `brokenAt`; the chain shows the first altered entry. Do not "repair" the log |
| `secret.key is corrupt` | delete `data/secret.key` (a new key is generated; client pseudonyms change) |
| Start fresh for a demo | `npm run reset -- --yes` then `npm run setup` (`--new-secret` also rotates the key) |
| Port already in use | set `STUDIO_PORT`, `PROXY_PORT`, `TARGET_PORT` |

`npm run reset` without `--yes` only lists what would be deleted.

## 4. Known limitations

* Session cookies are not marked `Secure` in the default (HTTP, loopback-only) setup; the flag is set automatically
  when the console is served over HTTPS.
* Login throttling and the analysis limiter are in memory (per process); the username lockout is also persisted.
* The audit chain detects modification but cannot prevent someone with file-system access from deleting the whole
  database file; keep backups / exports for evidence.
* Replays use the redacted sample, so an attack hidden inside a masked field (e.g. `password=`) is not reproduced.
