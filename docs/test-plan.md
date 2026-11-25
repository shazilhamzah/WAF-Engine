# WAF Studio — Test Plan

> Owner: Saad (member D: automation, security testing, packaging, QA).
> Objective OBJ-4: "Measure effectiveness with repeatable positive, negative, edge-case, and misuse tests."
> Results: [`test-results.md`](test-results.md) and the generated [`evaluation/results.md`](evaluation/results.md).

## 1. Strategy

1. **Contract first.** All tests are written against the binding integration contract
   ([`02-architecture.md`](02-architecture.md)): endpoints, roles, error codes, decision and audit
   formats. A failing test therefore points either at a defect or at a contract deviation that must be
   recorded in `docs/PROGRESS.md`.
2. **Black-box through real sockets.** Integration, security and evaluation tests start the *whole*
   stack (Studio API + WAF proxy + vulnerable target) on **ephemeral 127.0.0.1 ports** with a
   **temporary SQLite database**, exactly as `npm start` wires it (`startAll` in `src/index.js`). No
   mocks between layers; nothing is sent to external hosts.
3. **White-box only where black-box cannot see.** Some security properties are checked by opening the
   database file directly: sessions store only token hashes, audit triggers reject UPDATE/DELETE,
   tampering is detected, canary secrets never reach any table or the WAL file.
4. **Evidence for every claim.** The evaluation harness records, for every sample: input (sanitised),
   expected result, actual result, evidence (event id, matched rule ids, score, categories, anomalies,
   explanation) and pass/fail — as the proposal requires for T1–T6.
5. **Repeatable.** Fixed fixtures (`fixtures/`), fixed test passwords, fresh temp data per suite;
   `npm test`, `npm run evaluate`, `npm run check` regenerate everything.

## 2. Test levels

| Level | Location | Owner | What it covers | Runner |
|---|---|---|---|---|
| Unit — engine | `test/unit/engine/` | Nufil | Parser/normalisation, DSL compile + validation (line/col errors, ReDoS guard), scoring, modes, rate limiter, exceptions, redaction | `npm run test:unit` |
| Unit — backend | `test/unit/{db,auth,api}/` | Shazil | Repositories, audit chain, password hashing, sessions, CSRF/role middleware, API validation | `npm run test:unit` |
| Unit — UI / reports | `test/unit/{ui,reports}/` | Wahaj | DOM helpers (no `innerHTML`), formatting, export sanitisation | `npm run test:unit` |
| Integration | `test/integration/` | Saad | Proposal workflow end to end, reverse proxy behaviour, exception workflow, vulnerable target | `npm run test:integration` |
| Security | `test/security/` | Saad | Authorization matrix, CSRF/sessions, lockout, injection/XSS/CSV, safe errors + headers, secrets, audit integrity, import validation | `npm run test:security` |
| Evaluation | `scripts/evaluate.js` (+ `test/evaluation/`) | Saad | Mandatory cases T1–T6, T-final, corpus coverage/FP/FN/precision/recall/latency | `npm run evaluate` |
| Performance | `scripts/bench-latency.js` | Saad | T6 latency overhead stand-alone | `npm run bench` |
| Acceptance gate | `scripts/check.js` | Saad | All tests, pass-rate ≥ 80 %, `npm audit --omit=dev` | `npm run check` |

## 3. Environments

| Item | Value |
|---|---|
| OS | Windows 11 (primary, team laptops); macOS/Linux supported (no OS-specific code except browser paths for PDF) |
| Runtime | Node.js ≥ 22.13 (developed on v24) — built-in `node:sqlite` and `node:test`; no Docker |
| Network | Loopback only (127.0.0.1), ephemeral ports in tests; fixed ports 3000/8080/3001 only for `npm start` |
| Data | Temporary directory per suite (`os.tmpdir()/waf-studio-test-*`), deleted afterwards |
| Credentials | Test-only passwords defined in `test/helpers/stack.js` (`TEST_PASSWORDS`) — never used outside tests |
| Browser (PDF only) | Microsoft Edge or Google Chrome, headless |

## 4. Evaluation case catalogue (mandatory cases)

Expected-verdict mapping used by the harness (`test/evaluation/runner.js`):

| Fixture `expected.verdict` | Pass when (observed through the proxy + stored event) |
|---|---|
| `block` | Proxy answers `X-WAF-Action: blocked` — HTTP 403 for rule matches (400/413/429 accepted for parser, size or rate rejections and noted) |
| `allow` | Request forwarded to the target (`X-WAF-Action: allowed`) **and** event verdict `allow` (a `flag` on benign input is reported as a soft false positive) |
| `flag` | Request forwarded (not blocked) **and** event verdict `flag` |

| Case | Input | Expected result | Evidence collected | Pass criterion |
|---|---|---|---|---|
| **T1** SQLi / XSS / traversal | `fixtures/t1-attacks.json` — classic SQL injection (tautologies, UNION, stacked, comments), reflected/stored XSS (script, event handlers, `javascript:`), path traversal (`../`, absolute paths) against the Vulnerable Shop routes | `block` with the right category | Event id, rule ids + names, match location, category, score vs thresholds, explanation | Every sample meets its expected verdict |
| **T2** Encoding variants | `fixtures/t2-encoding.json` — URL, double and triple URL encoding, `%u` / overlong UTF-8, HTML entities, Unicode full-width, mixed case, null bytes | Decoded and detected (`block`/`flag`), or anomaly recorded | As T1 plus `decodedVia` normalisation chain and anomalies (e.g. `DOUBLE_ENCODING`) | Expected verdict met; evidence shows which decoding revealed the payload |
| **T3** Benign false positives | `fixtures/t3-benign.json` — legitimate inputs that *look* suspicious (names like O'Brien, "select a size", SQL tutorials in comments, `<3`, file names with dots) | `allow` | Verdict, score, any matched rules | Every benign sample allowed; flags reported as soft FPs |
| **T4** Large bodies | Generated with `fixtures/large-body.js` `makeLargeBody(bytes, {payload, position})`: 10 KB benign, 60 KB benign, 200 KB with payload **beyond** the 64 KB inspection window, 200 KB with payload at the start, 2 MB, exactly `maxBodyBytes` | 10/60 KB forwarded intact; 200 KB-late → forwarded with `BODY_PARTIALLY_INSPECTED` anomaly (documented limitation); 200 KB-early → 403; 2 MB → 413 `BODY_TOO_LARGE` before rules; boundary not rejected for size | Target echo byte count, `request.truncated`, anomalies, blockReason | Each sub-case as stated |
| **T5** Bypass attempts | `fixtures/t5-bypass.json` — comment-splitting (`UN/**/ION`), whitespace alternatives, case games, concatenation, HTTP parameter pollution, JSON-body smuggling, uncommon methods/headers | `block`/`flag` as labelled by Nufil; known misses labelled honestly | As T1 | Expected verdict met; misses become documented limitations |
| **T6** Latency overhead | N ≥ 300 interleaved request pairs (direct to target vs. via WAF) per scenario after 30 warm-up pairs: `GET /search?q=mug`, `POST /api/echo` 2 KB form; keep-alive, one socket per side | Overhead small enough for interactive use | mean / p50 / p95 / p99 for both sides and the difference | **p95 overhead < 25 ms** on localhost and zero proxy errors |
| **T-final** | TF-01 5000-char URL via proxy · TF-02 malformed percent-encoding · TF-03 malformed JSON to API · TF-04 2.5 MB JSON to API · TF-05 anonymous record request · TF-06 viewer requests evidence · TF-07 viewer config change · TF-08 15 rapid requests with limit 10/min · TF-09 7 wrong passwords then the right one · TF-10 target stopped · TF-11 stop whole stack, restart on the same DB | 400 MALFORMED_REQUEST · safe non-5xx · 400 MALFORMED_JSON · 413 · 401 · generic 403 + `auth.denied` · 403 · 10 × 200 then 429 `RATE_LIMITED` · 401 × 5 then 429 (even correct password) + `auth.lockout` · safe 502 + studio healthy + `system.error` · rules/config/events/audit persisted, chain verifies, WAF enforcing | Status codes, error codes, audit entries, event evidence, before/after counts, `/api/audit/verify` | Each check as stated |

### 4.1 Corpus metrics

`fixtures/corpus-benign.json` + `fixtures/corpus-attack.json` are sent through the proxy. Positive =
expected `block`/`flag`; predicted positive = engine verdict `block`/`flag`. Reported: TP, FP, TN, FN,
**precision, recall (detection coverage), F1, false-positive rate**, attacks actually blocked, coverage
per category (sqli, xss, traversal, …), and **decision latency** from the engine's own
`decision.timings.totalMs` (mean/p50/p95/p99). Every false positive and false negative is listed with its
evidence.

## 5. Integration and security test inventory

| File | Tests | Focus | Traceability |
|---|---|---|---|
| `integration/target.test.js` | 14 | Each lab vulnerability works directly; sandbox guard (traversal cannot leave `target/files/`, stacked SQL ignored, 5 MB cap, no internals) | §7, TH-20 |
| `integration/workflow.test.js` | 10 | Proposal illustrative example: benign → suspicious (rule id + location) → history → compare → export → admin threshold change with confirm → replay → traceable in config history and audit | OBJ-1, OBJ-2, FR-3, FR-6, FR-7, NFR-8 |
| `integration/proxy.test.js` | 10 | allowed / blocked (403, event id, no rule details) / JSON block page / monitor mode (`logged`, `wouldBlock`) / 429 / 413 / event filters / target down → 502 + `system.error` | FR-1, FR-4, FR-5, FR-6, NFR-5 |
| `integration/exceptions.test.js` | 13 | Preview, request, operator cannot approve, self-approval refused, 428 without confirm, second admin approves, replay shows suppressed match, scope respected, revoke restores, reject, all audited | FR-7, TH-05 |
| `security/authorization.test.js` | 120 + 4 | 30 endpoints × {anonymous, viewer, operator, admin}; viewer summaries only; denial audited; no self role escalation; forged ids | NFR-2, TH-04 |
| `security/session-csrf.test.js` | 11 | Cookie flags, token hashed at rest, no fixation, CSRF missing/wrong/cross-session, logout invalidation, idle + absolute expiry | NFR-2, NFR-3, TH-02, TH-03 |
| `security/accounts.test.js` | 2 | Disabled user loses access; password change policy | NFR-2 |
| `security/login-protection.test.js` | 7 | Generic 401, malformed credentials, lockout + Retry-After, other users unaffected, audit without passwords, SQLi usernames, per-client limit | FR-5, NFR-7, TH-01 |
| `security/injection-output.test.js` | 9 | SQLi in every filter, LIKE wildcards, server-side ids, XSS as JSON data, HTML export escaping, CSV formula injection, export formats | NFR-4, TH-06..TH-08 |
| `security/errors-headers.test.js` | 12 | Malformed/huge/deep JSON, wrong content type, odd methods, validation details, `request.rejected` audited, CSP/nosniff/frame/referrer headers, no-store, loopback binding, proxy hostile input | NFR-5, NFR-10, TH-13, TH-14 |
| `security/secrets.test.js` | 7 | Canary secrets absent from every table, WAL, API responses and all export formats; no raw IPs; scrypt hashes; secret key not served | NFR-6, TH-11, TH-12 |
| `security/audit-integrity.test.js` | 7 | Audit format, chain links + verify, filters, UPDATE/DELETE rejected, no edit API, tamper detected at the right `seq` | FR-6, TH-09, TH-10 |
| `security/import-validation.test.js` | 10 | Valid import, extension check, path-like names, >100 samples, boundary 100, >2 MiB, bad structure, empty, per-sample rejections, viewer denied | NFR-4, TH-19 |
| `evaluation/harness.test.js` | 11 | The harness itself: percentiles, metrics, verdict mapping, markdown escaping, raw client, latency measurement | OBJ-4 |

## 6. Pass criteria

* **Acceptance gate** (`npm run check`): ≥ 80 % of all automated tests pass (strict mode — suites fail
  rather than skip when a module is missing) **and** no high/critical production `npm audit` findings.
* **Zero unresolved critical defects** in authorization, injection, secret exposure or unsafe file
  handling (proposal acceptance criteria). Any failing test in `authorization`, `injection-output`,
  `secrets` or `target` (sandbox) is treated as critical until triaged.
* **Evaluation**: every T-case reports per-sample pass/fail; T6 passes when p95 overhead < 25 ms. The
  harness never hides failures — it exits 0 so the measurement is always written, and the summary lists
  what failed.

## 7. How to run

```bash
npm test                    # everything (unit + integration + security + harness), sequential
npm run test:integration    # integration only
npm run test:security       # security only
node --test test/security/authorization.test.js     # one file
npm run evaluate            # T1–T6 + T-final + corpus → docs/evaluation/results.{md,json}
npm run evaluate -- --quick # faster smoke run (N = 100 for T6)
npm run bench               # T6 only → docs/evaluation/latency.json
npm run check               # acceptance gate → docs/evaluation/check-summary.json
```

While the backend is incomplete, integration/security suites **skip** with a reason; `npm run check`
sets `WAF_STRICT=1` so they fail instead (use `node scripts/check.js --lenient` during development).

Final integration (2026-10-20): the backend is complete; the recorded acceptance run has zero skips.
Adverse fixtures are generated by `npm run fixtures:build`. `attack-fixtures.test.js` checks the
fixture contract, all baseline T1/T2 blocks and explicit triage of bypass misses. Expected block is
retained for known misses; those still fail their protection expectation in the evaluation. Tests
that verify honest limitation reporting are distinct from successful attack prevention. Full final
counts and method limitations are in [test-results.md](test-results.md).

## 8. Traceability (requirement → tests)

| Requirement | Tests / evaluation |
|---|---|
| FR-1 Request parser | `integration/proxy.test.js` (413, malformed), `security/errors-headers.test.js` (proxy hostile input), evaluation T2, T4, TF-01, TF-02, engine unit tests |
| FR-2 Rule DSL | `security/authorization.test.js` (rule endpoints), `integration/workflow.test.js` (rule ids/names in evidence), engine unit tests |
| FR-3 Scoring | `integration/workflow.test.js` (contributions, byCategory, thresholds), evaluation T1–T5 evidence |
| FR-4 Block/monitor | `integration/proxy.test.js` (monitor → `logged`, `wouldBlock`; back to block) |
| FR-5 Rate limits | `integration/proxy.test.js` (429), `security/login-protection.test.js`, evaluation TF-08, TF-09 |
| FR-6 Audit console | `security/audit-integrity.test.js`, `integration/workflow.test.js`, evaluation TF-11 |
| FR-7 Tuning & exceptions | `integration/exceptions.test.js`, `integration/workflow.test.js` (replay) |
| NFR-2 Auth, sessions, least privilege | `security/authorization.test.js`, `security/session-csrf.test.js`, `security/accounts.test.js` |
| NFR-3 CSRF | `security/session-csrf.test.js` |
| NFR-4 Validation, parameterised SQL, server ids | `security/injection-output.test.js`, `security/import-validation.test.js`, `security/errors-headers.test.js` |
| NFR-5 Stable errors, no stack traces | `security/errors-headers.test.js`, evaluation TF-03, TF-04 |
| NFR-6 Secrets | `security/secrets.test.js` |
| NFR-7 Rate limiting sensitive actions | `security/login-protection.test.js`, evaluation TF-08, TF-09 |
| NFR-8 Logging | `integration/workflow.test.js`, `integration/exceptions.test.js`, `security/audit-integrity.test.js` |
| NFR-9 Local, Node only | every suite (ephemeral ports, temp DB, no Docker) |
| NFR-10 CSP / headers | `security/errors-headers.test.js`, `unit/ui/static-security.test.js` |
| NFR-11 Recovery | evaluation TF-11; `docs/setup-guide.md` §Recovery |
| Proposal "illustrative example" | `integration/workflow.test.js` |
| Proposal "unauthorized viewer receives a generic denial, logged" | `security/authorization.test.js`, evaluation TF-06 |
