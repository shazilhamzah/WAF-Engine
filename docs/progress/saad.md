# Progress log — Saad (member D: automation, security testing, packaging, QA)

| Date | Entry |
|---|---|
| 2026-10-19 | Read the proposal, `docs/00-project-plan.md`, `docs/01-requirements.md` and the binding contract `docs/02-architecture.md` |
| 2026-10-19 | **Vulnerable target** `target/app.js` + `target/server.js` (Vulnerable Shop: reflected/stored XSS, SQLi on login + products, sandboxed path traversal, 5 MB byte-count echo, health; LAB ONLY banner; loopback-only). Safety design: in-memory fake DB via single-statement `prepare()` with extensions disabled; traversal guarded by resolved path + realpath inside `target/files/`; no outbound calls. Fake files under `target/files/{public,secret,config}`. 14 tests (`test/integration/target.test.js`) pass |
| 2026-10-19 | **Test helpers** `test/helpers/`: `startStack()` (seeds a temp DB with known passwords through `openDatabase` + `seedDatabase`, then `startAll` on ephemeral ports), cookie/CSRF-aware `ApiClient` (global fetch), non-normalising `rawRequest` (node:http) for the proxy, domain helpers. Suites skip with a reason while the backend is missing, fail under `WAF_STRICT=1` |
| 2026-10-19 | **Integration tests**: proposal workflow (10), reverse proxy (10), exception workflow with separation of duties (13) |
| 2026-10-19 | **Security tests**: authorization matrix (30 endpoints × 4 roles + 4), sessions/CSRF (11), accounts (2), login protection (7), injection/XSS/CSV (9), safe errors + headers (12), secrets canary grep of DB/WAL/API/exports (7), audit append-only + tamper detection (7), import validation (10) |
| 2026-10-19 | **Evaluation harness** `scripts/evaluate.js` + `test/evaluation/` (stats, proxy sample runner, latency, markdown report; 11 self-tests): T1–T5 from Nufil's fixtures through the real proxy, T4 with `fixtures/large-body.js`, T6 interleaved direct-vs-proxy latency (p95 overhead < 25 ms), T-final TF-01..TF-11 including restart recovery, corpus precision/recall/FP/FN/coverage/decision latency → `docs/evaluation/results.{md,json}` |
| 2026-10-19 | **Scripts**: `bench-latency.js` (→ `docs/evaluation/latency.json`), `check.js` (strict test run with spec + TAP reporters, pass-rate ≥ 80 %, `npm audit --omit=dev`, → `docs/evaluation/check-summary.json`), `build-pdf.js` (marked → print HTML with cover, TOC, running header, Page X of Y, inlined SVG, CSP `default-src 'none'` → headless Edge/Chrome PDF; `--all`). Verified on every doc in `docs/` |
| 2026-10-19 | **Docs**: `docs/threat-model.md` (assets, actors, DFD `docs/diagrams/dfd.svg` + ASCII fallback, TB1–TB5, 13 flows, 20 STRIDE threats → mitigation → file → test → residual risk), `docs/test-plan.md`, `docs/limitations-and-ethics.md`, `docs/setup-guide.md`, `README.md`, `docs/test-results.md` (phase-1 snapshot) |
| 2026-10-19 | First run against the integrated backend: 213/236 → found (a) contract deviation: analyze/import accept 2 MiB JSON (tests aligned), (b) secret query parameters in console samples stored unredacted (reported; fixed by Shazil in 0c7dd43), (c) my own test bugs (CSV cell matching, import sample path with raw spaces, rate-limit test depending on earlier mode) — fixed |
| 2026-10-19 | With `src/rules/default.rules`: my suites 246/247; `npm run check` 559/560 (99.8 %), `npm audit` 0 vulnerabilities. Remaining failure: single-level traversal `../secret/flag.txt` only flagged (rule 930105, 2 points) → reaches the fake secret through the WAF (reported to Nufil/master) |
| 2026-10-19 | `npm run evaluate --quick` end to end: T3 38/38, T4 6/6, T6 2/2 (p95 overhead ≈ 2.4 ms), T-final 11/11; T1, T2, T5 and the attack corpus waiting for fixtures |
| 2026-11-25 | Corrected the B/D role labels across the documentation to match the actual allocation (Nufil = B security engine / fixtures, Saad = D automation / security testing / QA); the per-member progress logs were swapped to match |
| 2026-11-25 | Done with Claude: proxy-level tests for the new hex/`||` tautology rules (`test/integration/tautology-proxy.test.js`, 3 attacks blocked + 3 benign look-alikes allowed); full re-measurement — evaluation 119/123 (was 117/123; T5 14/18), corpus recall 0.9625 with 0 false positives, benchmark p95 overhead GET 1.721 ms / POST 1.886 ms, strict check 804/804 and 0 audit findings; `docs/test-results.md` updated. |

## Next (phase 2)

**Completed by integration continuation on 2026-10-20.** The list below is retained as the original
handover checklist; it is no longer pending. Strict check 779/779, audit 0; full evaluation 117/123
(six disclosed T5 misses); independent latency GET/POST p95 overhead 1.888/1.988 ms. Final results,
traceability and report/PDF replace the phase-1 status. The separate demo is omitted at the user's
explicit request.

* Re-run `npm run check`, `npm run evaluate` (full, N = 300) and `npm run bench` on the integrated tree;
  commit `docs/evaluation/results.{md,json}`, `latency.json`, `check-summary.json`.
* Replace the phase-1 snapshot in `docs/test-results.md` with the final numbers and per-case analysis.
* Build `docs/final-report.pdf` with `npm run docs:pdf` once the master has written `docs/final-report.md`.
