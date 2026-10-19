# WAF Studio - Requirements and Evidence Traceability

**Proposal 44 | Class 3, Group 12 | Final integration: 2026-10-20 (Asia/Karachi)**

The source proposal enumerates FR-1 through FR-7, despite its acceptance paragraph saying "six".
All **seven** are mapped below. Paths in the implementation and test columns are relative to the
project root. Measured evidence links are relative to this document. Tests were run in strict mode:
**782 passed, 0 failed, 0 skipped**; see [acceptance evidence](evaluation/check-summary.json).

## 1. Functional requirements

| ID | Implemented behaviour | Implementation | Reproducible verification | Result |
|---|---|---|---|---|
| FR-1 | Validate/normalize requests; preserve decoding and anomaly evidence; enforce size limits | `src/engine/parser.js`, `normalize.js`, `src/proxy/server.js` | `test/unit/engine/parser.test.js`, `inspect.test.js`; `test/integration/proxy.test.js`; T2, T4, TF-01..TF-04 in [evaluation](evaluation/results.md) | Implemented; partial-body inspection limit disclosed |
| FR-2 | Documented rule DSL; line/column validation, regex guard, versioned rule changes | `src/engine/dsl.js`, `regexguard.js`, `src/api/routes/rules.js`; [DSL](rule-dsl.md) | `test/unit/engine/dsl.test.js`, `rules.test.js`; `test/unit/api/api.test.js` | Tests pass; 41 default rules compile |
| FR-3 | Per-rule contributions, category totals and stored flag/block thresholds | `src/engine/scoring.js`, `explain.js`, `pipeline.js` | `test/unit/engine/scoring-modes.test.js`; `test/integration/workflow.test.js`; T1..T5 per-event evidence | Tests pass; expectations and misses recorded |
| FR-4 | Block mode enforces, monitor mode logs with `wouldBlock`; changes versioned/audited | `src/engine/modes.js`, `src/api/routes/config.js`, `public/js/views/config.js` | `test/unit/engine/scoring-modes.test.js`; `test/integration/proxy.test.js` | Tests pass; oversized bodies still rejected by proxy in monitor mode |
| FR-5 | Proxy sliding-window limits; login throttling/lockout; analysis throttling | `src/engine/ratelimit.js`, `src/auth/rateLimit.js`, `src/api/routes/events.js` | `test/unit/engine/ratelimit.test.js`; `test/security/login-protection.test.js`; TF-08, TF-09 | Tests pass; counters reset on restart/config change |
| FR-6 | Append-only audit records, hash verification, history/filter/compare and evidence views | `src/db/repositories/audit.js`, `src/api/routes/audit.js`, `public/js/views/audit.js`, `events.js`, `event-detail.js`, `compare.js` | `test/unit/db/audit.test.js`; `test/security/audit-integrity.test.js`; `test/integration/workflow.test.js`; TF-11 | Tests pass; chain has no external anchor |
| FR-7 | Scoped exception preview/request, different-admin review, replay, revoke and versioned tuning | `src/engine/exceptions.js`, `src/api/routes/exceptions.js`, `public/js/views/exceptions.js` | `test/unit/engine/exceptions.test.js`; `test/integration/exceptions.test.js`, `workflow.test.js` | Tests pass; role checks and separation of duties enforced |

## 2. Objectives and non-functional requirements

| ID | Requirement | Implementation / document | Evidence |
|---|---|---|---|
| OBJ-1 | Complete input-to-result workflow | Console, API, engine, SQLite, report exports | `test/integration/workflow.test.js`; [user guide](user-guide.md) |
| OBJ-2 | Explain each decision | Stored matches, rule names/versions, location, excerpt, decoding, score and recommendation | `test/unit/engine/inspect.test.js`, `scoring-modes.test.js`; [evaluation](evaluation/results.md) |
| OBJ-3 | Threat-model-driven protection | [20-threat STRIDE model](threat-model.md), [security controls](security-controls.md) | `test/security/*.test.js`; [acceptance evidence](evaluation/check-summary.json) |
| OBJ-4 | Repeatable effectiveness measurements | Fixed synthetic fixtures and whole-stack harness | [results JSON](evaluation/results.json), [latency](evaluation/latency.json) |
| NFR-1 | Layered architecture | [integration contract](02-architecture.md), `src/engine/`, `src/api/`, `src/db/`, `public/`, `fixtures/` | [architecture diagram](diagrams/architecture.svg); separately testable factories |
| NFR-2 | Password hashing, expiry, least privilege | `src/auth/`, `src/db/repositories/sessions.js`; [roles](02-architecture.md) | `test/unit/auth/*.test.js`; `test/security/authorization.test.js`, `session-csrf.test.js`, `accounts.test.js` |
| NFR-3 | CSRF and hardened cookie sessions | `src/auth/middleware.js`, `sessions.js` | `test/security/session-csrf.test.js`; HttpOnly/SameSite=Strict, token bound to session |
| NFR-4 | Parameterized SQL, identifiers, validation/import limits | `src/db/repositories/`, `src/api/validation.js`, `src/api/routes/events.js` | `test/security/injection-output.test.js`, `import-validation.test.js`, `errors-headers.test.js` |
| NFR-5 | Stable safe errors | `src/api/errors.js`, `middleware.js`, `src/proxy/pages.js` | `test/security/errors-headers.test.js`; TF-03..TF-07, TF-10 |
| NFR-6 | Protected secrets and data minimization | `src/config.js`, `src/services/redact.js`, `clientId.js`, `src/engine/redact.js` | `test/security/secrets.test.js`; tests scan DB/WAL/API/exports for canaries |
| NFR-7 | Limit sensitive actions | Login and analysis throttles | `test/security/login-protection.test.js`; `test/unit/api/api.test.js`; TF-08/09 |
| NFR-8 | Security-relevant logging | Audit service and repositories; authenticated routes | `test/integration/workflow.test.js`, `exceptions.test.js`; `test/security/audit-integrity.test.js` |
| NFR-9 | Local laptop, Node, no required Docker/paid service | `package.json`, `src/index.js`; [setup](setup-guide.md) | Current strict tests/evaluation run on Windows/Node 24; other OS support not reverified in this completion |
| NFR-10 | Responsive, keyboard-accessible UI; strict CSP | `public/css/app.css`, `public/js/ui.js`, safe DOM builder | `test/unit/ui/*.test.js`; `test/security/errors-headers.test.js`; historical browser smoke in [Wahaj's log](progress/wahaj.md) ; updated dashboard browser checks in [UI review](evaluation/ui-review.json) |
| NFR-11 | Persistent state and recovery | SQLite WAL, migrations, graceful shutdown; [recovery guide](setup-guide.md) | TF-11: same DB restarted, rules/config/events persisted, chain verifies, WAF enforcing |

## 3. Mandatory evaluation and acceptance

| Case / criterion | Input source | Final outcome | Evidence |
|---|---|---|---|
| T1 SQLi/XSS/traversal | `fixtures/t1-attacks.json` | 28/28 blocked | [per-input results](evaluation/results.md); canonical case key `T1` in [JSON](evaluation/results.json) |
| T2 encoding variants | `fixtures/t2-encoding.json` | 20/20 blocked | `T2` in [evaluation](evaluation/results.md) |
| T3 benign false positives | `fixtures/t3-benign.json` | 38/38 allowed | `T3` in [evaluation](evaluation/results.md) |
| T4 large bodies | `fixtures/large-body.js` | 6/6 checks; beyond-window blind spot explicitly observed | `T4` in [evaluation](evaluation/results.md) |
| T5 bypass attempts | `fixtures/t5-bypass.json` | 12/18 blocked; six failed protection expectations retained | `T5` in [evaluation](evaluation/results.md); [limitations](limitations-and-ethics.md) |
| T6 latency | Direct versus proxy, 300 pairs/scenario, 30 warmups | Both scenarios below 25 ms p95 overhead | [evaluation](evaluation/results.json), [independent benchmark](evaluation/latency.json) |
| T-final | Malformed/oversized input, denial, repetition, safe failure, restart | 11/11 checks pass | `T-final` in [evaluation](evaluation/results.md) |
| Automated pass rate at least 80% | All test files, strict mode | 782/782, 100%; no skips/cancellations | [check summary](evaluation/check-summary.json) |
| No unresolved critical application-security findings in tested scope | Authorization, injection/output, secrets, import/sandbox suites | All pass; no open critical findings identified by these checks | [test results](test-results.md); [threat model](threat-model.md) |
| Quantitative coverage, FP/FN and decision latency | 68 benign + 80 adverse synthetic corpus | TP 76, TN 68, FP 0, FN 4; recall 95%; decision p95 0.476 ms | `metrics` in [JSON](evaluation/results.json); no claim of real-world accuracy |

Passing regression tests verifies implementation behaviour, including honest reporting of known
limitations. It does not turn the six failed T5 protection expectations into passing detections.

## 4. Delivery checklist and scope exception

| Proposal deliverable | Location | State |
|---|---|---|
| Source and setup guide | `src/`, `public/`, `target/`, `scripts/`, [README](../README.md), [setup](setup-guide.md) | Complete |
| Sanitized sample data | `fixtures/`; [fixture guide](fixtures.md) | Complete; synthetic only |
| Architecture and DFD | [architecture](02-architecture.md), [architecture SVG](diagrams/architecture.svg), [DFD SVG](diagrams/dfd.svg) | Complete |
| Threat model with at least eight threats | [STRIDE model](threat-model.md) | Complete; 20 threats and five trust boundaries |
| Test plan/results | [plan](test-plan.md), [results](test-results.md), `evaluation/` | Complete; known misses disclosed |
| User and administrator guide | [user](user-guide.md), [admin](admin-guide.md) | Complete |
| Limitations/ethics | [statement](limitations-and-ethics.md) | Complete |
| Final report | [editable report](final-report.md), [PDF](final-report.pdf) | Complete |
| Reproducible 10-15 minute demonstration | No walkthrough or demo artifact | **Excluded at the user's explicit request on 2026-10-20** |

The demonstration is a deliberate scope exception; this project must not be described as satisfying
that particular proposal deliverable. The automated evaluation is retained for reproducibility.
