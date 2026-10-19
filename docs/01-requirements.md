# WAF Studio — Requirements

Derived directly from Proposal 44. IDs are referenced from code comments, tests and `docs/traceability.md`.

## 1. Users

| Role | Description |
|---|---|
| Administrator | Configures the system (mode, thresholds, rules, rate limits, users), approves exceptions, reviews audit records |
| Operator / analyst | Runs the normal workflow: submits/imports samples, reviews decisions and evidence, compares history, requests exceptions, exports reports |
| Viewer (restricted) | Sees dashboard and sanitized event summaries only; cannot see evidence, configuration or audit records |

Authorization is enforced by the server for every endpoint.

## 2. Objectives

| ID | Objective |
|---|---|
| OBJ-1 | Complete input-to-result workflow for web request inspection |
| OBJ-2 | Every warning, score, allow/deny decision is explainable |
| OBJ-3 | Stored data, credentials, sessions, uploads and logs protected according to a threat model |
| OBJ-4 | Effectiveness measured with repeatable positive, negative, edge-case and misuse tests |

## 3. Functional requirements

Each module must **validate its input, report a clear result, and record security-relevant actions without retaining unnecessary sensitive data**.

| ID | Module | Acceptance (how it is demonstrated) |
|---|---|---|
| FR-1 | Request parser | Malformed/oversized requests rejected with explicit anomaly codes; encodings normalized; decoded-via evidence recorded |
| FR-2 | Rule DSL | Rules written in a documented DSL; invalid rules rejected with line/column errors; unsafe regexes refused; versions recorded |
| FR-3 | Scoring | Anomaly score with per-rule contributions, per-category breakdown and thresholds stored with the decision |
| FR-4 | Block/monitor modes | Same attack is blocked in block mode and allowed-but-logged (`wouldBlock`) in monitor mode; mode changes audited |
| FR-5 | Rate limits | Per-client sliding window; breach returns 429 (block mode) with evidence; login endpoint rate-limited and lockout |
| FR-6 | Audit console | Append-only hash-chained audit log with filters and verification; event history with filters, detail, compare |
| FR-7 | Tuning & exception workflow | Operator requests a scoped exception from an event, previews impact; a different admin approves; replay shows the changed, traceable decision |

## 4. Non-functional / security requirements

| ID | Requirement |
|---|---|
| NFR-1 | Layered architecture: browser, API/service, security engine, repository, fixtures |
| NFR-2 | scrypt password hashing, session expiry (30 min idle / 8 h absolute), server-side authorization, least privilege |
| NFR-3 | CSRF protection for cookie sessions; SameSite=Strict, HttpOnly cookies |
| NFR-4 | Parameterized SQL; server-generated identifiers; strict server-side validation of type, size, structure, fields |
| NFR-5 | Stable error codes; no stack traces |
| NFR-6 | Secrets protected (generated key file, env override), redacted from logs and exports |
| NFR-7 | Rate limiting on sensitive actions (login, analysis submission) |
| NFR-8 | Logging of login, configuration change, submission, decision, export, failure and admin activity |
| NFR-9 | Runs locally from VS Code on an ordinary laptop with Node.js only (no Docker, no paid services) |
| NFR-10 | Responsive, keyboard-accessible UI; strict Content-Security-Policy |
| NFR-11 | Recovery: state persists in SQLite and survives restart; documented reset/recovery steps |

## 5. Evaluation cases (mandatory)

| ID | Case |
|---|---|
| T1 | SQLi / XSS / path traversal strings |
| T2 | Encoding variants |
| T3 | Benign false positives |
| T4 | Large bodies |
| T5 | Bypass attempts |
| T6 | Latency overhead |
| T-final | Malformed/oversized input, unauthorized request, repeated submission, safe failure, recovery after restart |

Each case records input, expected result, actual result, evidence and pass/fail.

## 6. Acceptance criteria

* All functional requirements demonstrable.
* ≥ 80 % of automated tests pass; zero unresolved critical authorization, injection, secret-exposure or unsafe-file-handling defects.
* Report coverage, false positives, false negatives and decision latency.
* Every report claim links to a test, log excerpt or measured result.

## 7. Scope

**In scope:** responsive web interface, local API, persistent data store, protection component, evidence view, exportable result.
**Out of scope:** production hosting, paid services, native mobile, real-world attack deployment, unapproved external targets.
