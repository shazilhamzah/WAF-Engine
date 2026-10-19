# WAF Studio — Project Plan and Team Allocation

**Proposal:** 44 — WAF Studio: Learning Web Application Firewall
**Assignment:** Class 3, Group 12 · **Domain:** Web and Infrastructure Security
**Source of truth:** `Copy of 44_Class_3_Group_12_WAF_Studio_Learning_Web_Application_Firewall.pdf` (project root)

## 1. Goal

Build a reverse-proxy-style local WAF that applies explainable rules to a deliberately vulnerable local
test application. It must be a working, locally demonstrable security system with measurable evidence.

## 2. Team allocation (from the proposal's four-person model)

| Member | Proposal role | Owns |
|---|---|---|
| **Shazil** | A — backend / data / authentication | SQLite repository layer, append-only audit store, auth (password hashing, sessions, CSRF, lockout), API/service layer, WAF reverse proxy, process bootstrap, data model + API docs |
| **Saad** | B — security engine / evaluation fixtures | Request parser, Rule DSL (lexer/parser/validator/compiler), scoring, block/monitor modes, rate limiter, exception matching, redaction, default rule set, safe sample fixtures, engine unit tests, DSL + engine docs |
| **Wahaj** | C — frontend / reporting / integration | Responsive accessible web console (dashboard, analyze, history/compare, evidence view, rules editor, config, exceptions workflow, audit console, users), report export (JSON/CSV/HTML), wireframes, user + admin guides |
| **Nufil** | D — automation / security testing / packaging / QA | Deliberately vulnerable target app, integration + security tests, evaluation harness (T1–T6, T-final), latency benchmark, setup/reset/check scripts, PDF build, threat model, test plan/results, limitations & ethics, setup guide |
| **Master** (integration lead) | — | Contracts, integration, traceability matrix, final report, progress tracking |

Everyone must understand the full system; each member's docs explain their part for the others.

## 3. Five-week plan mapping (proposal schedule)

| Week | Proposal scope | Where it lives |
|---|---|---|
| W1 | Requirements, research, threat model, wireframes, architecture, test data | `docs/01-requirements.md`, `docs/02-architecture.md`, `docs/threat-model.md`, `docs/wireframes.md`, `fixtures/` |
| W2 | Data model, authentication, API skeleton, one end-to-end slice | `src/db`, `src/auth`, `src/api`, `docs/data-model.md`, `docs/api.md` |
| W3 | Security engine, dashboard, audit trail, features | `src/engine`, `public/`, audit repository |
| W4 | Integration, adversarial tests, measurement, accessibility, hardening | `test/`, `scripts/evaluate.js`, `scripts/bench-latency.js` |
| W5 | Fixes, evaluation, documentation, packaging | `docs/test-results.md`, `docs/final-report.md` (+PDF) |

## 4. Deliverables checklist (proposal page 3)

| Deliverable | Location |
|---|---|
| Source and setup guide | `src/`, `public/`, `target/`, `README.md`, `docs/setup-guide.md` |
| Sanitized sample data | `fixtures/` |
| Architecture / data-flow diagrams | `docs/02-architecture.md`, `docs/threat-model.md` |
| Threat model (DFD, trust boundaries, ≥8 threats → mitigations) | `docs/threat-model.md` |
| Test plan / results | `docs/test-plan.md`, `docs/test-results.md`, `docs/evaluation/` |
| User and administrator guide | `docs/user-guide.md`, `docs/admin-guide.md` |
| Limitations and ethics statement | `docs/limitations-and-ethics.md` |
| Final report | `docs/final-report.md`, `docs/final-report.pdf` |
| Demonstration | Omitted at the user's explicit instruction on 2026-10-20; no 10-15 minute walkthrough or demo artifact is included. The automated evaluation remains available. |

## 5. Working method

1. The master wrote `docs/02-architecture.md` (the **integration contract**) first: data model, roles, input schema,
   decision schema, audit-event format, API surface, module interfaces and file ownership — as the proposal
   requires ("define … before building screens").
2. The four members built their areas in parallel against that contract, committing in small steps.
3. The master integrated, ran the full test suite, and resolved cross-module defects.
4. Nufil supplied the phase-1 harness and handover; integration continued with the missing adverse fixtures, final measured evaluation, final report and traceability matrix. See `docs/PROGRESS.md` for the handover boundary.

Progress is tracked in `docs/PROGRESS.md` (master) and `docs/progress/<member>.md` (per member).
