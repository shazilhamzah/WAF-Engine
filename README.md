# WAF Studio — a learning, explainable Web Application Firewall

**Proposal 44 · Class 3, Group 12 · Domain: Web and Infrastructure Security**

WAF Studio is a local **reverse-proxy Web Application Firewall** that protects a deliberately vulnerable
test shop and **explains every decision**: which rule matched, where, after which decoding step, how many
points it added, which thresholds applied and what to do about it. Administrators tune rules, thresholds
and modes; operators analyze samples, compare history, request scoped exceptions and export sanitised
reports; viewers see summaries. Every security-relevant action lands in an append-only, hash-chained
audit log.

> ⚠️ **Lab only.** The bundled *Vulnerable Shop* is intentionally insecure and contains only fake data.
> Everything binds to `127.0.0.1`. Never expose it or point the proxy at systems you do not own — see
> [limitations and ethics](docs/limitations-and-ethics.md).

```
 Browser ──▶ Studio console :3000 (UI + JSON API) ──▶ security engine ◀── WAF proxy :8080 ──▶ Vulnerable Shop :3001
                       │                                                      ▲
                       └──────────── SQLite: rules · config · events · audit ─┘      curl / tester ──┘
```

## Quick start

Requirements: **Node.js ≥ 22.13** (built-in `node:sqlite`; developed on v24), npm, Git. No Docker, no
database server. Ports 3000, 3001 and 8080 on 127.0.0.1 must be free.

Run these in order from a fresh clone:

```bash
git clone <repository-url> WAF-Engine
cd WAF-Engine      # package.json is at the repository root
node --version     # must print v22.13 or newer
npm ci             # exact versions from package-lock.json (the only step that needs the internet)
npm run setup      # creates data/, the database, default rules and accounts — SAVE THE PRINTED PASSWORDS
npm test           # optional: all tests should pass
npm start          # Studio http://127.0.0.1:3000 · WAF proxy http://127.0.0.1:8080 · target :3001
```

`npm start` runs in the foreground; stop it with Ctrl+C. Startup and proxying print no deprecation
warnings (http-proxy's `DEP0060 util._extend` notice is filtered in `src/proxy/silenceDep0060.js`).

In a second terminal, try an attack through the WAF (on Windows PowerShell use `curl.exe`):

```bash
curl -i "http://127.0.0.1:8080/search?q=mug"                          # 200, X-WAF-Action: allowed
curl -i "http://127.0.0.1:8080/products?id=1%20OR%201%3D1"            # 403 block page with event id
curl -i --path-as-is "http://127.0.0.1:8080/files?name=../secret/flag.txt"   # 403 (traversal)
```

Sign in to the console as **operator**, open *Events*, and read the evidence for that event id.

Full instructions, curl examples, configuration, reset/recovery and Windows troubleshooting:
**[docs/setup-guide.md](docs/setup-guide.md)**.

## Commands

| Command | What it does |
|---|---|
| `npm run setup` | First-run setup (idempotent); `-- --reset-passwords` for lost passwords |
| `npm start` | Studio console + WAF proxy + vulnerable target |
| `npm run start:target` | Vulnerable target only (127.0.0.1:3001) |
| `npm test` | All automated tests (unit, integration, security) on ephemeral ports |
| `npm run test:unit` / `test:integration` / `test:security` | One test level |
| `npm run evaluate` | Mandatory evaluation T1–T6 + T-final + corpus metrics → `docs/evaluation/results.md` |
| `npm run fixtures:build` | Rebuild the four deterministic synthetic adverse fixture sets |
| `npm run bench` | T6 latency overhead (direct vs. via WAF) → `docs/evaluation/latency.json` |
| `npm run check` | Acceptance gate: tests ≥ 80 % pass + `npm audit` → `docs/evaluation/check-summary.json` |
| `npm run docs:pdf` | Final report → PDF (headless Edge/Chrome); `node scripts/build-pdf.js --all` for every doc |
| `npm run reset -- --yes` | Delete the database (recovery from corruption / clean demo), then `npm run setup` |

## What it demonstrates (proposal mapping)

| Requirement | Where |
|---|---|
| FR-1 Request parser — validation, normalisation, anomalies | `src/engine/parser.js`, `src/engine/normalize.js` |
| FR-2 Rule DSL — documented, validated, versioned | `src/engine/dsl.js`, `src/rules/default.rules`, `docs/rule-dsl.md` |
| FR-3 Scoring — per-rule contributions, categories, thresholds | `src/engine/scoring.js` |
| FR-4 Block / monitor modes | `src/engine/modes.js`, console Configuration page |
| FR-5 Rate limits — proxy and login | `src/engine/ratelimit.js`, `src/auth/rateLimit.js` |
| FR-6 Audit console — append-only hash chain, filters, verification | `src/db/repositories/audit.js`, console Audit page |
| FR-7 Tuning & exceptions — request, preview, approve (other admin), replay | `src/api/routes/exceptions.js`, console Exceptions page |
| Threat model (DFD, trust boundaries, 20 threats → mitigations → tests) | [docs/threat-model.md](docs/threat-model.md) |
| Test plan and results | [docs/test-plan.md](docs/test-plan.md), [docs/test-results.md](docs/test-results.md), [docs/evaluation/](docs/evaluation/) |

## Documentation

Final submission material: **[final report](docs/final-report.md)** ([PDF](docs/final-report.pdf)),
**[traceability matrix](docs/traceability.md)**, **[final test results](docs/test-results.md)** and
**[measured evaluation](docs/evaluation/results.md)**. The requested scope excludes the proposal's
separate 10-15 minute demonstration. Known bypass misses remain visible in the evaluation.

| Document | Contents |
|---|---|
| [docs/00-project-plan.md](docs/00-project-plan.md) | Team allocation, schedule, deliverables |
| [docs/01-requirements.md](docs/01-requirements.md) | Objectives, FR/NFR, evaluation cases, acceptance criteria |
| [docs/02-architecture.md](docs/02-architecture.md) | Integration contract: layers, engine interface, data model, API, proxy |
| [docs/threat-model.md](docs/threat-model.md) | Assets, actors, DFD with trust boundaries, STRIDE |
| [docs/test-plan.md](docs/test-plan.md) | Strategy, levels, T1–T6/T-final catalogue, traceability |
| [docs/test-results.md](docs/test-results.md) | Test and evaluation results |
| [docs/setup-guide.md](docs/setup-guide.md) | Install, run, attack examples, recovery, troubleshooting |
| [docs/user-guide.md](docs/user-guide.md) · [docs/admin-guide.md](docs/admin-guide.md) | Using the console per role |
| [docs/limitations-and-ethics.md](docs/limitations-and-ethics.md) | Lab-only use, synthetic data, known WAF limitations |

## Project layout

```
src/        studio API, auth, services, repository (SQLite), security engine, rules, proxy, reports
public/     browser console (strict CSP, no inline scripts)
target/     Vulnerable Shop lab application (LAB ONLY) and its fake files
fixtures/   safe sample inputs for the evaluation (T1–T5, corpora, large-body generator)
test/       unit, integration, security and evaluation tests + shared helpers
scripts/    setup, reset, evaluate, bench-latency, check, build-pdf
docs/       requirements, architecture, threat model, test plan/results, guides, diagrams, evaluation output
```

## Team

| Member | Role | Owns |
|---|---|---|
| Shazil | A — backend / data / authentication | Repository + audit store, auth, API, reverse proxy, bootstrap, setup/reset |
| Nufil | B — security engine / evaluation fixtures | Parser, rule DSL, scoring, modes, rate limiter, exceptions, redaction, default rules, fixtures |
| Wahaj | C — frontend / reporting / integration | Web console, report export, wireframes, user + admin guides |
| Saad | D — automation / security testing / packaging / QA | Vulnerable target, integration + security tests, evaluation harness, benchmark, check + PDF scripts, threat model, test plan/results, ethics, setup guide |

Stack: Node.js, Express 4, http-proxy, built-in SQLite (`node:sqlite`), vanilla JavaScript. Licence: MIT.
