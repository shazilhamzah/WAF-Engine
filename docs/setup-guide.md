# WAF Studio — Setup Guide

> Owner: Nufil. Everything runs locally from VS Code on an ordinary laptop with **Node.js only** — no
> Docker, no database server, no paid services, no internet access needed after `npm install`.
> Role guides: [user guide](user-guide.md) (operator/viewer), [admin guide](admin-guide.md).

## 1. Prerequisites

| Tool | Version | Check | Notes |
|---|---|---|---|
| Node.js | **≥ 22.13** (developed on v24) | `node --version` | Needed for the built-in `node:sqlite` and `node:test` modules. Install the LTS from nodejs.org or `winget install OpenJS.NodeJS.LTS` |
| npm | comes with Node | `npm --version` | |
| Git | any | `git --version` | To clone the repository |
| VS Code | any recent | | Optional but recommended |
| Microsoft Edge **or** Google Chrome | any recent | | Only for building PDFs (`npm run docs:pdf`). Edge ships with Windows |
| curl | any | `curl --version` | Optional, for trying attacks. Windows 10/11 include `curl.exe` |

Free ports **3000**, **3001** and **8080** on 127.0.0.1 (configurable, see §8).

## 2. Install

```bash
git clone <repository-url> WAF-Engine
cd WAF-Engine                     # package.json is at the repository root
npm ci                            # express, http-proxy (+ marked for the PDF build), exact lockfile versions
```

`npm ci` (or `npm install`) is the only step that needs the internet.

## 3. First-run setup — save the printed passwords

```bash
npm run setup
```

This is idempotent and:

1. creates `data/` and a random 32-byte `data/secret.key` (owner-only);
2. creates and migrates the SQLite database `data/waf-studio.db`;
3. loads the default rule set `src/rules/default.rules`;
4. writes configuration version 1 from the engine defaults (block mode, flag 3 / block 5);
5. creates the accounts **admin**, **operator**, **viewer** and **admin2** (a second administrator for the
   separation-of-duties demo — the person who requests an exception cannot approve it).

The passwords are **random and printed once**. They are not stored anywhere in plain text, so copy them
into a password manager immediately:

```
  Accounts (passwords are shown ONCE and are not stored anywhere in plain text):
    admin     admin     created         <random password>
    operator  operator  created         <random password>
    ...
```

To choose the passwords yourself, set environment variables before running setup (≥ 12 characters):

```powershell
# PowerShell
$env:WAF_ADMIN_PASSWORD = 'choose-a-long-passphrase'; $env:WAF_OPERATOR_PASSWORD = '...'; npm run setup
```
```bash
# bash
WAF_ADMIN_PASSWORD='choose-a-long-passphrase' WAF_OPERATOR_PASSWORD='...' npm run setup
```

(`WAF_VIEWER_PASSWORD`, `WAF_ADMIN2_PASSWORD` work the same way.)

## 4. Start

```bash
npm start
```

| URL | What |
|---|---|
| <http://127.0.0.1:3000> | **Studio console** — sign in as admin / operator / viewer |
| <http://127.0.0.1:8080> | **WAF proxy** — the Vulnerable Shop *protected* by WAF Studio. Use this for demos and attacks |
| <http://127.0.0.1:3001> | Vulnerable target directly (unprotected — only to compare; never expose it) |

Stop with **Ctrl+C**. All state persists in `data/` and is reloaded on the next start.

`npm run start:target` starts only the vulnerable target (useful when developing the target).

## 5. Try it — attacks through the proxy with curl

On Windows use `curl.exe` in PowerShell (plain `curl` is an alias for `Invoke-WebRequest`). Add `-i` to
see the `X-WAF-Action` and `X-WAF-Event-Id` headers.

```bash
# benign → forwarded, X-WAF-Action: allowed
curl -i "http://127.0.0.1:8080/search?q=mug"

# reflected XSS → 403 block page with an event id only
curl -i "http://127.0.0.1:8080/search?q=%3Cscript%3Ealert(1)%3C/script%3E"

# SQL injection (tautology / UNION)
curl -i "http://127.0.0.1:8080/products?id=1%20OR%201%3D1"
curl -i "http://127.0.0.1:8080/products?id=0%20UNION%20SELECT%20id,username,password%20FROM%20users"

# SQL injection in a login form
curl -i -X POST "http://127.0.0.1:8080/login" -d "username=' OR '1'='1' --&password=x"

# path traversal to the fake secret (use --path-as-is so curl does not normalise ../)
curl -i --path-as-is "http://127.0.0.1:8080/files?name=../secret/flag.txt"

# double encoding (decoded by the parser; evidence shows decodedVia)
curl -i "http://127.0.0.1:8080/search?q=%253Cscript%253E"

# oversized body → 413 before any rule runs
node -e "process.stdout.write('a'.repeat(2*1024*1024))" | curl -i -X POST --data-binary @- "http://127.0.0.1:8080/api/echo"

# compare with the unprotected target (the attack succeeds there)
curl "http://127.0.0.1:3001/products?id=1%20OR%201%3D1"
```

Then open the console → **Events**, find the event id from the block page, and read the evidence: rule
id and name, location (`query.id`), decoded value, score contributions, thresholds and the explanation.
Switch the mode to **monitor** (admin → Configuration) and repeat: the request now passes with
`X-WAF-Action: logged` and the event shows `wouldBlock: true`.

## 6. Tests, evaluation, benchmark, acceptance check

```bash
npm test                    # all tests (unit + integration + security), sequential, ephemeral ports
npm run test:unit
npm run test:integration
npm run test:security
npm run evaluate            # T1–T6 + T-final + corpus metrics → docs/evaluation/results.md + results.json
npm run evaluate -- --quick # fast smoke run (T6 with N = 100)
npm run bench               # T6 latency only → docs/evaluation/latency.json
npm run check               # acceptance gate: all tests, pass rate ≥ 80 %, npm audit → docs/evaluation/check-summary.json
```

Tests and the evaluation never touch `data/` or the fixed ports: each suite starts its own stack on
random 127.0.0.1 ports with a temporary database and deletes it afterwards, so you can run them while
`npm start` is running.

## 7. Build the PDFs

```bash
npm run docs:pdf                                  # docs/final-report.md → docs/final-report.pdf
node scripts/build-pdf.js docs/threat-model.md    # any document → PDF next to it
node scripts/build-pdf.js --all                   # every docs/*.md (+ README) → docs/pdf/
node scripts/build-pdf.js --html-only docs/test-plan.md   # just the print HTML in .tmp/pdf/
```

The builder auto-detects Microsoft Edge or Google Chrome. If neither is found, pass
`--browser "C:\path\to\chrome.exe"` or set `WAF_PDF_BROWSER`. It uses a private browser profile in
`.tmp/`, so an open browser window is not affected.

## 8. Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `STUDIO_PORT` | 3000 | Studio console |
| `PROXY_PORT` | 8080 | WAF proxy |
| `TARGET_PORT` | 3001 | Vulnerable target |
| `TARGET_URL` | `http://127.0.0.1:3001` | Upstream for the proxy |
| `WAF_DATA_DIR` | `./data` | Database + secret key directory |
| `WAF_DB_PATH` | `<WAF_DATA_DIR>/waf-studio.db` | SQLite file |
| `WAF_SECRET` | generated `secret.key` | HMAC secret (≥ 16 characters) |

PowerShell: `$env:PROXY_PORT = 8081; npm start` · bash: `PROXY_PORT=8081 npm start`.

## 9. Reset and recovery

| Situation | What to do |
|---|---|
| **Lost passwords** | Stop WAF Studio, then `npm run setup -- --reset-passwords`. New passwords are printed once; all existing sessions end. Rules, config, events and audit are kept |
| **Corrupted database** (start fails with "Database integrity check failed") | Stop WAF Studio. Optionally copy `data/` aside for analysis. Run `npm run reset -- --yes`, then `npm run setup`. This deletes users, rules, events, exceptions and the audit log; the secret key is kept |
| **Fresh demo state** | `npm run reset -- --yes` then `npm run setup` |
| **Rotate the secret key** | `npm run reset -- --yes --new-secret` then `npm run setup` (client pseudonyms change) |
| **Backup** | Stop WAF Studio and copy the whole `data/` folder (database, `-wal`, `secret.key`). Restore by copying it back |
| **Check audit integrity** | Admin → Audit → *Verify chain* (or `GET /api/audit/verify`). `ok: false` + `brokenAt` = tampering or corruption from that entry onwards; keep a copy of `data/` as evidence before resetting |

Recovery after a crash needs no action: state is in SQLite (WAL mode) and is reloaded on `npm start`.
The evaluation case **TF-11** verifies this automatically (stop → restart on the same database → rules,
configuration, events and the audit chain survive and verify).

## 10. Troubleshooting (Windows)

| Symptom | Fix |
|---|---|
| `EADDRINUSE 127.0.0.1:3000` (or 8080 / 3001) | Another process uses the port. Find it: `netstat -ano \| findstr :8080`, then `taskkill /PID <pid> /F`, or start on other ports (§8) |
| `No such built-in module: node:sqlite` / `DatabaseSync is not a constructor` | Node is too old — install ≥ 22.13 and reopen the terminal |
| `ExperimentalWarning: SQLite is an experimental feature` | Harmless on Node 22/24 |
| `curl` in PowerShell behaves strangely | Use `curl.exe`, or run the commands in Git Bash |
| Path-traversal attempt reaches `/files?name=secret/flag.txt` instead | curl normalised `../`; add `--path-as-is` |
| Login says "Too many attempts" (429) | Lockout after 5 failures for that user (15 min) or 20 attempts/min from your machine; wait, or reset passwords (§9) |
| PDF build: "No Chromium browser found" | Install Edge/Chrome or pass `--browser` (§7) |
| PDF build hangs or produces nothing | Close stray headless browser processes (`taskkill /IM msedge.exe /F` — closes all Edge windows) and retry |
| Antivirus / Windows Defender slows `npm install` or tests | Exclude the project folder or wait; nothing listens on external interfaces |
| Tests fail with `EBUSY` deleting temp files | A previous run is still open; rerun — temp dirs are removed with retries |
| Line-ending warnings from Git (`LF will be replaced by CRLF`) | Harmless |

## 11. VS Code tips

* **Open the `Project` folder** (the one with `package.json`) as the workspace root so npm scripts and
  the Testing view work.
* **NPM Scripts** panel (Explorer → NPM Scripts): one click for `start`, `test`, `evaluate`, `check`.
* **Testing view**: VS Code discovers `node:test` files; run or debug a single test from the gutter.
* **Debug**: *Run and Debug* → "JavaScript Debug Terminal", then `npm start` or
  `node --test test/integration/proxy.test.js` — breakpoints work in `src/` and `test/`.
* Markdown preview (`Ctrl+Shift+V`) renders the docs and the DFD SVG.
* The REST Client extension can replay `curl` examples; keep requests pointed at 127.0.0.1.

## 12. Project layout

```
src/index.js            starts studio + proxy + target (startAll)
src/api/, src/auth/     Studio API: routes, validation, sessions, CSRF, RBAC, errors
src/services/           engine state, analysis, audit, redaction, seeding
src/db/                 SQLite repositories + schema (append-only audit triggers)
src/engine/             security engine: parser, DSL, scoring, modes, rate limiting, exceptions
src/rules/              default rule set (DSL)
src/proxy/              WAF reverse proxy (http-proxy) + block pages
src/reports/            JSON / CSV / HTML export
public/                 browser console (no inline scripts, strict CSP)
target/                 Vulnerable Shop lab app (LAB ONLY) + fake files
fixtures/               safe sample inputs: T1–T5 cases, corpora, large-body generator
test/unit/              module tests (each owner)
test/integration/       end-to-end workflow, proxy, exceptions, target
test/security/          authorization matrix, CSRF/sessions, injection, secrets, audit, import, errors
test/evaluation/, test/helpers/   evaluation library and shared test helpers
scripts/                setup, reset, evaluate, bench-latency, check, build-pdf
docs/                   requirements, architecture, threat model, test plan/results, guides, evaluation
data/                   runtime database + secret key (git-ignored)
```
