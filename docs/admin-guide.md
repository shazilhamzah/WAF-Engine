# WAF Studio — Administrator Guide

Owner: Wahaj (member C). For administrators who configure WAF Studio, manage users, approve exceptions and
review the audit trail. Read `docs/user-guide.md` first for the operator workflow; screen layouts are in
`docs/wireframes.md`, the authorization matrix and API in `docs/02-architecture.md` §2 and §5, the rule
language in `docs/rule-dsl.md`, and the setup procedure in `docs/setup-guide.md`.

## 1. First run and accounts

```bash
npm install          # express, http-proxy (no other runtime dependencies)
npm run setup        # creates data/, secret.key, the database, default rules, default config, users
npm start            # console http://127.0.0.1:3000 · WAF proxy http://127.0.0.1:8080 · lab target 127.0.0.1:3001
```

`npm run setup` creates **admin**, **operator**, **viewer** and **admin2** (a second administrator so that
separation of duties can be demonstrated). Passwords come from `WAF_ADMIN_PASSWORD`, `WAF_OPERATOR_PASSWORD`,
`WAF_VIEWER_PASSWORD`, `WAF_ADMIN2_PASSWORD`, or are generated and **printed once** — store them in a password
manager immediately; they are never written to disk in plain text. `npm run setup -- --reset-passwords` issues new
ones (and ends those users' sessions).

All listeners bind to `127.0.0.1` only. Ports and paths: `STUDIO_PORT`, `PROXY_PORT`, `TARGET_PORT`, `TARGET_URL`,
`WAF_DATA_DIR`, `WAF_DB_PATH`, `WAF_SECRET`.

## 2. Users and roles (Users page)

| Role | Grant to | Can |
|---|---|---|
| admin | the people who own the WAF | everything below + rules, configuration, exception approval, audit, users |
| operator | analysts | analyze/import, evidence, compare, replay, read rules/config, validate DSL, request exceptions, export reports |
| viewer | observers, students | dashboard and sanitized event summaries only |

* **Create user**: username (3–64 letters, digits, `.`, `_`, `-`), initial password (≥ 12 characters), role.
  Give the password through a safe channel and ask the user to change it on the **Account** page.
* **Change role**: pick the role and press **Apply**; a confirmation dialog shows *old → new*. Takes effect on the
  user's next request. You cannot change your own role from this page.
* **Disable / Enable**: confirmation required; disabling ends the user's sessions and blocks sign-in.
* **Set password**: recovery for a forgotten password or a lock-out (accounts lock temporarily after 5 failed sign-ins
  within 15 minutes; the *Status* column shows *locked until …*).
* Grant the **least privilege** needed; keep the number of admins small but ≥ 2 so exceptions can be reviewed by
  someone other than the requester.

Every change is audited (`user.create`, `user.update`).

## 3. Modes, thresholds, limits and rate limits (Config page)

| Setting | Meaning | Default |
|---|---|---|
| Mode | `block` enforces (requests at/above the block threshold get 403; rate-limited clients get 429). `monitor` never blocks: the decision is still computed and logged with *would block*. | block |
| Flag threshold | Score at which a request is flagged (still allowed). | 3 |
| Block threshold | Score at which a request is blocked (block mode). `1 ≤ flag ≤ block ≤ 100`. | 5 |
| Max body | Larger bodies are rejected with 413 `BODY_TOO_LARGE` before any rule runs. | 1 MiB |
| Inspected body | Bytes of the body the rules inspect; the rest raises `BODY_PARTIALLY_INSPECTED`. | 64 KiB |
| Max URL length / header count / args | Larger requests are rejected as `MALFORMED_REQUEST`. | 4096 / 100 / 200 |
| Decode rounds | URL-decoding passes; reveals double/triple encoding. | 3 |
| Rate limit | Per-client sliding window (enabled, window ms, max requests). | 300 / 60 s |

Workflow:

1. Change the fields and press **Review changes…**. The console checks ranges first.
2. The confirmation dialog lists every change as **current → new**. Switching to monitor shows an explicit warning
   that attacks will be forwarded to the target.
3. Enter the **reason** (required) and press **Apply change**. A new configuration **version** is stored with your
   name, time and reason, the proxy reloads it immediately, and a `config.update` audit event is written.
4. **Change history** lists every version with the diff against the previous one. To roll back, re-enter the old
   values (this creates a new version — history is never rewritten).

Use monitor mode when introducing new rules: run real traffic, review flagged/would-block events for false positives,
then switch back to block.

## 4. Rules and the DSL (Rules page)

Rules are written in the WAF Studio DSL (full grammar: `docs/rule-dsl.md`):

```
rule 942100 "SQLi boolean tautology" {
  when args matches /\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i
  severity critical
  score 5
  category sqli
  tags sqli, owasp-a03
  description "Tautology used to bypass WHERE clauses"
}
```

Editing workflow:

1. **+ New rule** loads a template; **Edit** loads an existing rule (operators see **View** and can only validate).
2. Press **Validate**. The server compiles the rule and either confirms it (id, name, severity, category, score) or
   lists errors as **Line L, col C: message** — click an error to jump to that position in the editor. Unsafe regular
   expressions (catastrophic backtracking) are refused.
3. **Save rule** creates the rule (enabled) or a new **version** of it. The ruleset version (hash) changes and the
   proxy reloads immediately.
4. **History** shows every version (create/update/enable/disable/delete) with who, when and the source.
5. **Disable** and **Delete** ask for confirmation first and send `confirm: true`; prefer disabling — it is reversible.
   Deleted rules keep their history.

Test every change: analyze a known-bad sample (must still match) and a known-good one (must not), or replay saved
events and compare before/after. The ruleset version recorded with each event tells you which rules produced it.

## 5. Approving exceptions (Exceptions page) — separation of duties

Operators request exceptions from a specific match; the request holds a rule id and a **scope** (path prefix,
location, method), a reason, the source event and an optional expiry.

* **Pending** tab: review each request. Open the source event, check the evidence, and use the impact preview
  (operators see it when requesting) — would the exception also hide real attacks?
* **Approve** (confirmation, optional note) — only an administrator **other than the requester** may approve or
  reject; the console disables those buttons on your own requests and the server refuses them (403, audited as
  `denied`). Approved exceptions apply immediately in the proxy and console.
* **Reject** with a note explaining why.
* **Approved** tab → **Revoke** (confirmation) when the exception is no longer needed; the rule applies again at once.
* Suppressed matches remain visible in every decision (*Suppressed by approved exceptions*), so tuning never hides
  evidence. Prefer narrow scopes and expiry dates; review the Approved tab regularly.

All steps are audited: `exception.request`, `exception.approve`, `exception.reject`, `exception.revoke`.

## 6. Audit console and chain verification (Audit page)

The audit log records sign-ins (success, failure, lockout), denials, password changes, configuration and rule
changes, submissions, imports, replays, exception workflow steps, exports, user administration, system start and
errors. Each record has: sequence number, time, actor and role, action, target, outcome (`success`, `failure`,
`denied`), the client pseudonym (`c_…`, an HMAC of the IP — raw IPs are never stored) and redacted details.

* **Filters**: action (e.g. `config.update`, `auth.login.failure`), actor, outcome, date range; 50 per page.
* **Verify chain** recomputes every record's SHA-256 hash from the previous one.
  `✔ Chain intact — N records checked` means nothing was altered. `⛔ Chain broken at seq N` means a record was
  modified or removed outside the application: stop WAF Studio, keep a copy of the database for investigation, and
  restore from your last good backup.
* The database itself refuses `UPDATE` and `DELETE` on the audit table; the API offers no way to modify it.

Suggested routine: verify the chain daily; review `auth.login.failure`, `auth.lockout`, `auth.denied` spikes;
confirm every `config.update` and `rule.*` has a sensible reason.

## 7. Rate limits

* **WAF proxy**: per-client sliding window from the configuration (default 300 requests / 60 s). Breaches return
  `429` in block mode (logged only in monitor mode) and appear in the evidence view's *Rate limit* section.
* **Sign-in**: 5 failures per username in 15 minutes, or 20 per client per minute → `429` with a retry time;
  repeated failures lock the account temporarily.
* **Console submissions** (analyze/import/replay) are rate-limited per user to keep the console responsive.

## 8. Reports

Admins and operators export sanitized HTML/CSV/JSON reports (see the user guide §9). The `report.export` audit event
records who exported which format, how many events and with which filters — never the content.

## 9. Backup, reset and recovery

State lives in `data/` (or `WAF_DATA_DIR`): `waf-studio.db` (+ `-wal`/`-shm` while running) and `secret.key`.

* **Backup**: stop WAF Studio (or ensure no writes), then copy the whole data directory. Keep backups private — they
  contain password hashes and the HMAC secret.
* **Restart**: everything persists across restarts (users, rules, versions, exceptions, events, audit).
* **Corruption / clean demo**: `npm run reset -- --yes` deletes the database (keeps `secret.key`; add `--new-secret`
  to rotate it), then `npm run setup` recreates defaults and new passwords. On start-up WAF Studio refuses a database
  that fails its integrity check and tells you to restore or reset.
* **Restore**: stop WAF Studio, replace the data directory with the backup, start, then **Verify chain** on the Audit
  page.

## 10. Security recommendations

1. Keep all listeners on `127.0.0.1`; never expose the vulnerable target or the console to a network.
2. Change generated passwords on first use; use long passphrases; disable accounts that are no longer needed.
3. Keep at least two administrators and never approve your own exceptions (the server enforces this).
4. Prefer monitor mode only temporarily; return to block mode after tuning.
5. Keep exceptions narrow (path + location) and time-limited; revoke unused ones.
6. Validate every rule change against known-good and known-bad samples; watch for new false positives on the dashboard.
7. Verify the audit chain regularly and after any incident; back up the data directory.
8. Protect `secret.key` (owner-only permissions are set automatically) or provide `WAF_SECRET` via the environment.
9. Treat exported reports as internal documents even though they are sanitized.
10. The console enforces a strict Content-Security-Policy and renders all request data as text; do not modify
    `public/` to insert HTML from data.
