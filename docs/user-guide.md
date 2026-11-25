# WAF Studio — User Guide (operator and viewer)

Owner: Wahaj (member C). This guide covers the browser console for the **operator / analyst** and the
restricted **viewer**. Administrators should also read `docs/admin-guide.md`. Screen layouts are in
`docs/wireframes.md`; the API behind every screen is in `docs/02-architecture.md` §5.

> WAF Studio is a local learning tool. Only send traffic to the bundled, deliberately vulnerable lab
> target. Never point it at systems you do not own or have no written permission to test.

## 1. What you can do, by role

| Task | operator | viewer |
|---|:-:|:-:|
| Sign in, change own password, sign out | ✓ | ✓ |
| Dashboard (totals, timeline, top rules, latency) | ✓ | ✓ |
| Events list (sanitized summaries) | ✓ | ✓ |
| Event evidence, compare, replay | ✓ | — |
| Analyze a sample, import a sample file | ✓ | — |
| Read rules and configuration, validate rule DSL | ✓ | — |
| Request an exception (tuning) and preview its impact | ✓ | — |
| Export reports (HTML / CSV / JSON) | ✓ | — |

Links you cannot use are not shown. If you open such a page directly (for example a bookmarked
`#/events/evt_…` as a viewer) you see **"Not available for your role"**. The server enforces the same rule:
it answers with a generic `403` that reveals nothing about the record, and records an `auth.denied` audit event.

## 2. Signing in and sessions

1. Start WAF Studio (`npm start`) and open the console URL printed in the terminal (default `http://127.0.0.1:3000`).
2. Enter the username and password an administrator gave you and press **Sign in**.
   * A wrong username or password always shows the same message, *"Invalid username or password."* — the
     console never tells you which part was wrong.
   * After repeated failures sign-in is paused: the button is disabled and a countdown shows when you may try again.
     Five failures within 15 minutes lock the account temporarily; ask an administrator if you are locked out.
3. Your session ends after **30 minutes without activity** or **8 hours** in total. When it ends the console
   returns to the sign-in screen with *"Your session has expired"*; nothing you have not submitted is sent.
4. **Account** (top right) shows your role and session expiry and lets you change your password
   (at least 12 characters; a passphrase of several words works well). **Log out** ends the session on the server.

The header shows one protection indicator: **Enabled** (block mode) or **Monitoring only**
(monitor mode). Oversized bodies still exceed the proxy's safety limit even in monitor mode.

Navigation is grouped into **Activity**, **Tools**, **Policy**, and (for admins) **Administration**.
Policy/Administration expand when needed. **Account** appears once in the header, not the sidebar.

## 3. Overview (dashboard)

* **Three cards**: total inspections, blocked and passed for the selected time range (1 hour to 7 days).
  Passed includes monitor-only outcomes; flagged is an overlapping detection verdict and is shown as
  a supporting count, not added to the total. These are inspection records from proxy traffic,
  manual analyses, imports and replays, not a count of proxy traffic alone.
* **Recommended action** links to relevant filtered events or to request analysis when appropriate.
* **Inspection activity** shows hourly outcomes in local time, with dates for multi-day ranges and per-bar tooltips.
* **Detected patterns** uses readable category names. **Matched rules** expands to show rule IDs,
  names and match counts without competing with the main overview.
* **Recent inspections** shows the latest five records within the same selected time window.
  One outcome badge distinguishes blocked, passed, flagged-but-passed and would-block-in-monitor
  records. Full verdict/action/score evidence remains on the event detail screen.
* **System details** expands to show full ruleset/config versions and latency statistics.
* **Refresh** updates the snapshot and the single global protection indicator.

Current screenshots: [desktop](images/dashboard-desktop.png), [phone width](images/dashboard-mobile.png).

## 4. Analyzing a request (Analyze)

1. Open **Tools → Analyze** (`Single request` tab). Optionally choose from the **Load example…** dropdown in the header:
   * `✔ Benign search`, `✔ Benign name with apostrophe`, `✔ Benign JSON comment` — normal inputs, including
     classic false-positive candidates (an apostrophe; the words *select* and *union* in prose).
   * `⚠ SQL injection`, `⚠ Cross-site scripting`, `⚠ Path traversal`, `⚠ Double-encoded traversal` — textbook
     attack indicators for the lab target.
2. Adjust **Method**, **Path and query** (must start with `/`; URL-encode spaces as `%20`), **Headers** (name/value
   rows; *+ Add header*, *✕* to remove) and **Body**. Give it a **Label** so you can find it later.
3. Press **Analyze**. The console checks the obvious problems first (method, path, header names, sizes) and lists them
   if anything is wrong; the server validates everything again.
4. The **Result** card appears with the unified outcome badge, the score bar with the flag and block thresholds,
   the explanation and the recommendation. Press **Open full evidence →** for the complete record.

Repeated submissions are rate-limited; if you see *"Too many requests. Try again in N seconds."* wait and retry.

## 5. Importing samples (Batch import tab)

* Open **Tools → Analyze** and select the **Batch import (.json)** tab (or visit `#/import`).
* Choose a `.json` file of at most **256 KB** with at most **100 samples**: either an array of samples or
  `{ "samples": [ … ] }`. Each entry is a sample (`{ "method": "GET", "path": "/search?q=shoes", "headers": {}, "body": null }`)
  or `{ "label": "…", "sample": { … } }`.
* The console shows how many entries are valid and why the others are not, and previews the valid ones.
  Nothing is sent until you press **Import N samples**.
* The server validates the file again and returns the created events (links to their evidence) and any entries it
  rejected with a reason.

## 6. Reading a decision — the evidence view

Open an event from **Events**, the dashboard, or the Analyze result. The view is organized into a summary bar and three cards:

| Section | What it tells you |
|---|---|
| Summary bar | Unified **Outcome** badge (`Passed`, `Flagged · passed`, `Would block · monitor`, `Blocked`), HTTP status chip when blocked, event source/label and the request `METHOD /path`. |
| Decision & score | The anomaly score bar against the **flag** and **block** thresholds (dashed markers), the per-category breakdown, the tuning recommendation, block reason (if blocked) and expandable **Decision steps** explaining each rule/anomaly contribution. |
| Rule matches | Per match: rule id and name, severity, points, category, **location** (`query.q`, `body.comment`, `header.user-agent`, …), the **matched excerpt** (shown as inert text, at most 120 characters, secrets masked) and **decoded via** chips (`url`, `html`, `unicode` …). Also includes expandable **Suppressed by exceptions**, **Parser anomalies** and **Rate limit** sections when present. |
| Request & metadata | Sanitized request parameters, body sizes, user agent, timestamps, timings, engine/ruleset/config versions, client pseudonym (`c_…`, never the IP), and expandable **Stored sample (redacted)** and **Raw decision JSON** views. |

What a **normal** sample looks like: `✔ Passed`, score below the flag threshold, *"No rule matched this request."*.
What a **seeded adverse** sample looks like: `■ Blocked` (or `⚑ Flagged · passed`), the exact rule, location and
excerpt that triggered it — never just "unsafe".

### Actions on an event

* **↻ Replay** (console and import events): re-runs the stored sample with today's rules,
  thresholds and exceptions and opens the new event, which links back to the original. Proxy events cannot be
  replayed because their bodies are not stored.
* **Compare with original** (on replays) / **Compare…**: opens the compare view.
* **⇩ Export**: downloads a report for just this event in the chosen format (`html`, `csv`, `json`).
* **Request exception** (per match): opens the exception form pre-filled with the rule id, location, path and method.

## 7. History, comparison and export (Events, Compare)

* **Filters**: search text (path, label, event id, method), verdict, source (`proxy`, `console`, `import`, `replay`),
  date range, and expandable **More filters** (`Action`, `Rule id`). Filters live in the address bar, so Back/Forward and bookmarks work.
* Results are paged 50 at a time (**‹ Previous / Next ›**) and show a single unified **Outcome** badge per row.
* **Compare**: tick **two** events and press **Compare (2/2)**. The compare view highlights all differing fields (`≠`) at the top and groups identical fields into an expandable **Unchanged fields** section.
* **Export**: choose `html`, `csv` or `json` in the **Events** header and press **⇩ Export** to download a report for either the selected events or the current filter set (or use `#/reports` for a standalone export form).

## 8. Requesting an exception (tuning a false positive)

1. From the evidence view press **Request exception** on the match you believe is a false positive.
2. Keep the scope **narrow**: a path prefix and/or a location, optionally a method. A rule-wide exception is refused
   by the form. Write a clear **reason** and, if possible, an **expiry date**.
3. Press **Preview impact** to see how many recent events this exception would have suppressed, with examples.
   If the number is surprisingly large, narrow the scope.
4. **Submit request**. The request is *pending* until an administrator **other than you** approves it
   (separation of duties). Track it under the **Pending / Approved / Rejected / Revoked** tabs.
5. Once approved, replay the original event: the match moves to *Suppressed by approved exceptions*, the score drops,
   and the comparison shows exactly what changed and why.

## 9. Exporting reports

Open **Reports**, choose **HTML** (readable, self-contained), **CSV** (spreadsheet; one row per event) or **JSON**
(machine-readable), optionally a date range, verdict and specific event ids (up to 500), and press
**⇩ Download report**. Without ids the most recent matching events are exported (at most 1 000).

Every report contains the generator, time, filters, ruleset and configuration versions, summary metrics (counts by
verdict and action, false-positive review figures, top rules, categories, latency) and, per event, the decision,
explanation, matches and recommendation. Reports are sanitized: redacted excerpts only, no stored samples, secret
headers, cookies, client pseudonyms or session data; HTML is escaped and script-free; CSV cells that could be read as
spreadsheet formulas are prefixed with `'`. Each export is recorded in the audit log (format, count and filters, never
the content).

## 10. Walkthrough — the proposal's illustrative example

This reproduces the scenario on page 3 of the proposal end to end.

1. **Operator signs in** as `operator` → Dashboard shows mode `⛔ BLOCK`, ruleset and config versions.
2. **Safe input**: Analyze → *Load example: Benign search* → label `normal search` → **Analyze**.
   Expected: `✔ allow`, action `allowed`, score 0, "No rule matched; no warnings." (completed status, no unjustified critical warning).
3. **Suspicious variant**: *Load example: SQL injection (tautology)* → label `suspicious variant` → **Analyze**.
   Expected: `⛔ block`, action `blocked`, HTTP 403; the match table names the SQLi rule, location `query.q`,
   excerpt `' OR 1=1--` and a `url` decoded-via chip — the particular indicator, not just "unsafe". Try the
   double-encoded traversal too: the chips show `url` decoding was needed (twice) and a `DOUBLE_ENCODING` anomaly.
4. **Compare in history**: Events → tick both events → **Compare selected** → verdict `allow → block`, score `+N`,
   rules added highlighted.
5. **Export a sanitized report**: Reports → HTML → both event ids → **Download report**.
6. **Administrator changes one permitted rule or threshold** (see the admin guide): e.g. Config → raise the block
   threshold above the SQLi score, reason "demo: tune threshold", confirm. A new configuration version is created and
   audited.
7. **Repeat the test**: open the `suspicious variant` event → **Replay with current rules** → the new event shows
   `⚑ flag` / `allowed` with the new thresholds; **Compare with original** shows *Configuration version changed* and
   the verdict change — both the new result and the configuration change are traceable (Audit: `config.update`,
   `event.replay`).
8. **Unauthorized viewer**: sign in as `viewer` and open the event URL → *Not available for your role*; the server
   returned a generic 403 and logged `auth.denied` without exposing the record.

## 11. Accessibility and devices

* Everything works with the keyboard: **Skip to content** is the first Tab stop, focus is always visible,
  dialogs trap focus, **Esc** closes them and focus returns to the button that opened them.
* Status messages are announced (`aria-live`); errors are prefixed with "Error:".
* Colour is never the only signal — every badge has an icon and a word, changed rows say "≠ changed".
* The console follows your system's light/dark preference and works on phones down to 360 px wide
  (menu button, stacked cards instead of wide tables).

## 12. Troubleshooting

| Message | Meaning / what to do |
|---|---|
| Invalid username or password. | Check both; after several failures wait for the countdown or ask an admin. |
| Your session has expired. | Sign in again (30 min idle / 8 h maximum). |
| This action is not available for your role. | The server refused (403). Ask an administrator if you need the permission. |
| Your session security token is out of date. | Reload the page (CSRF token rotated, e.g. after signing in elsewhere). |
| Too many requests. Try again in N seconds. | Rate limit on sign-in or submissions; wait. |
| Validation failed — field: message | Fix the named field; the server explains each problem. |
| Cannot reach the WAF Studio server. | Is `npm start` still running? |
