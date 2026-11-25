# WAF Studio — Console Wireframes

Owner: Wahaj (member C). Written **before** the screens were built, as the proposal requires
("Define the data model, roles, input schema, decision/result schema, and audit-event format before
building screens"). The screens consume the API in `docs/02-architecture.md` §5 and render the
Decision schema in §3.6.

> **UI refinement, 2026-10-20:** the original pre-build sketches below remain as a design record.
> The current shell groups Activity/Tools/Policy/Administration, places Account only in the header,
> and shows one calm protection indicator. The dashboard now uses a total card plus two outcome cards,
> an activity chart, category breakdown, five recent inspections with a single outcome, and
> expandable rule/system detail. All dashboard data uses the selected time window.
> Current visual evidence: [desktop](images/dashboard-desktop.png), [mobile](images/dashboard-mobile.png).
> Current instructions: [user guide](user-guide.md#3-overview-dashboard).

## 1. Design principles

| Principle | How the console applies it |
|---|---|
| Explainable output | Every decision shows verdict **and** action, score vs thresholds, the rule/location/excerpt that caused it, and a plain-language explanation and recommendation. Never just "unsafe". |
| Server is the authority | The UI hides controls a role cannot use, but every action is re-checked by the API. A 403 shows a generic "not available for your role" panel. |
| Hostile data is displayed safely | Attack payloads are evidence. They are only ever inserted with `textContent` inside `<code>`; no `innerHTML` with data, strict CSP (`script-src 'self'`, `style-src 'self'`). |
| Confirmation for high-impact actions | Mode/threshold change, disabling/deleting a rule, approving/revoking an exception, disabling a user, changing a role: modal dialog with an old→new summary, then the request carries `confirm: true`. |
| Colour is never the only signal | Badges carry text + a symbol (`✔ allow`, `⚑ flag`, `⛔ block`), bars carry numeric labels. |
| Responsive | One column below 720 px, navigation collapses into a menu button; tables become stacked cards; no horizontal page scroll at 360 px. |
| Accessible | Landmarks (`header`, `nav`, `main`), skip link, labels on every input, visible focus ring, `aria-live` status region, dialogs with focus trap + Esc, tables with `<th scope>`. |

## 2. Navigation map and role visibility

```
                 ┌────────────┐
                 │  #/login   │  (public)
                 └─────┬──────┘
                       │ 200 login
                       ▼
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ #/dashboard ─ #/analyze ─ #/import ─ #/events ─ #/rules ─ #/config ─         │
 │ #/exceptions ─ #/audit ─ #/reports ─ #/users ─ #/account                     │
 └──────────────────────────────────────────────────────────────────────────────┘
   #/events ──click row──▶ #/events/<id>  (evidence view)
   #/events ──select 2───▶ #/compare?a=<id>&b=<id>
   #/events/<id> ─Replay─▶ #/events/<newId>  (+ "compare with original" link)
   #/events/<id> ─Request exception─▶ #/exceptions?new=1&ruleId=…&location=…&path=…&event=…
   #/analyze ─submit─▶ inline decision panel ─"Open evidence"─▶ #/events/<id>
   any 401 ─▶ #/login (with "session expired" notice)    any 403 ─▶ "not available for your role"
```

| Screen (route) | admin | operator | viewer |
|---|:-:|:-:|:-:|
| Login `#/login` | ✓ | ✓ | ✓ |
| Dashboard `#/dashboard` | ✓ | ✓ | ✓ |
| Analyze `#/analyze` | ✓ | ✓ | role panel |
| Import `#/import` | ✓ | ✓ | role panel |
| Events list `#/events` | ✓ | ✓ | ✓ (summaries, no links to detail, no compare) |
| Event detail `#/events/<id>` | ✓ | ✓ | role panel |
| Compare `#/compare` | ✓ | ✓ | role panel |
| Rules `#/rules` | ✓ edit | ✓ read + validate | role panel |
| Config `#/config` | ✓ edit | ✓ read | role panel |
| Exceptions `#/exceptions` | ✓ request + review (not own) | ✓ request | role panel |
| Audit `#/audit` | ✓ | role panel | role panel |
| Reports `#/reports` | ✓ | ✓ | role panel |
| Users `#/users` | ✓ | role panel | role panel |
| Account `#/account` | ✓ | ✓ | ✓ |

Navigation links that a role cannot use are not rendered at all; typing the route by hand shows the
role panel ("This page is not available for your role (viewer)."), and the server would return 403 anyway.

## 3. Application shell

### Desktop (≥ 720 px)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ [Skip to content]                                                                    │
│ ◆ WAF Studio      Mode: [⛔ BLOCK]                  alice (operator)  [Account] [Log out]│
├───────────────┬──────────────────────────────────────────────────────────────────────┤
│ Dashboard     │  <h1>Page title</h1>                                                 │
│ Analyze       │                                                                      │
│ Import        │  ┌ status (aria-live) ───────────────────────────────────────────┐   │
│ Events        │  │ ✔ Saved. / ⚠ Error message                                     │   │
│ Rules         │  └───────────────────────────────────────────────────────────────┘   │
│ Config        │                                                                      │
│ Exceptions    │  page content                                                        │
│ Audit         │                                                                      │
│ Reports       │                                                                      │
│ Users         │                                                                      │
└───────────────┴──────────────────────────────────────────────────────────────────────┘
```

### Mobile (360 px)

```
┌────────────────────────────────┐
│ ◆ WAF Studio  [⛔ BLOCK] [☰ Menu]│
├────────────────────────────────┤
│ (menu expands as a vertical    │
│  list under the header)        │
│ <h1>Page title</h1>            │
│ status region                  │
│ content, single column         │
└────────────────────────────────┘
```

## 4. Login

```
Desktop                                         Mobile
┌──────────────────────────────────────┐        ┌──────────────────────────┐
│            ◆ WAF Studio              │        │ ◆ WAF Studio             │
│   ┌──────────────────────────────┐   │        │ Sign in                  │
│   │ Sign in                      │   │        │ Username [____________]  │
│   │ Username [_________________] │   │        │ Password [____________]  │
│   │ Password [_________________] │   │        │ [ Sign in ]              │
│   │ [ Sign in ]                  │   │        │ ⚠ Invalid username or    │
│   │ ⚠ Invalid username or        │   │        │   password.              │
│   │   password.                  │   │        └──────────────────────────┘
│   └──────────────────────────────┘   │
│ ⓘ Your session expired. Sign in again.│
└──────────────────────────────────────┘
```

* One generic failure message for unknown user, wrong password and disabled account (no enumeration).
* 429 → "Too many attempts. Try again in N seconds." (from `retryAfterSeconds`); button disabled for that time.

## 5. Dashboard

```
Desktop
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Dashboard                          Window: [24 h ▾]  [↻ Refresh]                     │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐                           │
│ │Requests │ │✔Allowed │ │⚑Flagged │ │✎ Logged │ │⛔Blocked │                           │
│ │  1 204  │ │  1 120  │ │   41    │ │   12    │ │   72    │                           │
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘                           │
│ Mode ⛔ BLOCK · Ruleset sha256-3f9a… · Config v7 · Latency p50 0.4 ms / p95 1.2 ms       │
│                                                                                      │
│ Hourly timeline (stacked bars; table alternative below for screen readers)           │
│  ▇▇ ▇  ▇▇▇ ▇ ▇▇ ...                                                                  │
│  10 11 12 13 14 ...    ■ allowed ■ logged ■ blocked                                  │
│                                                                                      │
│ ┌ Top rules ────────────────────┐  ┌ By category ─────────────────┐                  │
│ │ 942100 SQLi tautology   ███ 31│  │ sqli  ████████ 40            │                  │
│ │ 941100 XSS script tag   ██  18│  │ xss   ████ 22                │                  │
│ └───────────────────────────────┘  └──────────────────────────────┘                  │
│ Recent events (last 10) → table as in Events                                         │
└──────────────────────────────────────────────────────────────────────────────────────┘
Mobile: metric cards wrap 2 per row; timeline scrolls inside its own box; top rules and
category stack vertically.
```

## 6. Analyze (submit a sample)

```
Desktop
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Analyze a request                                                                    │
│ Load example: [Benign search] [Benign form] [SQLi] [XSS] [Path traversal] [Encoded]  │
│ Label  [________________________]                                                    │
│ Method [GET ▾]  Path [/search?q=hello________________________________]               │
│ Headers                                                                              │
│   [content-type ] [application/json      ] [✕]                                       │
│   [user-agent   ] [lab-client            ] [✕]                                       │
│   [+ Add header]                                                                     │
│ Body                                                                                 │
│   [                                                                       ]          │
│ [ Analyze ]   [ Clear ]                                                              │
├──────────────────────────────────────────────────────────────────────────────────────┤
│ Result (aria-live)                                                                   │
│ ⛔ BLOCK · action blocked · score 8 / flag 3 / block 5   [Open evidence →]            │
│ Rule 942100 'SQLi boolean tautology' matched query.q after URL decoding (+5)        │
│ Recommendation: Block: input contains a SQL tautology…                              │
└──────────────────────────────────────────────────────────────────────────────────────┘
Mobile: header rows wrap name above value; buttons full width.
```

Client checks before submit (server re-validates): method in enum, path starts with `/` and ≤ 4096
chars, ≤ 50 headers with names `[A-Za-z0-9-]`, values ≤ 4096, body ≤ 1 MiB.

## 7. Import

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Import samples                                                                       │
│ File (.json, ≤ 256 KB, array of samples or {samples:[…]})  [Choose file]             │
│ ✔ samples.json — 12 samples valid, 1 invalid (#4: path must start with '/')          │
│ Preview: # │ Method │ Path            │ Headers │ Body bytes                          │
│          1 │ GET    │ /search?q=shoes │ 1       │ 0                                   │
│ [ Import 12 samples ]                                                                │
│ Result: imported 12 · rejected 0  → table of resulting event summaries (links)       │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

## 8. Events / history

```
Desktop
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Events                                                                               │
│ Verdict [any▾] Action [any▾] Source [any▾] Rule id [_____] Text [________]           │
│ From [date] To [date]   [Apply] [Reset]                                              │
│ [Compare selected (2)]                                       Showing 1–50 of 1 204   │
│ ┌──┬───────────────────┬────────┬──────┬───────────────┬────────┬─────────┬─────┬──┐ │
│ │☐ │ Time              │ Source │Method│ Path          │Verdict │ Action  │Score│Rules│
│ ├──┼───────────────────┼────────┼──────┼───────────────┼────────┼─────────┼─────┼──┤ │
│ │☑ │ 2026-10-19 10:00  │console │ GET  │ /search?q=…   │⛔block │ blocked │ 8   │942100│
│ │☑ │ 2026-10-19 09:58  │console │ GET  │ /search?q=shoe│✔allow  │ allowed │ 0   │ —    │
│ └──┴───────────────────┴────────┴──────┴───────────────┴────────┴─────────┴─────┴──┘ │
│ [‹ Prev]  page 1 / 25  [Next ›]                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
Mobile: each row becomes a card:
┌────────────────────────────────┐
│ ☐ ⛔ block · blocked · score 8  │
│ GET /search?q=…                │
│ console · 2026-10-19 10:00     │
│ rules 942100   [Details →]     │
└────────────────────────────────┘
Viewer: no checkboxes, no details link, no compare button.
```

## 9. Event detail — evidence view

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Event evt_1234 · console · "suspicious variant"                                      │
│ [⛔ BLOCK] [blocked · 403] mode block   would block: yes                              │
│ [↻ Replay with current rules] [⇩ Export this event] [Compare with…]                  │
│                                                                                      │
│ Score  ███████████████░░░░░░░░  8                                                    │
│        |flag 3   |block 5                                                            │
│ By category: sqli 5 · xss 3                                                          │
│                                                                                      │
│ Why (explanation)                                                                    │
│  1. Rule 942100 'SQLi boolean tautology' matched query.q after URL decoding (+5)     │
│  2. …                                                                                │
│ Recommendation: Block: input contains a SQL tautology…                               │
│                                                                                      │
│ Matches                                                                              │
│ Rule        │Ver│Severity │Cat │Location│Op     │Excerpt        │Decoded via│         │
│ 942100 SQLi…│ 1 │critical │sqli│query.q │matches│' OR 1=1       │[url]      │[Request │
│             │   │         │    │        │       │(shown as code)│           │exception]│
│ Suppressed by exceptions: rule 941100 at query.q — exception exc_9 (approved)       │
│ Anomalies: DOUBLE_ENCODING (+2) — Value was URL-encoded twice                        │
│ Rate limit: checked · 4 / 300 per 60 s · not limited                                 │
│ Request summary: GET /search · query names q · body 0 B · UA curl/8.4               │
│ Versions: engine 1.0.0 · ruleset sha256-3f9a… · config v7                           │
│ Timings: parse 0.1 ms · rules 0.4 ms · total 0.6 ms                                  │
│ Replay of evt_… (link) · submitted by alice · client c_3f9a…                        │
└──────────────────────────────────────────────────────────────────────────────────────┘
Mobile: matches table becomes stacked cards; buttons wrap full width.
```

## 10. Compare

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Compare events                    A [evt_1____] B [evt_2____] [Compare]              │
│ Summary of differences: verdict changed allow → block · score +8 ·                   │
│                         rules added 942100 · ruleset unchanged · config changed      │
│ ┌───────────────────┬──────────────────────────┬──────────────────────────┐          │
│ │ Field             │ A (evt_1)                │ B (evt_2)                │          │
│ ├───────────────────┼──────────────────────────┼──────────────────────────┤          │
│ │ Verdict      ≠    │ ✔ allow                  │ ⛔ block                  │ ← highlighted│
│ │ Action       ≠    │ allowed                  │ blocked                  │          │
│ │ Score        ≠    │ 0                        │ 8                        │          │
│ │ Thresholds        │ 3 / 5                    │ 3 / 5                    │          │
│ │ Mode              │ block                    │ block                    │          │
│ │ Matched rules ≠   │ —                        │ 942100                   │          │
│ │ Ruleset version   │ sha256-3f9a              │ sha256-3f9a              │          │
│ │ Config version ≠  │ 7                        │ 8                        │          │
│ │ Path              │ /search?q=shoes          │ /search?q=' OR 1=1       │          │
│ └───────────────────┴──────────────────────────┴──────────────────────────┘          │
└──────────────────────────────────────────────────────────────────────────────────────┘
Mobile: the table keeps three columns but wraps text; long values break.
Differences are marked with "≠ changed" text and a highlighted background (not colour alone).
```

## 11. Rules

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Rules       ruleset sha256-3f9a…            [+ New rule] (admin)                      │
│ ┌────────┬──────────────────────┬─────────┬──────┬───┬─────────┬──────────────────┐  │
│ │ Id     │ Name                 │Severity │ Cat  │Ver│ Enabled │ Actions          │  │
│ │ 942100 │ SQLi boolean tautol. │critical │ sqli │ 1 │ [✔ on]  │[Edit][History][🗑]│  │
│ └────────┴──────────────────────┴─────────┴──────┴───┴─────────┴──────────────────┘  │
│ Editor (rule 942100)                                                                 │
│ ┌──────────────────────────────────────────────────────────────────────────┐         │
│ │ rule 942100 "SQLi boolean tautology" {                                   │         │
│ │   when args matches /…/i                                                 │         │
│ │ }                                                                        │         │
│ └──────────────────────────────────────────────────────────────────────────┘         │
│ [Validate] [Save] (admin)  [Cancel]                                                   │
│ ⚠ Line 2, col 8: unknown target 'argz'                                                │
│ History: v2 update by admin 2026-10-19 · v1 create by system …                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
Disable / delete → confirmation dialog "Disable rule 942100? Requests that only matched this
rule will no longer be flagged." [Cancel] [Disable rule]
Operator: no toggles, no save/delete; Validate is available.
```

## 12. Config

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Configuration   active v7 · changed by admin 2026-10-19 10:00                         │
│ Mode  (•) block  ( ) monitor                                                          │
│ Thresholds  flag [3]  block [5]                                                       │
│ Limits  max body [1048576] inspect body [65536] max URL [4096] max headers [100]      │
│         max args [200] decode rounds [3]                                              │
│ Rate limit [✔ enabled] window ms [60000] max requests [300]                          │
│ [Review changes…] (admin)                                                             │
│ History: v7 2026-10-19 admin "lower block threshold for demo" [view]                 │
└──────────────────────────────────────────────────────────────────────────────────────┘
Review dialog:
┌ Confirm configuration change ─────────────────────┐
│ thresholds.block   5 → 4                          │
│ mode               block → monitor                │
│ Reason (required) [______________________]        │
│ [Cancel]                         [Apply change]   │
└───────────────────────────────────────────────────┘
```

## 13. Exceptions (tuning workflow)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Exceptions   [Pending (2)] [Approved] [Rejected] [Revoked]                            │
│ ⓘ An administrator other than the requester must approve an exception.               │
│ Request an exception                                                                 │
│  Rule id [942100] Path prefix [/search] Location [query.q] Method [any ▾]            │
│  Reason [_______________________]  Expires [date, optional]  Source event evt_…      │
│  [Preview impact]  → "Would have suppressed 3 of recent events" + list               │
│  [Submit request]                                                                     │
│ ┌──────┬──────┬─────────┬──────────┬────────┬──────────┬─────────┬──────────────────┐│
│ │ Id   │ Rule │ Scope   │ Reason   │Status  │Requested │Reviewed │ Actions (admin)  ││
│ │exc_1 │942100│/search  │FP on …   │pending │alice     │ —       │[Approve][Reject] ││
│ └──────┴──────┴─────────┴──────────┴────────┴──────────┴─────────┴──────────────────┘│
└──────────────────────────────────────────────────────────────────────────────────────┘
Own request: Approve disabled with text "You requested this — another admin must approve".
Approve/Revoke → confirmation dialog with optional note.
```

## 14. Audit console (admin)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Audit log                                 [Verify chain]  ✔ Chain intact (412 checked)│
│ Action [_______] Actor [_____] Outcome [any ▾] From [ ] To [ ] [Apply]                │
│ Seq │ Time      │ Actor (role)   │ Action         │ Target       │ Outcome │ Details  │
│ 412 │ 10:00:01  │ admin (admin)  │ config.update  │ config 8     │ success │ {reason…}│
│ [‹ Prev] [Next ›]                                                                     │
└──────────────────────────────────────────────────────────────────────────────────────┘
Broken chain → "⛔ Chain broken at seq 37" (text + icon).
```

## 15. Reports

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Export a report                                                                      │
│ Format (•) HTML ( ) CSV ( ) JSON                                                     │
│ From [date] To [date] Verdict [any ▾]  Event ids [evt_1, evt_2] (optional)           │
│ [Download report]                                                                    │
│ ⓘ Reports contain redacted excerpts only; secrets and session data are never        │
│   included. Each export is recorded in the audit log.                                │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

## 16. Users (admin)

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ Users                                                                                │
│ Create: Username [_____] Password [_____] Role [operator ▾] [Create user]            │
│ Username │ Role          │ Status          │ Created     │ Actions                   │
│ alice    │ [operator ▾]  │ active          │ 2026-10-19  │ [Apply role] [Disable]    │
│ bob      │ [viewer ▾]    │ locked until …  │ 2026-10-19  │ [Apply role] [Enable]     │
└──────────────────────────────────────────────────────────────────────────────────────┘
Role change / disable → confirmation dialog.
```

## 17. Account

```
┌──────────────────────────────────────┐
│ Account: alice (operator)            │
│ Session expires at 18:30             │
│ Change password                      │
│  Current [________]                  │
│  New     [________] (≥ 12 chars)     │
│  Confirm [________]                  │
│  [Change password]                   │
│ [Log out]                            │
└──────────────────────────────────────┘
```

## 18. Role panel (restricted state)

```
┌──────────────────────────────────────────────────────────┐
│ 🔒 Not available for your role                            │
│ This page needs the operator or admin role. You are       │
│ signed in as viewer. [Back to dashboard]                  │
└──────────────────────────────────────────────────────────┘
```

## 19. The proposal's illustrative example, screen by screen

1. Operator signs in (Login) → Dashboard.
2. Analyze → "Load example: Benign search" → Analyze → ✔ allow, no critical warning (evidence view: no matches).
3. Analyze → "Load example: SQLi" → ⛔ block with rule 942100 at `query.q`, excerpt and decoded-via chip.
4. Events → tick both → Compare → verdict/score/rules differences highlighted.
5. Reports → HTML → Download (sanitized; audit `report.export`).
6. Admin: Config → threshold change with reason (or Rules → edit one rule) → confirm.
7. Operator: Event detail → Replay with current rules → new event linked to the original; Compare
   shows `configChanged`/`rulesetChanged` and the new score/verdict — the change is traceable in Audit.
8. A viewer opening `#/events/<id>` sees the role panel; the server returns a generic 403 and logs `auth.denied`.
