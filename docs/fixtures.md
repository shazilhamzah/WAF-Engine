# Fixtures — safe sample data

Owner: Saad (member B). Directory: `fixtures/` (layer 5 of the architecture, "Test fixtures (safe
sample inputs)").

## Synthetic-data statement

Every fixture is **synthetic** and was written for this lab. Names (Alice, Bob, Test User, …),
e-mail addresses (only the reserved `example.com`, `example.net` and `example.org` domains),
phone numbers (the fictional `555-01xx` range), passwords, bearer tokens and session ids are
invented and never belonged to a real person or system. No fixture contains data collected from
real traffic. Requests target only the local lab shop (`target/`) on 127.0.0.1.

## Sets in this task

| File | Evaluation case | Samples | What it covers | Expected |
|---|---|---|---|---|
| `t3-benign.json` | **T3** benign false positives | 38 | Inputs that *look* a little like attacks: apostrophes (`O'Brien`, `rock 'n' roll`), `&` and `|`, SQL words in prose (`select a size`, `union station`, `drop shipping`, `SELECT * FROM menu tutorial`), `1+1=2`, `<3`, `<b>` markup, markdown with links and inline code, code snippets with `;`, `javascript: the good parts`, `regular expression (`, `sleep (8 hours)`, Windows paths with backslashes, correctly encoded `%`, UTF-8 and CJK text, e-mail with `+tag`, encoded redirect parameter, password with symbols | all `allow` |
| `corpus-benign.json` | false-positive rate (T3 / evaluation report) | 68 | Realistic everyday traffic for the lab shop: home, product and static pages, searches, pagination and filters, logins with fake credentials (form and JSON), logout, registration, password reset, comments, contact / newsletter / address forms, JSON API calls (POST/PUT/PATCH/DELETE, nested objects, arrays, numbers, unicode), plain-text body, file names in query strings, a multipart upload, HEAD/OPTIONS, cookies, a fake bearer token, caching and proxy headers, mobile/desktop user agents, long harmless comment | all `allow` |
| `import-sample.json` | console Import feature | 5 | `{ "samples": [ { method, path, headers, body } ] }` exactly as `POST /api/import` expects | all `allow` |
| `large-body.js` | **T4** large bodies | generator | `makeLargeBody(bytes, { payload, position })` returns exactly `bytes` bytes of benign filler with an optional payload at `'start'`, `'middle'` or `'end'`; `makeLargeRequest(bytes, opts)` wraps it in a raw engine request | see below |

Large-body behaviour with the default limits (unit test `fixtures.test.js`):

| Body size | Payload position | Result |
|---|---|---|
| ≤ 64 KiB (`inspectBodyBytes`) | anywhere | fully inspected, payload detected |
| 64 KiB – 1 MiB | start / middle within the first 64 KiB | detected, plus anomaly `BODY_PARTIALLY_INSPECTED` |
| 64 KiB – 1 MiB | end | **not** inspected (documented limitation), anomaly `BODY_PARTIALLY_INSPECTED` (+1) |
| > 1 MiB (`maxBodyBytes`) | any | rejected before rules: 413 `BODY_TOO_LARGE` |

## Format

```json
{ "case": "T3", "title": "…", "description": "…",
  "samples": [ { "id": "T3-01", "description": "…",
     "request": { "method": "GET", "path": "/search?q=O%27Brien", "headers": { "user-agent": "Mozilla/5.0 (fixture)" }, "body": null },
     "expected": { "verdict": "allow", "categories": [] } } ] }
```

* `request` follows the console **Sample** schema (contract §5.2): `path` starts with `/` and contains
  the raw (already percent-encoded) query string; header names are lower-case; `body` is a string or
  `null`.
* `expected.verdict` is the verdict with the default rules and configuration; `expected.categories`
  lists rule categories that must appear in the matches (empty for benign sets).
* Sample ids are unique per file (`T3-nn`, `CB-nn`).

## Results

With the default rule set (41 rules) and `DEFAULT_CONFIG`, in both block and monitor mode:

| Set | Samples | Allowed | Score > 0 |
|---|---|---|---|
| `t3-benign.json` | 38 | 38 | 0 |
| `corpus-benign.json` | 68 | 68 | 0 |
| `import-sample.json` | 5 | 5 | 0 |

False positives: **0 / 111**. Reproduce with `node --test "test/unit/engine/fixtures.test.js"`.

## Adverse fixtures (completed 2026-10-20)

| File | Samples | Coverage | Measured blocks |
|---|---|---|---|
| `t1-attacks.json` | 28 | 10 SQLi, 10 XSS, 8 traversal strings | 28 |
| `t2-encoding.json` | 20 | URL/double/triple encoding, %u escapes, named/decimal/hex/nested entities, mixed case, NFKC, null/zero-width characters, whitespace, SQL comments, traversal/backslashes and malformed UTF-8 | 20 |
| `t5-bypass.json` | 18 | Comment splitting, versioned comments, whitespace, JSON nesting/escapes, duplicate parameters, forms/multipart, encoded traversal, alternative XSS and six bypass classes | 12 |
| `corpus-attack.json` | 80 | 27 SQLi, 25 XSS, 16 traversal, 8 command signatures, 4 scanner signatures | 76 |

Rebuild deterministically with `npm run fixtures:build`. Source:
`scripts/build-attack-fixtures.js`; regression checks:
`test/unit/engine/attack-fixtures.test.js`. The generator never executes its strings or sends traffic.

Every adverse sample keeps `expected.verdict: "block"`. Six T5 misses carry `knownLimitation`:
cross-parameter SQL reconstruction, split JSON reconstruction, application-level base64, hexadecimal
boolean comparison, string-concatenated comparison, and XSS reconstructed across duplicate parameters.
The first four are also retained in the corpus. They are counted as failed protection expectations,
not successful detections. Conditional reconstruction/base64 cases are not demonstrated exploits of
the bundled target; they expose the limits of context-free matching.

The corpus shares signature families with the mandatory cases. Its 95% recall and 0/68 benign false
positives describe this controlled synthetic dataset, not real-world accuracy or an independent
holdout. The T2 overlong-UTF-8 example combines malformed bytes with a visible traversal signature:
it demonstrates anomaly reporting plus traversal detection, not general decoding of overlong UTF-8.
Full per-input evidence is in [evaluation/results.md](evaluation/results.md) and `results.json`.
