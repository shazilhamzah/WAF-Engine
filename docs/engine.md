# WAF Studio Security Engine

Owner: Nufil (member B). Code: `src/engine/` (layer 3 of the architecture). Default rules:
`src/rules/default.rules`. Contract: `docs/02-architecture.md` §1.2 and §3. DSL reference:
`docs/rule-dsl.md`.

The engine is a set of **synchronous, pure functions** with no database, network or file access
(only `src/rules/index.js` reads the default rule file). The console API and the reverse proxy share
the same compiled rules, config, exceptions and rate limiter, so a sample analysed in the console
gets exactly the decision the proxy would make.

## 1. Public interface (`src/engine/index.js`)

| Export | Purpose |
|---|---|
| `ENGINE_VERSION` | `'1.0.0'`, stored in every decision |
| `DEFAULT_CONFIG` | frozen EngineConfig (contract §3.2) |
| `validateConfig(cfg)` | `{ ok, config, errors: [{ field, message }] }`; partial configs are merged over the defaults; unknown fields, wrong types and out-of-range values are errors |
| `parseRequest(raw, limits)` | `{ ok, request, anomalies, error }`; on rejection also `statusCode` (400/413) and `partial` (method/path/size for the summary) |
| `validateRuleSource(src)` | `{ ok, rule: { id, name, severity, score, category, tags, description, targets, operators }, errors: [{ line, col, message }] }` |
| `parseRuleFile(text)` | `{ rules: [{ id, source }], errors: [{ ruleId, line, col, message }] }` |
| `compileRules(records)` | `{ rules, errors: [{ ruleId, line, col, message }], rulesetVersion }` |
| `createRateLimiter(opts)` | `{ check(key, now), configure(opts), reset(), size(), options }` |
| `inspect(raw, ctx)` | full pipeline → Decision; never throws |
| `redact(value)` | deep copy with secrets masked (`[REDACTED]`) |
| `excerpt(str, index, len)` | ≤ 120-character safe excerpt around `[index, index+len)` |

## 2. Pipeline stages ↔ requirements

`inspect(raw, ctx)` runs the proposal's working sequence (contract §1.2):

| Step | Stage | Module | Requirement | What it does |
|---|---|---|---|---|
| 1 | Request parser | `parser.js`, `normalize.js` | FR-1 | validates method, URL, headers, argument count and body size; parses query, cookies, urlencoded / JSON / multipart / text bodies; builds normalized variants; records anomalies. Malformed or oversized input stops here (no rule runs) |
| 2 | Rule DSL | `dsl.js`, `evaluate.js`, `exceptions.js` | FR-2, FR-7 | runs every compiled rule once over the normalized fields; collects evidence (location, operator, excerpt, `decodedVia`); applies approved exceptions — suppressed matches move to `suppressed[]` |
| 3 | Scoring | `scoring.js` | FR-3 | total = rule points + anomaly points; per-category breakdown; contributions; verdict vs thresholds |
| 4 | Block/monitor | `modes.js` | FR-4 | maps the would-block outcome to `blocked` (block mode) or `logged` (monitor mode) |
| 5 | Rate limits | `ratelimit.js` | FR-5 | sliding window per `ctx.clientKey`; breach → `RATE_LIMITED` / 429, mapped by the same mode policy |
| 6 | Audit console | (caller) | FR-6 | the returned Decision is what the service layer stores as an event; the engine does no I/O |
| 7 | Tuning & exceptions | `exceptions.js`, `explain.js` | FR-7, OBJ-2 | approved exceptions feed stage 2; explanation, recommendation and evidence make the decision reviewable and replayable |

Stage 5 runs after stage 3 in code (its outcome must also pass through the mode policy), but it is
logically the fifth stage and every request — including rejected ones — is counted.

## 3. Request parsing and normalization (FR-1)

### 3.1 Validation and limits

| Check | Limit (default) | Result |
|---|---|---|
| request is an object | — | `INVALID_REQUEST` → 400 `MALFORMED_REQUEST` |
| method is an RFC 9110 token, 1–24 chars | — | `INVALID_METHOD` → 400 |
| URL present, origin-form (`/…`, absolute-form is reduced to its path), no control characters or spaces | — | `INVALID_URL` → 400 |
| URL length | `maxUrlLength` 4096 | `URL_TOO_LONG` → 400 |
| header count | `maxHeaderCount` 100 | `TOO_MANY_HEADERS` → 400 |
| header name is a token; value has no CR/LF/NUL | — | `INVALID_HEADER` → 400 |
| header value length | 16 384 | `HEADER_TOO_LONG` → 400 |
| query + body arguments | `maxArgs` 200 | `TOO_MANY_ARGS` → 400 |
| body size (max of declared `bodyBytes` and actual) | `maxBodyBytes` 1 MiB | `BODY_TOO_LARGE` → 413 |
| body beyond the inspection window | `inspectBodyBytes` 64 KiB | anomaly `BODY_PARTIALLY_INSPECTED` (+1), first 64 KiB inspected |

Rejection anomalies carry 0 points; the decision's `blockReason` (`MALFORMED_REQUEST` or
`BODY_TOO_LARGE`) and the first anomaly explain the rejection.

### 3.2 Parsing

* **Query**: split on `&`; names are decoded for display/locations (`query.<name>`), values stay raw
  so the variants can show which decoding revealed a match.
* **Body**: `application/x-www-form-urlencoded` → fields `body.<name>`; `application/json` (or
  `+json`, or no content type and the body starts with `{`/`[`) → flattened leaves with dotted names
  (`body.user.roles.0`); `multipart/form-data` → fields plus `<name>.filename`; anything else → raw
  text only. Invalid JSON → anomaly `MALFORMED_JSON` (+2); nesting > 32 → `JSON_TOO_DEEP` (+2);
  missing multipart boundary → `MALFORMED_MULTIPART` (+1).
* **Cookies** → `cookie.<name>`. **Headers** are lower-cased; duplicates are joined with `, `.

### 3.3 Normalization variants

Every value gets a variant list; variant 0 is the raw value. Steps are applied cumulatively in the
decode chain, and each step that changes the value adds a variant whose `via` lists the steps so
far. Derived variants are computed from the fully decoded value.

| Step (`decodedVia` name) | What it does | Anomaly |
|---|---|---|
| `url` | percent-decoding (UTF-8), repeated up to `decodeRounds` (default 3); `+` → space in query/form values (first round only) | `DOUBLE_ENCODING` (+2) when more than one round changed the value; `INVALID_ENCODING` (+1) for `%` not followed by two hex digits in the raw path/query/form value |
| `unicode_escape` | `%uXXXX` (IIS-style) escapes | `UNICODE_ESCAPE` (+2) |
| `html` | HTML character references: named (common set), decimal `&#60;`, hex `&#x3c;`, two rounds (`&amp;lt;`) | — |
| `nfkc` | Unicode NFKC (folds fullwidth `＜ｓｃｒｉｐｔ＞` to `<script>`, ligatures, etc.) | — |
| `nullbyte` | removes NUL characters | `NULL_BYTE` (+3) |
| `invisible` | removes zero-width characters and soft hyphens | — |
| `sql_comment` (derived) | removes `/* … */` comments (two variants: replaced by a space and by nothing; MySQL `/*!…*/` keeps its content) | — |
| `whitespace` (derived) | collapses whitespace runs to one space | — |
| `lowercase` (derived) | lower-cases | — |
| `backslash` (derived) | `\` → `/` | — |
| `path` (derived, path only) | canonicalizes: `\`→`/`, `//`→`/`, removes `.`, resolves `..` | `PATH_ESCAPES_ROOT` (+2) when `..` climbs above `/` |

Which values report which anomalies: `INVALID_ENCODING` only for the path, query and urlencoded
form values (a literal `%` in JSON or text is normal); header values only report `NULL_BYTE` (a
Referer legitimately carries encoded URLs). Each anomaly code counts once per request.

## 4. Rule evaluation and evidence (FR-2)

See `docs/rule-dsl.md` §5 for operator semantics. For each rule that matches, the decision gets one
match entry:

```js
{ ruleId, ruleName, ruleVersion, severity, points, category, tags,
  location: 'query.q',          // first value location that matched
  locations: ['query.q', 'query.x'],   // every matched location (≤ 10), extra field
  operator: 'matches',
  excerpt: "' OR 1=1",          // ≤ 120 chars, redacted, control chars escaped
  decodedVia: ['url'],          // fewest normalization steps that revealed the match
  suppressedBy: null }          // exception id when suppressed
```

## 5. Scoring and thresholds (FR-3)

```
total    = Σ points(unsuppressed rule matches, each rule once) + Σ points(parser anomalies, each code once)
verdict  = block  if total ≥ thresholds.block   (default 5)
           flag   if total ≥ thresholds.flag    (default 3)
           allow  otherwise
```

`score.byCategory` groups rule points by rule category and anomaly points under `anomaly`;
`score.contributions` lists every rule (`source: 'rule'`, `id` = rule id as string) and anomaly
(`source: 'anomaly'`, `id` = code) with its points and a short reason. Thresholds are stored in
each decision (`flagThreshold`, `blockThreshold`).

Default rule calibration: score 5 = strong indicator (blocks alone), 3–4 = suspicious (flags alone,
blocks with one more signal), 1–2 = context. Every textbook SQLi, XSS, traversal and command
injection string reaches ≥ 5 in its category; every benign fixture scores 0.

## 6. Modes (FR-4)

The engine first decides whether the request **would be blocked** and why (`blockReason`):

| Priority | Condition | `blockReason` | status |
|---|---|---|---|
| 1 | parser rejection | `MALFORMED_REQUEST` / `BODY_TOO_LARGE` | 400 / 413 |
| 2 | score ≥ block threshold | `SCORE_THRESHOLD` | 403 |
| 3 | rate limit exceeded | `RATE_LIMITED` | 429 |

Then the mode decides what happens:

| Mode | would block | otherwise |
|---|---|---|
| `block` | `action: 'blocked'`, `wouldBlock: true`, `statusCode` = status above | `action: 'allowed'` |
| `monitor` | `action: 'logged'`, `wouldBlock: true`, `statusCode: null` (forwarded) | `action: 'allowed'` |

`verdict` is the engine's opinion (`block` for every would-block case, including rejections and rate
limiting); a `flag` verdict is always allowed and visible in the event list. The same attack is
therefore `blocked`/403 in block mode and `logged` with `wouldBlock: true` in monitor mode
(unit test `scoring-modes.test.js`).

## 7. Rate limiting (FR-5)

Algorithm: **sliding log per client key** (`ctx.clientKey`, the caller's HMAC pseudonym of the IP).
On `check(key, now)` the limiter drops timestamps `≤ now − windowMs`, appends `now`, and the request
is limited when the count (including this request) exceeds `maxRequests`. Limited requests are
recorded too, so a flooding client stays limited until it slows down.

* Result: `{ checked: true, limited, count, limit, windowMs, retryAfterSeconds }` (the last field is
  an addition for the `Retry-After` header).
* Memory bound: at most `maxRequests + 1` timestamps per key; at most `maxKeys` (default 10 000)
  keys. Stale keys are swept at most once per window and whenever the table is full; if it is still
  full, the least-recently-seen key is evicted.
* The clock is injectable (`now` argument; `ctx.now` in `inspect`).
* `ctx.rateLimiter === null` or `config.rateLimit.enabled === false` → `rateLimit.checked = false`.
  `inspect` re-configures the shared limiter when `config.rateLimit` changes.

## 8. Exceptions (FR-7)

Input: `ctx.exceptions`, the approved and unexpired exceptions (contract §3.4). A rule match is
suppressed when an exception has the same `ruleId` and every non-null scope field matches:

| Scope field | Compared with |
|---|---|
| `pathPrefix` | `request.normalizedPath` (decoded and dot-segment-resolved) `startsWith(pathPrefix)` |
| `location` | the match location, exactly (`query.q`) |
| `method` | the request method, case-insensitive |

* If a rule matched several value locations, **all** of them must be covered, otherwise the rule
  still counts (a payload moved to another parameter is not hidden by a narrow exception).
* Suppressed matches keep all their evidence, appear in `suppressed[]` with `suppressedBy` set,
  contribute 0 points and get an explanation line.
* Defence in depth: entries with a `status` other than `approved`, or with `expiresAt` ≤ `ctx.now`,
  are ignored even if the caller passes them.

## 9. Explanation format (OBJ-2)

`decision.explanation` is an ordered list of sentences, for example:

```
Rule 942100 'SQLi boolean tautology' matched query.q after URL decoding (+5)
Rule 941100 'XSS script tag' matched query.q but is suppressed by approved exception exc_… (+0)
Parser anomaly DOUBLE_ENCODING: A value was URL-encoded more than once … (2 rounds at query.q) (+2)
Total score 7 >= block threshold 5 -> score verdict block
Rate limit ok: 4/300 requests in the last 60 s
Mode block: request blocked with HTTP 403 (SCORE_THRESHOLD)
```

Rejected requests start with `Request rejected by the parser before rule evaluation: <CODE> — …`.
`decision.recommendation` is one sentence starting with `Block:`, `Reject:`, `Throttle:`,
`Review:` or `Allow:`; for blocks it suggests a scoped exception rather than disabling a rule.
Explanations never contain raw request values (only rule names, locations and codes).

## 10. Decision schema

Exactly contract §3.6, with these additions (extra fields, nothing removed):

* `matches[].locations` / `suppressed[].locations` — every matched location;
* `rateLimit.retryAfterSeconds` — present when the limiter was checked;
* `request.normalizedPath` — the canonical path used for exception matching.

`request` (summary) contains: `method`, `path` (≤ 200 chars, no query), `normalizedPath`,
`queryNames`/`bodyNames` (≤ 50 names, ≤ 64 chars each), `contentType` (media type only),
`bodyBytes`, `inspectedBytes`, `truncated`, `userAgent` (≤ 80 chars). It contains no other header
value, no cookie, no query or body value.

## 11. Data minimization and redaction

* `redact(value)` masks: headers `authorization`, `proxy-authorization`, `cookie`, `set-cookie`,
  `x-api-key`, `x-auth-token`, `x-csrf-token`, `x-xsrf-token`, `x-access-token`; any key matching
  `/pass(word|wd|phrase)?|pwd|secret|token|api[_-]?key|session|credit|card|cvv|ssn|csrf|credential|authori[sz]ation|cookie|private[_-]?key|jwt/i`;
  secret parameters inside strings (`password=…` in query strings and form bodies, `"token":"…"` in
  JSON text) and `Bearer/Basic/Digest/Token` credentials. Cycles, depth > 20, buffers and functions
  are handled without throwing.
* Excerpts: at most 120 characters around the match; control, bidi-override and zero-width
  characters escaped (`\n`, `\x1b`, `‮`). Matches at sensitive locations (`body.password`,
  `header.authorization`, `cookie.sid`, …) get the excerpt `[REDACTED]`; secret parameters inside a
  raw body are masked before the excerpt is cut.
* Unit test `redact.test.js` asserts `JSON.stringify(decision)` contains none of the planted secrets.

## 12. Robustness

`inspect` never throws: hostile values (non-objects, throwing getters, Proxies, random bytes, 300 KB
binary bodies, deeply nested JSON, invalid UTF-16) are covered by `inspect.test.js`. An internal
failure returns a fail-safe decision: `verdict: 'block'`, `blockReason: 'MALFORMED_REQUEST'`,
anomaly `INSPECTION_ERROR`, `blocked`/400 in block mode, `logged` in monitor mode — and no internal
error text. A rule whose evaluation throws is skipped.

## 13. Performance

Final measured evidence (2026-10-20 local date), Node 24.19 on Windows, default 41 rules:

| Measurement | p50 | p95 | Evidence |
|---|---|---|---|
| Engine decisions over the 148-request controlled corpus | 0.234 ms | 0.476 ms | `evaluation/results.json`, `metrics.decisionLatencyMs` |
| GET added proxy latency (independent benchmark) | 1.194 ms | 1.888 ms | `evaluation/latency.json` |
| POST 2 KiB form added proxy latency | 1.102 ms | 1.988 ms | `evaluation/latency.json` |

The proxy measurements include event storage and forwarding; they are not isolated engine timings.
Overhead subtracts the corresponding direct statistic from the proxy statistic. See
[final results](test-results.md) for sample counts, environment, definitions and limitations.

All default regexes use bounded repetition; adversarial 64 KiB inputs finish well within the
500 ms test bound (most within a few ms). End-to-end proxy latency (T6) is measured separately by
`scripts/bench-latency.js`.

## 14. Contract clarifications

Choices made where the contract left room (also recorded in `docs/progress/nufil.md`):

1. **`excerpt(str, index, len)`**: `len` is the length of the matched region; the result is always
   ≤ 120 characters.
2. **Monitor mode never blocks**, including parser rejections and rate limiting (`logged`,
   `statusCode: null`). The proxy must still not forward a body it did not fully buffer (see
   integration note in the progress log).
3. **`blockReason` priority**: parser rejection > `SCORE_THRESHOLD` > `RATE_LIMITED`; every request is
   counted by the rate limiter, even rejected ones.
4. **`flag` verdict → `action: 'allowed'`** in both modes.
5. **Anomaly category**: anomaly points are grouped as `byCategory.anomaly`.
6. **Exception `pathPrefix`** is compared with the canonical path (`request.normalizedPath`), and a
   multi-location match is suppressed only when all its locations are covered.
7. **`rulesetVersion`** = first 16 hex characters of SHA-256 over the enabled, successfully compiled
   rules' `id`, `version` and `source`, sorted by id. `inspect` copies `ctx.rulesetVersion` into the
   decision (it does not recompute it).
8. **`compileRules`** skips `enabled: false` records and reports a record whose id differs from the
   id in its source.
9. **String operators are case-insensitive**; `gt/lt/ge/le` compare the raw value length for text
   targets.
10. **`args`** falls back to the raw body when the body has no parsed fields.
11. Rule categories used by the default set: `sqli`, `xss`, `traversal`, `cmdi`, `protocol`,
    `scanner`.
