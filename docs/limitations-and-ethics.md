# WAF Studio — Limitations and Ethics Statement

> Owner: Saad. Applies to the whole project (source, fixtures, vulnerable target, evaluation data and
> reports). Proposal scope: "Production hosting, paid services, native mobile development, real-world
> attack deployment, and unapproved external targets are out of scope."

## 1. Ethics statement

### 1.1 Lab-only use

* WAF Studio is a **teaching tool**. It is designed, tested and documented to run on a single laptop with
  every listener bound to `127.0.0.1`. It is not a production security product and must not be put in
  front of real services or exposed to a network.
* The **Vulnerable Shop** target (`target/`) is deliberately insecure (reflected and stored XSS, SQL
  injection, path traversal). It shows a red **"LAB ONLY — deliberately vulnerable"** banner on every
  page, binds to loopback only, refuses to start on a non-loopback address (`target/server.js`), and is
  fenced so that "vulnerable" never means "dangerous to the host": SQL runs against a throw-away
  in-memory database, traversal cannot leave `target/files/`, and the app makes no outbound requests
  (see the safety design comment at the top of `target/app.js` and `test/integration/target.test.js`).

### 1.2 No external targets

* All attack strings in `fixtures/` and in the tests are aimed **only** at the local Vulnerable Shop
  through the local WAF proxy. The test helpers and the evaluation harness only ever connect to
  `127.0.0.1` on ports they started themselves.
* Team members agreed not to use the fixtures, the harness or the knowledge gained from the bypass cases
  (T5) against any system they do not own or have written permission to test. Testing third-party
  websites, university infrastructure or classmates' machines is out of scope and prohibited.

### 1.3 Synthetic data only

* Users, products, comments, "secret" files, flags and credentials in the target are **fake**
  (`alice`, `bob`, `fake-pass-…`, `FAKE-LAB-FLAG{…}`, `…@shop.example`). No real personal data is
  collected, imported or stored.
* Console accounts are created by `npm run setup` with random passwords printed once; test suites use
  test-only passwords that exist only in temporary databases.
* Data minimisation is built in: raw client IP addresses are never stored (HMAC pseudonyms), proxy events
  keep only sanitised summaries and ≤ 120-character redacted excerpts, and secrets are redacted before
  storage and export (`docs/threat-model.md` TH-11, TH-12).

### 1.4 Responsible disclosure

* If the team discovers a vulnerability in a **third-party** component while building this project
  (Node.js, Express, http-proxy, marked, SQLite, browsers), it will be reported privately to the
  maintainer through their published security policy, not published with exploit details first.
* Weaknesses found in **WAF Studio itself** are recorded openly in this document, in
  `docs/threat-model.md` §7 and in `docs/test-results.md`, because the project's purpose is learning.
* Bypass techniques demonstrated in T5 are well-known, publicly documented classes (comment splitting,
  encoding, case variation, parameter pollution). The report explains *why* they work against
  signature-based filters; it does not provide novel exploits.

### 1.5 Academic integrity

Every claim in the final report links to a test, a log excerpt or a measured result
(`docs/evaluation/results.md`, `docs/evaluation/check-summary.json`). Results that fail are reported as
failures, not removed. Generated measurements state their environment and timestamp.

## 2. Technical limitations

### 2.1 Detection (regex / signature-based WAFs)

| Limitation | Consequence | Mitigation in WAF Studio / note |
|---|---|---|
| Signature rules recognise **known patterns**, not intent | Novel or heavily obfuscated attacks can pass (false negatives) | Anomaly scoring combines several weak signals; normalisation before matching; monitor mode for safe tuning; misses are listed in the evaluation (T5, corpus FN table) |
| Known bypass classes: SQL comment splitting (`UN/**/ION`), alternative whitespace (`%09`, `%0b`, `/**/`), case and Unicode variants, string concatenation (`CONCAT('ad','min')`, `'ad'+'min'`; the `' OR ('a'\|\|'b')=(...)` shape is caught by 942110 since 2026-11-25), numeric tricks (`1e0`, `2-1=1`; hex literals such as `0x31=0x31` are caught by 942100 since 2026-11-25), HTTP parameter pollution, JSON/multipart smuggling, uncommon content types, payloads split across parameters or requests | Some T5 samples are expected to slip through | Each miss is labelled honestly in `fixtures/t5-bypass.json` and reported; adding a rule is a policy change that is versioned and audited |
| **False positives**: legitimate text that looks like code (names like O'Brien, SQL tutorials, `<3`, mathematical expressions) | Benign requests flagged or blocked | T3 + benign corpus measure the FP rate; scoped exceptions (FR-7) let operators fix them with admin approval; thresholds tunable |
| Context-free matching | The WAF does not know the target's real data types, so it cannot tell a dangerous parameter from a harmless one | Exceptions can be scoped by path prefix, location and method |
| Only HTTP/1.1 requests the proxy sees are inspected | Responses are not inspected (no data-leak prevention, no virtual patching of output) | Out of scope |
| No JavaScript execution / DOM analysis | DOM-based XSS that never reaches the server is invisible to the WAF | Out of scope; the target's own sinks are the lesson |

### 2.2 Body inspection and performance

* Only the first `inspectBodyBytes` (default **64 KB**) of a body are inspected; the remainder is
  forwarded uninspected and the decision carries a `BODY_PARTIALLY_INSPECTED` anomaly (evaluation T4
  shows a payload placed after the window). Bodies above `maxBodyBytes` (default **1 MiB**) are rejected
  with 413 before any rule runs.
* The proxy **buffers** each request body (up to the limit) before inspecting it; streaming inspection is
  not implemented, which raises memory use per request and adds latency proportional to body size.
* Everything runs in **one Node.js process** (single event loop). Regex evaluation is synchronous, so one
  expensive request delays others; the DSL's ReDoS guard reduces but cannot rule out slow patterns.
  No clustering, connection limits or slow-loris protection beyond Node's defaults.
* T6 measures overhead on **localhost only** (no network latency, warm caches, one client); numbers will
  differ on other machines and under concurrency. The pass threshold (p95 overhead < 25 ms) is a
  usability target for a teaching tool, not a production SLO.

### 2.3 Rate limiting

* The proxy rate limiter is an **in-memory sliding window per pseudonymous client id** on a single node:
  counters reset when the process restarts and are not shared between instances.
* Clients are identified by source IP only. On localhost every client is `127.0.0.1`, so all local tools
  share one bucket; in a real deployment many source addresses (or a shared NAT) would defeat or distort
  a per-IP limit. `X-Forwarded-For` is deliberately **not** trusted.
* Login throttling (5 failures / 15 min per username, 20 attempts / min per client) can be used to lock a
  known username out temporarily (a deliberate trade-off; lockout is audited and expires).

### 2.4 Transport and deployment

* **No TLS** locally: traffic on loopback is plaintext and the session cookie cannot carry the `Secure`
  flag. Any deployment beyond localhost would need TLS termination, `Secure` cookies, HSTS and a
  reviewed host/origin policy — out of scope.
* No high availability: if the proxy stops, protected traffic stops (fail-closed). If the target stops,
  the proxy returns a safe 502.
* SQLite is a single local file. It survives restarts (evaluation TF-11) but is not replicated; backups
  are manual (copy `data/` while stopped).

### 2.5 Audit and secrets

* The audit log is append-only (SQLite triggers) and hash-chained, which **detects** tampering, but a
  person with write access to `data/` can delete the triggers and rewrite the entire chain consistently.
  The chain is not anchored externally (no signed checkpoints or remote log).
* Secret redaction is pattern-based (header and field names such as `authorization`, `cookie`,
  `password`, `token`, `secret`, `api_key`). Secrets under unusual names, or embedded in free text, can
  be stored in evidence excerpts (query-string secrets in console samples were caught by the canary test
  and fixed; threat model §7).
* File-permission hardening of `data/secret.key` (`0600`) is best-effort on Windows, where NTFS ACLs are
  inherited from the user profile.

### 2.6 Scope limits (by design)

No production hosting, no paid services, no native mobile app, no real-world attack deployment, no
external or unapproved targets, no Docker requirement, no cloud components, no machine-learning
detection. One organisation, one node, three roles.

## 3. Intended use summary

Final measured limitations (2026-10-20): T5-13..T5-18 were allowed despite expected block; the first
four also appear as corpus CA-077..CA-080 (4/80 false negatives). These cover cross-value/JSON
reconstruction, application-level base64, hexadecimal comparisons, concatenated strings and split
markup. Reconstruction/base64 cases depend on application behaviour and are not successful
exploits demonstrated against the bundled shop. The small synthetic corpus shares signature
families with baseline cases, so 95% recall and 0/68 false positives do not estimate Internet-wide
protection. See [final test results](test-results.md) for evidence and latency definitions.

Update (2026-11-25): two of the six misses are now blocked. **T5-16** (`1 OR 0x31=0x31`) matches rule
942100, which now accepts hexadecimal as well as decimal literals; **T5-17**
(`' OR ('a'||'b')=('a'||'b')`) matches rule 942110, which now also recognises a quote break-out
followed by a parenthesised `||` concatenation in a comparison. Both changes only add alternatives to
the existing patterns (nothing previously matched stops matching), pass the ReDoS guard, and keep T3
and the benign corpus fully allowed. Expected verdicts were not changed. Engine-level result: 4/18 T5
samples allowed and 3/80 corpus false negatives (CA-080 is now detected). The 2026-10-19 snapshot in
[`evaluation/results.md`](evaluation/results.md) and [test-results](test-results.md) predates this
change and has not been regenerated. These remain signatures, not an SQL interpreter: equivalent
forms such as `1 OR 1e0=1e0`, `2-1=1`, `CONCAT('a','b')=CONCAT('a','b')` or `'a'+'b'='a'+'b'` still pass.

The four remaining misses are **out of scope** for a WAF that inspects each value on its own:

* **T5-13 / T5-14 — keywords split across parameters or JSON fields.** Every value (`UN`, `ION`, …)
  is harmless by itself; SQL only exists if the application concatenates the fields. Catching it
  needs knowledge of how the application combines its inputs (data-flow analysis). A rule that
  joined or matched keyword fragments across fields would fire on ordinary short values.
* **T5-15 — base64 inside an application-specific parameter.** Decoding every base64-looking value
  would also decode ordinary tokens, IDs and image data, cost time on every request and still miss
  other encodings (hex, custom schemes). The application that decodes the value must validate the
  decoded result.
* **T5-18 — markup split across duplicate parameters.** Each `q` value is inspected separately;
  whether duplicates are joined (and with which separator) is framework behaviour. Joining before
  matching would change the verdict for benign duplicate parameters. A duplicate that carries a
  complete attack is still blocked (T5-07).

| Do | Don't |
|---|---|
| Run on your own laptop, on 127.0.0.1 | Expose ports 3000, 3001 or 8080 to a network |
| Attack the Vulnerable Shop **through** the WAF proxy (:8080) to learn how rules respond | Point the proxy at a real website or someone else's server |
| Use synthetic data and the provided fixtures | Import real logs containing personal data or credentials |
| Report and document weaknesses you find | Use bypass techniques against systems you do not own |
