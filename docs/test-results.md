# WAF Studio - Final Test Results

**Final integration: 2026-10-20 (Asia/Karachi); re-measured 2026-11-25** after the hex-literal and `||` concatenation tautology fix (T5-16, T5-17), the console/idempotency update and the dependency audit fix. This replaces the phase-1 559/560 snapshot.
Plan: [test-plan.md](test-plan.md). Full evidence: [evaluation](evaluation/results.md),
[JSON](evaluation/results.json), [acceptance gate](evaluation/check-summary.json),
[standalone benchmark](evaluation/latency.json).

## 1. Environment and method

Node v24.19.0 on Windows_NT 10.0.26300 (win32/x64), Intel Core Ultra 7 255H, 16 logical CPUs,
31 GiB RAM (rounded Node measurement). Dependencies: Express 4.22.3, http-proxy 1.18.1, marked
18.1.1 (documentation only). All network evaluation is against temporary localhost listeners;
temporary databases isolate it from normal runtime data. Source: `environment` in results JSON.

Acceptance evidence timestamp: **2026-11-25T18:19:27.709Z** (23:19 on 25 November in Karachi).
Evaluation: **2026-11-25T18:00:40.214Z**. Benchmark: **2026-11-25T18:00:54.142Z**.
These three runs are separate. Tests needing local sockets were run with localhost access;
a restricted-sandbox run that denied connections is not the acceptance evidence.

## 2. Strict automated acceptance

| Metric | Final result |
|---|---|
| Automated tests | **806** |
| Passed / failed | **806 / 0** |
| Skipped / cancelled / todo | **0 / 0 / 0** |
| Suites | 39 |
| Pass rate / required threshold | **100% / 80%** |
| Strict mode | `WAF_STRICT=1` |
| Test execution time | 23.136 seconds |
| Production dependency vulnerabilities | **0** (0 critical/high/moderate/low) |
| Gate result | **PASS** |

Evidence: [check-summary.json](evaluation/check-summary.json). The raw TAP output is regenerable
under `.tmp/check.tap`; it is temporary output, not the stable submission record. The 51 adverse-fixture tests cover fixture integrity, intended T1/T2 detection, explicit bypass triage and the controlled
95% corpus detection target. Source: `test/unit/engine/attack-fixtures.test.js`.

The gate script's general policy permits a pass at 80%; the actual run has **no failures**. All
authorization, application injection/output, secret redaction, import and target-sandbox tests pass.
No unresolved critical application-security defect was identified by those checks. This statement
is limited to the tested scope and does not certify the absence of unknown vulnerabilities.

## 3. Mandatory evaluation

Baseline: block mode, thresholds flag 3 / block 5, 41 rules, engine 1.0.0,
ruleset `96ab725577dc312f`. Proxy rate limits were raised during measurement to avoid accidental
throttling; TF-08 explicitly reconfigures and exercises them. See `stack` in results JSON.

| Case | Passed / total | Observed result |
|---|---|---|
| T1 SQLi/XSS/traversal | **28/28** | 10 SQLi, 10 XSS and 8 traversal strings blocked |
| T2 encoding variants | **20/20** | URL/repeated URL, %u, entities, case, NFKC, null/invisible characters, whitespace, comments and encoded paths blocked |
| T3 benign false positives | **38/38** | All allowed, no false positives in this set |
| T4 large bodies | **6/6** | 10/60 KiB bodies forwarded intact; adverse prefix blocked; suffix beyond 64 KiB uninspected and explicitly marked partial; 2 MiB rejected; 1 MiB boundary not rejected for size |
| T5 bypass attempts | **14/18** | Hex-literal (T5-16) and `\|\|` concatenation (T5-17) tautologies now blocked; four expected-block inputs still allowed and retained as failures |
| T6 latency | **2/2** | GET added p95 1.674 ms; POST 2.154 ms; target <25 ms |
| T-final | **11/11** | Denials, throttles, safe errors and restart persistence verified |
| Total | **119/123 (96.7%)** | Four failures, all T5; no mandatory case unrun (was 117/123 before the 2026-11-25 rule fix) |

Per-input expected/actual, rule IDs, score, decoding, anomalies, event ID and pass/fail are retained
in [the full evaluation](evaluation/results.md) and [results.json](evaluation/results.json).
The T2 overlong-byte sample also contains a visible traversal indicator; it is not evidence that
arbitrary overlong UTF-8 payloads can be decoded.

### 3.1 T-final checks

| ID | Behaviour | Actual |
|---|---|---|
| TF-01 | Oversized URL | 400 blocked |
| TF-02 | Malformed percent encoding | 200 allowed; anomaly evidence, safe handling rather than mandatory denial |
| TF-03 | Malformed API JSON | 400 `MALFORMED_JSON` |
| TF-04 | Oversized API JSON | 413 `PAYLOAD_TOO_LARGE` |
| TF-05 | Anonymous evidence retrieval | 401 `AUTH_REQUIRED` |
| TF-06 | Viewer requests evidence | Generic 403 `FORBIDDEN`; denial audited |
| TF-07 | Viewer changes config | 403 |
| TF-08 | Repeated proxy submissions | Ten 200 responses, then five 429 responses |
| TF-09 | Repeated failed logins | Five 401 responses, then 429 lockout |
| TF-10 | Target unavailable | Safe 502; Studio health remains 200 |
| TF-11 | Restart on same DB | 41 rules, config v4 and 936 events persist; audit verifies; SQLi 403 and benign 200 |

TF-11 event IDs and counts belong to this disposable run. Normal runtime data is not seeded with
the evaluation records; saved JSON/Markdown preserves their evidence after cleanup.

## 4. Corpus coverage and detection errors

| Metric | Value |
|---|---|
| Controlled corpus | 80 adverse + 68 benign = 148 requests |
| True positives / true negatives | 77 / 68 |
| False positives / false negatives | **0 / 3** |
| Precision / recall / F1 | **1 / 0.9625 / 0.9809** |
| Observed false-positive rate | **0/68 = 0%** |
| Accuracy | 0.9797 |
| Attacks actually blocked | 77/80 |
| Engine decision mean / p50 / p95 / p99 | 0.147 / 0.126 / **0.277** / 0.452 ms |

| Intended category | Samples | Detected | Coverage |
|---|---|---|---|
| SQLi | 27 | 25 | 92.6% |
| XSS | 25 | 24 | 96% |
| Traversal | 16 | 16 | 100% |
| Command signatures | 8 | 8 | 100% |
| Scanner signatures | 4 | 4 | 100% |

These fixtures are synthetic and share signature families with T1/T2/T5. They are not an independent
holdout and do not estimate real-world protection. Detection positive means flag/block; in this run
all 77 detected adverse corpus samples were actually blocked. Source: `metrics` in results JSON.

### 4.1 Retained bypass misses

| T5 ID | Corpus ID | Miss / reason |
|---|---|---|
| T5-13 | CA-077 | SQL tokens split across parameters; no application-specific joining |
| T5-14 | CA-078 | SQL tokens split across JSON fields; no cross-field reconstruction |
| T5-15 | CA-079 | Application-level base64 markup; no arbitrary base64 decoding |
| T5-18 | Not in corpus | Markup split between duplicate parameters; application joining not modeled |

All four remain **expected block, actual allow**. T5-16 (hexadecimal numeric comparison, corpus CA-080) and T5-17 (string-concatenated comparison) were misses until 2026-11-25, when rules 942100/942110 learned hex literals and `||` concatenation; both are now blocked, with unit tests (`test/unit/engine/tautology-variants.test.js`) and proxy tests (`test/integration/tautology-proxy.test.js`) including benign look-alikes. Conditional reconstruction/base64 examples require
specific application behaviour and are not demonstrated successful exploits of Vulnerable Shop.
They are coverage limitations under threat TH-17, not newly discovered injection vulnerabilities in
the Studio API. No input was removed or relabelled benign to improve the metrics.

## 5. Independent latency benchmark

300 interleaved direct/proxy pairs per scenario, 30 warmups, keep-alive, no concurrency. The proxy
measurement includes inspection, event storage and forwarding. Overhead is proxy p95 minus direct
p95, not the p95 of individual paired differences.

| Scenario | Direct p95 | WAF p95 | Added p95 | Verdict |
|---|---|---|---|---|
| GET search | 0.317 ms | 2.038 ms | **1.721 ms** | PASS |
| POST 2 KiB form | 0.238 ms | 2.124 ms | **1.886 ms** | PASS |

Threshold: added p95 <25 ms. No request errors. Source:
[latency.json](evaluation/latency.json). Different results from the earlier T6 run are expected
because scheduling and warm caches vary. These are local serial latency figures, not throughput or
production-load measurements.

## 6. Finding closure and limitations

| Finding | Final disposition | Evidence |
|---|---|---|
| F-1 Single-level traversal only flagged | **Fixed before Claude handover**: rule 930105 now contributes 5, sufficient to block | `test/unit/engine/rules.test.js`, `test/integration/proxy.test.js`; T1 and T2 |
| F-2 Secret-named query values stored in samples | **Fixed and reverified**: masking applied before storage/export | `test/security/secrets.test.js` |
| F-3 Analyze/import API envelope differs from initial 256 KiB contract | **Reconciled**: 2 MiB for analyze/import, 256 KiB elsewhere; UI import stays 256 KiB | [API](api.md), [architecture](02-architecture.md), import/size tests |
| T5 signature coverage gaps | **Two fixed 2026-11-25** (T5-16, T5-17); four remain known residual limitations | Above table; [limitations/ethics](limitations-and-ethics.md) |

The 64 KiB inspection window, redacted replay, local-only/no-TLS transport, unanchored audit chain
and in-memory rate-limit counters remain documented design boundaries. The original full-screen browser smoke is recorded in [Wahaj's log](progress/wahaj.md). The UI refinement was additionally reviewed live at 1440px and 390px, including keyboard disclosures, navigation, and time filters; see [UI review evidence](evaluation/ui-review.json). Automated UI/security tests are included in the 782-test acceptance result.

## 7. Reproduction and delivery scope

```bash
npm ci
npm run fixtures:build
npm run check
npm run evaluate
npm run bench
npm run docs:pdf
```

The evaluation script intentionally exits zero even when protection expectations fail; inspect its
per-case outcomes, `harnessError`, and corpus misses rather than treating exit status as a clean
security result. The full run above includes all seven mandatory case keys, with no harness error.

The separate 10-15 minute demo/walkthrough is **omitted at the user's request**. All other requested
deliverables are indexed in [traceability](traceability.md) and summarized in [the final report](final-report.md).
