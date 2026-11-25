# Fixtures — safe sample inputs (layer 5)

Owner: Saad. Full description: [`docs/fixtures.md`](../docs/fixtures.md).

All fixtures are **synthetic**. Names, e-mail addresses (only `example.com/.net/.org`), passwords,
tokens and session ids are invented for the lab and never belonged to a real person or system.

| File | Purpose | Expected result |
|---|---|---|
| `t1-attacks.json` | T1: 10 SQLi, 10 XSS and 8 traversal examples | all 28 `block` |
| `t2-encoding.json` | T2: 20 normalization / encoding variants | all 20 `block` |
| `t5-bypass.json` | T5: 18 evasion attempts, including application-dependent reconstruction | all expected `block`; six measured misses retained |
| `corpus-attack.json` | 80 controlled adverse requests across five rule categories | all expected `block`; four measured misses retained |
| `t3-benign.json` | Evaluation case T3: tricky-but-benign inputs (apostrophes, `&`, SQL/HTML words, markdown, code, non-ASCII) | every sample `allow` |
| `corpus-benign.json` | Realistic benign traffic for the lab shop (browsing, search, fake logins, forms, JSON APIs, uploads, cookies) — false-positive measurement | every sample `allow` |
| `import-sample.json` | Small `{ "samples": [...] }` file for the console's **Import** feature | every sample `allow` |
| `large-body.js` | `makeLargeBody(bytes, { payload, position })` / `makeLargeRequest(...)` generator for case T4 | depends on size vs limits |

Adverse fixtures are reproducible with `npm run fixtures:build`. This only writes synthetic JSON;
it does not send requests or execute payloads. The generation source is
`scripts/build-attack-fixtures.js`. Expectations are protection goals chosen before measurement.
`knownLimitation` explains a potential miss without changing its expected verdict to `allow`.

The corpus reuses signature families from T1/T2/T5 and is not an independent holdout or a random
sample of Internet traffic. The six T5 misses include application-dependent reconstruction and
base64 interpretation, not confirmed successful exploits of Vulnerable Shop. See
[`docs/evaluation/results.md`](../docs/evaluation/results.md) for measured results and evidence.

## Sample format

```json
{ "case": "T3", "title": "…", "description": "…",
  "samples": [ { "id": "T3-01", "description": "…",
     "request": { "method": "GET", "path": "/search?q=O%27Brien", "headers": { "user-agent": "Mozilla/5.0 (fixture)" }, "body": null },
     "expected": { "verdict": "allow", "categories": [] } } ] }
```

`request` is a console **Sample** (contract §5.2): `path` includes the raw query string, `body` is a
string or `null`. To run one through the engine directly:

```js
const engine = require('../src/engine');
const r = sample.request;
engine.inspect({ method: r.method, url: r.path, headers: r.headers, body: r.body,
                 bodyBytes: r.body ? Buffer.byteLength(r.body) : 0 }, ctx);
```

`expected.categories` lists the rule categories that must appear in the matches (empty for benign
sets). Results at the time of writing: 38/38 T3 and 68/68 corpus samples allowed with score 0.
