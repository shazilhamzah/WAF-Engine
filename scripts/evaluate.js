#!/usr/bin/env node
'use strict';
/**
 * WAF Studio evaluation harness (owner: Nufil) — mandatory cases T1–T6 + T-final and corpus metrics.
 *
 *   npm run evaluate                 full run (T6 with N = 300 request pairs)
 *   node scripts/evaluate.js --n 500 more latency samples
 *   node scripts/evaluate.js --quick N = 100, fewer warm-ups (for a fast smoke run)
 *   node scripts/evaluate.js --skip-latency
 *
 * Starts the FULL stack (studio + proxy + vulnerable target) on ephemeral 127.0.0.1 ports with a temp
 * database, seeds it, then sends every fixture sample THROUGH THE REAL PROXY and reads the stored event
 * as evidence. Writes docs/evaluation/results.json and docs/evaluation/results.md.
 * Exit code is 0 even when cases fail (this is a measurement); 1 only if the harness itself cannot run.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startStack, stackAvailable, waitFor, findLeak, rmrf } = require('../test/helpers/stack');
const { rawRequest } = require('../test/helpers/http');
const { loadFixture, runSample, fetchEvent, evidenceOf, caseSummary, describeInput, FIXTURES } = require('../test/evaluation/runner');
const { measureOverhead } = require('../test/evaluation/latency');
const { summarize, classification, sanitize } = require('../test/evaluation/stats');
const { render } = require('../test/evaluation/report');

const ROOT = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const a = { n: 300, warmup: 30, out: path.join(ROOT, 'docs', 'evaluation'), latency: true };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--n') a.n = Math.max(10, Number(argv[++i]) || 300);
    else if (k === '--quick') { a.n = 100; a.warmup = 10; }
    else if (k === '--out') a.out = path.resolve(argv[++i]);
    else if (k === '--skip-latency') a.latency = false;
    else if (k === '--help' || k === '-h') { console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(2, 17).join('\n')); process.exit(0); }
  }
  return a;
}

const log = (...m) => console.log('[evaluate]', ...m);

async function setConfig(admin, mutate, reason) {
  const cur = await admin.get('/api/config');
  if (cur.status !== 200) throw new Error(`GET /api/config → ${cur.status}`);
  const config = structuredClone(cur.body.config);
  mutate(config);
  const r = await admin.put('/api/config', { config, reason, confirm: true });
  if (r.status !== 200) throw new Error(`PUT /api/config → ${r.status} ${r.text.slice(0, 200)}`);
  return r.body;
}

// ───────────────────────────── fixture-driven cases (T1, T2, T3, T5) ─────────────────────────────
async function runFixtureCase(stack, admin, key, file, fallbackTitle) {
  let fx;
  try { fx = loadFixture(file); } catch (e) { return { title: fallbackTitle, status: 'not-run', reason: `fixture ${file} invalid: ${e.message}` }; }
  if (!fx) return { title: fallbackTitle, status: 'not-run', reason: `fixtures/${file} not found` };
  const samples = [];
  for (const s of fx.samples) samples.push(await runSample(stack, admin, s));
  log(`${key}: ${samples.filter((s) => s.pass).length}/${samples.length} passed`);
  return { title: fx.title || fallbackTitle, file: `fixtures/${file}`, status: 'run', samples, summary: caseSummary(samples) };
}

// ───────────────────────────── T4 large bodies ─────────────────────────────
function fallbackMakeLargeBody(bytes, { payload = '', position = 'end' } = {}) {
  const filler = 'lorem+ipsum+dolor+sit+amet+';
  const pay = payload ? `&q=${encodeURIComponent(payload)}` : '';
  const head = 'comment=';
  const fillLen = Math.max(0, bytes - head.length - pay.length);
  const fill = filler.repeat(Math.ceil(fillLen / filler.length)).slice(0, fillLen);
  if (!payload) return head + fill;
  return position === 'start' ? `q=${encodeURIComponent(payload)}&${head}${fill}`.slice(0, Math.max(bytes, pay.length + head.length)) : head + fill + pay;
}

function loadLargeBodyGenerator() {
  const f = path.join(FIXTURES, 'large-body.js');
  if (fs.existsSync(f)) {
    try { const m = require(f); if (typeof m.makeLargeBody === 'function') return { fn: m.makeLargeBody, source: 'fixtures/large-body.js' }; } catch { /* fall back */ }
  }
  return { fn: fallbackMakeLargeBody, source: 'scripts/evaluate.js fallback generator (fixtures/large-body.js missing)' };
}

function normalizeBody(out) {
  if (Buffer.isBuffer(out) || typeof out === 'string') {
    const s = Buffer.isBuffer(out) ? out.subarray(0, 1).toString() : out.slice(0, 1);
    return { body: out, contentType: s === '{' || s === '[' ? 'application/json' : 'application/x-www-form-urlencoded' };
  }
  if (out && typeof out === 'object' && out.body !== undefined) return { body: out.body, contentType: out.contentType || out.headers?.['content-type'] || 'application/x-www-form-urlencoded' };
  throw new Error('makeLargeBody returned an unsupported value');
}

async function runT4(stack, admin, config) {
  const gen = loadLargeBodyGenerator();
  const L = config.limits;
  const attack = "' UNION SELECT username,password FROM users --";
  const defs = [
    { id: 'T4-01', description: '10 KB benign form body', bytes: 10 * 1024, opts: {}, expect: 'allow' },
    { id: 'T4-02', description: '60 KB benign body (inside the inspection window)', bytes: 60 * 1024, opts: {}, expect: 'allow' },
    { id: 'T4-03', description: `200 KB body, SQLi payload BEYOND the ${L.inspectBodyBytes}-byte inspection window → partially-inspected anomaly evidence`, bytes: 200 * 1024, opts: { payload: attack, position: 'end' }, expect: 'partial' },
    { id: 'T4-04', description: '200 KB body, SQLi payload at the START (inside the window) → blocked', bytes: 200 * 1024, opts: { payload: attack, position: 'start' }, expect: 'block' },
    { id: 'T4-05', description: `2 MB body (> maxBodyBytes ${L.maxBodyBytes}) → 413 before rules`, bytes: 2 * 1024 * 1024, opts: {}, expect: '413' },
    { id: 'T4-06', description: `body exactly at maxBodyBytes (${L.maxBodyBytes} B) → not rejected for size`, bytes: L.maxBodyBytes, opts: {}, expect: 'not413' }
  ];
  const samples = [];
  for (const d of defs) {
    const norm = normalizeBody(gen.fn(d.bytes, d.opts));
    const body = norm.body;
    // fixtures/large-body.js produces plain-text filler (same as its makeLargeRequest helper).
    const contentType = gen.source.startsWith('fixtures/') ? 'text/plain' : norm.contentType;
    const raw = { method: 'POST', path: '/api/echo', headers: { 'content-type': contentType, accept: 'application/json', 'user-agent': 'Mozilla/5.0 (WAF Studio evaluation)' }, body };
    const res = await stack.proxy(raw);
    const eventId = res.headers['x-waf-event-id'] || null;
    const event = await fetchEvent(admin, eventId);
    const evidence = evidenceOf(event);
    const actual = { status: res.status, action: res.headers['x-waf-action'] || (res.status === 0 ? 'error' : 'unknown'), verdict: event ? event.verdict : null, roundTripMs: Math.round(res.ms), error: res.error || null };
    const notes = [];
    const truncated = event && event.decision && event.decision.request ? event.decision.request.truncated : null;
    let pass;
    let echoed = null;
    try { echoed = JSON.parse(res.text).bytes; } catch { /* not echo JSON */ }
    const size = Buffer.byteLength(body);
    switch (d.expect) {
      case 'allow':
        pass = actual.action === 'allowed' && echoed === size;
        notes.push(`target echoed ${echoed} of ${size} bytes`);
        break;
      case 'partial':
        pass = evidence.anomalies.includes('BODY_PARTIALLY_INSPECTED') && truncated === true;
        notes.push(`truncated=${truncated}; ${actual.action === 'blocked' ? 'blocked' : 'payload not inspected (documented limitation)'}`);
        break;
      case 'block':
        pass = actual.action === 'blocked' && actual.status === 403;
        break;
      case '413':
        pass = (actual.status === 413 && actual.action === 'blocked' && evidence.blockReason === 'BODY_TOO_LARGE') || (actual.status === 413 && !event);
        if (actual.status === 0) notes.push(`connection closed early (${actual.error})`);
        break;
      case 'not413':
        pass = actual.status !== 413 && actual.status !== 0;
        notes.push(`anomalies: ${evidence.anomalies.join(',') || 'none'}`);
        break;
      default: pass = false;
    }
    samples.push({
      id: d.id, description: d.description, input: { ...describeInput({ ...raw, body: null }), bodyBytes: size, bodyExcerpt: sanitize(String(body).slice(0, 60), 60) },
      expected: { verdict: { allow: 'allow', partial: 'allow/flag + BODY_PARTIALLY_INSPECTED', block: 'block', 413: 'block (413 BODY_TOO_LARGE)', not413: 'not rejected for size' }[d.expect], categories: d.expect === 'block' ? ['sqli'] : [] },
      actual, evidence, categoryHit: null, pass, notes
    });
  }
  log(`T4: ${samples.filter((s) => s.pass).length}/${samples.length} passed (generator: ${gen.source})`);
  return { title: 'Large bodies', description: `Bodies generated by ${gen.source}. Limits: inspectBodyBytes=${L.inspectBodyBytes}, maxBodyBytes=${L.maxBodyBytes}. All sent as POST /api/echo through the proxy; the target echoes the byte count it received.`, status: 'run', samples, summary: caseSummary(samples) };
}

// ───────────────────────────── corpus metrics ─────────────────────────────
async function runCorpus(stack, admin) {
  let benign, attack;
  try { benign = loadFixture('corpus-benign.json'); attack = loadFixture('corpus-attack.json'); } catch (e) { return { status: 'not-run', reason: e.message }; }
  if (!benign || !attack) return { status: 'not-run', reason: 'fixtures/corpus-benign.json or corpus-attack.json not found' };
  const records = [];
  for (const s of benign.samples) records.push({ ...(await runSample(stack, admin, s)), corpus: 'benign' });
  for (const s of attack.samples) records.push({ ...(await runSample(stack, admin, s)), corpus: 'attack' });
  const positive = (v) => v === 'block' || v === 'flag';
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const byCategory = {};
  const falseNegatives = [];
  const falsePositives = [];
  for (const r of records) {
    const truth = positive(r.expected.verdict);
    const pred = positive(r.actual.verdict) || r.actual.action === 'blocked';
    if (truth && pred) tp++; else if (truth && !pred) { fn++; falseNegatives.push(r); } else if (!truth && pred) { fp++; falsePositives.push(r); } else tn++;
    if (truth) {
      const cat = r.expected.categories[0] || 'uncategorised';
      byCategory[cat] = byCategory[cat] || { total: 0, detected: 0, coverage: 0 };
      byCategory[cat].total++;
      if (pred) byCategory[cat].detected++;
    }
  }
  for (const v of Object.values(byCategory)) v.coverage = Math.round((v.detected / v.total) * 1000) / 10;
  const benignRecs = records.filter((r) => !positive(r.expected.verdict));
  const attackRecs = records.filter((r) => positive(r.expected.verdict));
  const decisionMs = records.map((r) => r.evidence.decisionMs).filter((x) => typeof x === 'number');
  const metrics = {
    status: 'run',
    counts: { benign: benignRecs.length, attack: attackRecs.length },
    classification: classification({ tp, fp, tn, fn }),
    benignBlocked: benignRecs.filter((r) => r.actual.action === 'blocked').length,
    benignFlagged: benignRecs.filter((r) => r.actual.verdict === 'flag').length,
    attackBlocked: attackRecs.filter((r) => r.actual.action === 'blocked').length,
    byCategory,
    decisionLatencyMs: summarize(decisionMs),
    falseNegatives,
    falsePositives,
    records
  };
  log(`corpus: precision=${metrics.classification.precision} recall=${metrics.classification.recall} FP=${fp} FN=${fn}`);
  return metrics;
}

// ───────────────────────────── T-final ─────────────────────────────
async function runTFinal(ctx) {
  const { admin } = ctx;
  let stack = ctx.stack;
  const checks = [];
  const add = (c) => { checks.push(c); log(`${c.id} ${c.pass ? 'PASS' : 'FAIL'} — ${c.name}`); };
  const safe = (fn) => fn().catch((e) => ({ error: e.message }));

  // TF-01 oversized URL through the proxy
  await safe(async () => {
    const r = await stack.proxy({ path: '/search?q=' + 'a'.repeat(5000) });
    const ev = evidenceOf(await fetchEvent(admin, r.headers['x-waf-event-id']));
    add({ id: 'TF-01', name: 'Oversized URL via proxy', input: 'GET /search?q=<5000 × a>', expected: '400, blocked, MALFORMED_REQUEST, no internals',
      actual: `${r.status} ${r.headers['x-waf-action']}`, evidence: `event ${ev.eventId}; blockReason ${ev.blockReason}; anomalies ${ev.anomalies.join(',')}`,
      pass: r.status === 400 && r.headers['x-waf-action'] === 'blocked' && ev.blockReason === 'MALFORMED_REQUEST' && !findLeak(r.text) });
  });
  // TF-02 malformed percent-encoding
  await safe(async () => {
    const r = await stack.proxy({ path: '/search?q=%E0%A4%A%ZZ%' });
    add({ id: 'TF-02', name: 'Malformed percent-encoding via proxy', input: 'GET /search?q=%E0%A4%A%ZZ%', expected: 'handled safely (no 5xx, no internals), decision recorded',
      actual: `${r.status} ${r.headers['x-waf-action']}`, evidence: `event ${r.headers['x-waf-event-id'] || 'none'}`,
      pass: r.status > 0 && r.status < 500 && !!r.headers['x-waf-event-id'] && !findLeak(r.text) });
  });
  // TF-03 / TF-04 malformed + oversized API JSON
  const op = ctx.operator;
  await safe(async () => {
    const r = await rawRequest(stack.studioUrl, { method: 'POST', path: '/api/analyze', headers: { 'content-type': 'application/json', cookie: `waf_sid=${op.sid}`, 'x-csrf-token': op.csrfToken }, body: '{"label": "x", "sample": {' });
    let code = null; try { code = JSON.parse(r.text).error.code; } catch { /* */ }
    add({ id: 'TF-03', name: 'Malformed JSON to the API', input: 'POST /api/analyze {"label": "x", "sample": {', expected: '400 MALFORMED_JSON, no stack trace',
      actual: `${r.status} ${code}`, evidence: sanitize(r.text, 160), pass: r.status === 400 && code === 'MALFORMED_JSON' && !findLeak(r.text) });
  });
  await safe(async () => {
    const r = await op.post('/api/analyze', { label: 'big', sample: { method: 'POST', path: '/', headers: {}, body: 'a'.repeat(2.5 * 1024 * 1024) } });
    add({ id: 'TF-04', name: 'Oversized JSON to the API', input: 'POST /api/analyze with 2.5 MB JSON (limit 2 MiB for analyze/import, 256 KB elsewhere)', expected: '413 PAYLOAD_TOO_LARGE',
      actual: `${r.status} ${r.body && r.body.error && r.body.error.code}`, evidence: sanitize(r.text, 160), pass: r.status === 413 && !findLeak(r.text) });
  });
  // TF-05/06/07 unauthorized
  const someEvent = (await admin.get('/api/events?limit=1')).body.items[0];
  await safe(async () => {
    const r = await stack.client().get('/api/events/' + someEvent.id);
    add({ id: 'TF-05', name: 'Unauthenticated request for a record', input: `GET /api/events/${someEvent.id} (no session)`, expected: '401 AUTH_REQUIRED, no record data',
      actual: `${r.status} ${r.body && r.body.error && r.body.error.code}`, evidence: sanitize(r.text, 160), pass: r.status === 401 && !r.text.includes(someEvent.path) });
  });
  await safe(async () => {
    const viewer = await stack.login('viewer');
    const before = (await admin.get('/api/audit?action=auth.denied&limit=500')).body.items.length;
    const r = await viewer.get('/api/events/' + someEvent.id);
    const after = (await admin.get('/api/audit?action=auth.denied&limit=500')).body.items;
    const leaked = r.text.includes('decision') || r.text.includes(someEvent.id);
    add({ id: 'TF-06', name: 'Viewer requests protected evidence', input: `viewer GET /api/events/${someEvent.id}`, expected: 'generic 403, nothing leaked, auth.denied audited',
      actual: `${r.status} ${r.body && r.body.error && r.body.error.code}`, evidence: `auth.denied entries ${before} → ${after.length}; latest actor ${after[0] && after[0].actorName}`,
      pass: r.status === 403 && !leaked && after.length > before });
    const c = await viewer.put('/api/config', { config: {}, reason: 'x', confirm: true });
    add({ id: 'TF-07', name: 'Viewer attempts a config change', input: 'viewer PUT /api/config', expected: '403 FORBIDDEN', actual: String(c.status), evidence: sanitize(c.text, 120), pass: c.status === 403 });
  });
  // TF-08 repeated submission → proxy rate limit
  await safe(async () => {
    await setConfig(admin, (c) => { c.rateLimit = { enabled: true, windowMs: 60000, maxRequests: 10 }; }, 'T-final: tight rate limit');
    const statuses = [];
    let limited = null;
    for (let i = 0; i < 15; i++) {
      const r = await stack.proxy({ path: '/search?q=repeat' });
      statuses.push(r.status);
      if (r.status === 429 && !limited) limited = r;
    }
    const ev = limited ? evidenceOf(await fetchEvent(admin, limited.headers['x-waf-event-id'])) : null;
    add({ id: 'TF-08', name: 'Repeated submission through the proxy', input: '15 × GET /search?q=repeat with limit 10/min', expected: 'first 10 pass, then 429 with RATE_LIMITED evidence',
      actual: statuses.join(','), evidence: ev ? `event ${ev.eventId}; blockReason ${ev.blockReason}` : 'no 429',
      pass: statuses.slice(0, 10).every((s) => s === 200) && statuses.slice(10).every((s) => s === 429) && ev && ev.blockReason === 'RATE_LIMITED' });
    await setConfig(admin, (c) => { c.rateLimit = { enabled: true, windowMs: 60000, maxRequests: 100000 }; }, 'T-final: relax rate limit');
  });
  // TF-09 repeated login failures → lockout
  await safe(async () => {
    await admin.post('/api/users', { username: 'eval-lockout', password: 'Eval-Lockout-Passw0rd!', role: 'viewer' });
    const statuses = [];
    for (let i = 0; i < 7; i++) statuses.push((await stack.client().login('eval-lockout', 'wrong-password-' + i)).status);
    const right = await stack.client().login('eval-lockout', 'Eval-Lockout-Passw0rd!');
    const lock = (await admin.get('/api/audit?action=auth.lockout&limit=50')).body.items;
    add({ id: 'TF-09', name: 'Repeated failed logins', input: '7 wrong passwords then the right one for user eval-lockout', expected: '401 ×5, then 429; correct password also refused; auth.lockout audited',
      actual: `${statuses.join(',')} then ${right.status}`, evidence: `auth.lockout entries: ${lock.length}`,
      pass: statuses.slice(0, 5).every((s) => s === 401) && statuses.slice(5).every((s) => s === 429) && right.status === 429 && lock.length > 0 });
  });
  // TF-10 safe failure when the target is down
  await safe(async () => {
    await stack.stopTarget();
    const r = await stack.proxy({ path: '/search?q=mug' });
    const health = await stack.client().get('/api/health');
    const sysErr = await waitFor(async () => (await admin.get('/api/audit?action=system.error&limit=20')).body.items.length);
    add({ id: 'TF-10', name: 'Target unavailable', input: 'GET /search?q=mug via proxy after stopping the target', expected: '502 safe page, no internals, studio still healthy, system.error audited',
      actual: `${r.status}; studio health ${health.status}`, evidence: `system.error entries: ${sysErr}; body: ${sanitize(r.text, 80)}`,
      pass: r.status === 502 && !findLeak(r.text) && !/ECONNREFUSED/.test(r.text) && health.status === 200 && sysErr > 0 });
  });
  // TF-11 recovery after restart
  await safe(async () => {
    const snap = async (a) => ({
      rules: (await a.get('/api/rules')).body.items.length,
      configVersion: (await a.get('/api/config')).body.version,
      events: (await a.get('/api/events?limit=1')).body.total,
      audit: (await a.get('/api/audit?limit=1')).body.total,
      rulesetVersion: (await a.get('/api/rules')).body.rulesetVersion
    });
    const before = await snap(admin);
    await stack.stop({ keepData: true });
    const dataDir = stack.dataDir;
    stack = await startStack({ dataDir, seed: false, passwords: stack.passwords });
    ctx.stack = stack;
    const admin2 = await stack.login('admin');
    ctx.admin = admin2;
    const after = await snap(admin2);
    const verify = (await admin2.get('/api/audit/verify')).body;
    const block = await stack.proxy({ path: '/products?id=1%20OR%201%3D1' });
    const allow = await stack.proxy({ path: '/search?q=mug' });
    const pass = after.rules === before.rules && after.configVersion === before.configVersion && after.rulesetVersion === before.rulesetVersion &&
      after.events >= before.events && after.audit > before.audit && verify.ok === true && block.status === 403 && allow.status === 200;
    add({ id: 'TF-11', name: 'Recovery after restart (same DB file)', input: 'stop the whole stack, start again on the same data dir',
      expected: 'rules, config version, events and audit persisted; audit chain verifies; WAF enforcing again',
      actual: `rules ${before.rules}→${after.rules}; config v${before.configVersion}→v${after.configVersion}; events ${before.events}→${after.events}; audit ${before.audit}→${after.audit}; SQLi ${block.status}; benign ${allow.status}`,
      evidence: `audit verify ok=${verify.ok} checked=${verify.checked} brokenAt=${verify.brokenAt}`, pass });
  });
  return { title: 'Malformed/oversized input, unauthorized request, repeated submission, safe failure, recovery after restart', status: 'run', checks, summary: caseSummary(checks) };
}

// ───────────────────────────── main ─────────────────────────────
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!stackAvailable()) {
    console.error('[evaluate] The backend is not available yet (src/index.js / src/services/seed.js missing). Nothing measured.');
    process.exit(1);
  }
  const started = Date.now();
  const results = {
    generatedAt: new Date().toISOString(),
    environment: { node: process.version, os: `${os.type()} ${os.release()} (${process.platform}/${process.arch})`, cpu: (os.cpus()[0] || {}).model || 'unknown', cpus: os.cpus().length, totalMemGb: Math.round(os.totalmem() / 2 ** 30) },
    cases: {},
    metrics: null,
    totals: null
  };
  let stack;
  const ctx = {};
  try {
    log('starting stack on ephemeral ports …');
    stack = await startStack();
    ctx.stack = stack;
    const admin = await stack.login('admin');
    const operator = await stack.login('operator');
    ctx.admin = admin;
    ctx.operator = operator;
    // Measurement config: block mode, generous proxy rate limit so T1–T6 are not throttled (T-final tests it).
    await setConfig(admin, (c) => { c.mode = 'block'; c.rateLimit = { enabled: true, windowMs: 60000, maxRequests: 100000 }; }, 'evaluation baseline');
    const cfgNow = await admin.get('/api/config');
    const rules = await admin.get('/api/rules');
    results.stack = { config: cfgNow.body.config, configVersion: cfgNow.body.version, rulesetVersion: rules.body.rulesetVersion, rules: rules.body.items.length,
      engineVersion: null };

    results.cases.T1 = await runFixtureCase(stack, admin, 'T1', 't1-attacks.json', 'SQLi / XSS / path traversal strings');
    results.cases.T2 = await runFixtureCase(stack, admin, 'T2', 't2-encoding.json', 'Encoding variants');
    results.cases.T3 = await runFixtureCase(stack, admin, 'T3', 't3-benign.json', 'Benign false positives');
    results.cases.T4 = await runT4(stack, admin, cfgNow.body.config);
    results.cases.T5 = await runFixtureCase(stack, admin, 'T5', 't5-bypass.json', 'Bypass attempts');
    for (const c of Object.values(results.cases)) {
      const ev = c.samples && c.samples.find((s) => s.evidence.eventId);
      if (ev && !results.stack.engineVersion) {
        const full = await fetchEvent(admin, ev.evidence.eventId);
        results.stack.engineVersion = full && full.decision && full.decision.engine ? full.decision.engine.engineVersion : null;
      }
    }

    if (args.latency && stack.targetUrl) {
      log(`T6: measuring latency overhead with N=${args.n} …`);
      const latency = await measureOverhead({ directUrl: stack.targetUrl, proxyUrl: stack.proxyUrl, n: args.n, warmup: args.warmup });
      results.cases.T6 = { title: 'Latency overhead', status: 'run', description: 'Benign requests sent directly to the target vs. through the WAF proxy (interleaved, keep-alive, same process). Proxy timings include inspection, event storage and forwarding.',
        latency, checks: latency.results.map((r) => ({ id: 'T6', name: r.scenario, input: `${r.request.method} ${r.request.path} ×${r.n}`, expected: latency.criterion,
          actual: `p95 overhead ${r.overheadMs.p95} ms (mean ${r.overheadMs.mean}, p99 ${r.overheadMs.p99})`, evidence: `direct p95 ${r.direct.p95} ms, proxy p95 ${r.proxy.p95} ms, errors ${JSON.stringify(r.errors)}`, pass: r.pass })) };
      results.cases.T6.summary = caseSummary(results.cases.T6.checks);
      log(`T6: ${latency.pass ? 'PASS' : 'FAIL'} — ${latency.results.map((r) => `${r.scenario}: p95 overhead ${r.overheadMs.p95} ms`).join('; ')}`);
    } else {
      results.cases.T6 = { title: 'Latency overhead', status: 'not-run', reason: args.latency ? 'target URL unknown' : '--skip-latency' };
    }

    log('corpus metrics …');
    results.metrics = await runCorpus(stack, admin);

    log('T-final …');
    results.cases['T-final'] = await runTFinal(ctx);
    stack = ctx.stack;
  } catch (e) {
    results.harnessError = sanitize(e && e.stack ? e.stack : String(e), 2000);
    console.error('[evaluate] harness error:', e);
  } finally {
    if (ctx.stack) {
      const dir = ctx.stack.dataDir;
      await ctx.stack.stop({ keepData: true }).catch(() => {});
      rmrf(dir);
    }
  }

  // totals
  let total = 0, passed = 0;
  for (const c of Object.values(results.cases)) if (c.summary) { total += c.summary.total; passed += c.summary.passed; }
  results.totals = { total, passed, failed: total - passed, passRate: total ? Math.round((passed / total) * 1000) / 10 : 0 };
  results.durationSec = Math.round((Date.now() - started) / 100) / 10;
  // keep the JSON lean: corpus records are summarised in metrics, full list kept for reproducibility
  fs.mkdirSync(args.out, { recursive: true });
  fs.writeFileSync(path.join(args.out, 'results.json'), JSON.stringify(results, null, 2) + '\n');
  fs.writeFileSync(path.join(args.out, 'results.md'), render(results));

  console.log('');
  console.log('──────────── evaluation summary ────────────');
  for (const [k, c] of Object.entries(results.cases)) {
    const s = c.summary;
    console.log(`${k.padEnd(8)} ${c.status === 'not-run' ? 'NOT RUN  ' + c.reason : `${s.passed}/${s.total} passed`}`);
  }
  if (results.metrics && results.metrics.status === 'run') {
    const m = results.metrics.classification;
    console.log(`corpus   precision ${m.precision}  recall ${m.recall}  FP ${m.fp}  FN ${m.fn}  decision p95 ${results.metrics.decisionLatencyMs.p95} ms`);
  }
  console.log(`TOTAL    ${passed}/${total} (${results.totals.passRate} %) in ${results.durationSec} s`);
  console.log(`written  ${path.relative(ROOT, path.join(args.out, 'results.md'))}, results.json`);
  process.exit(results.harnessError ? 1 : 0);
}

if (require.main === module) main();

module.exports = { fallbackMakeLargeBody, normalizeBody };
