'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { percentile, summarize, classification, sanitize, mdCode } = require('./stats');
const { judge, toRaw } = require('./runner');
const { render } = require('./report');
const { measureOverhead } = require('./latency');
const { fallbackMakeLargeBody, normalizeBody } = require('../../scripts/evaluate');
const { createTargetApp } = require('../../target/app');
const { rawRequest, wireSafePath } = require('../helpers/http');

test('percentile uses nearest rank', () => {
  const v = Array.from({ length: 100 }, (_, i) => i + 1);
  assert.equal(percentile(v, 50), 50);
  assert.equal(percentile(v, 95), 95);
  assert.equal(percentile(v, 99), 99);
  assert.equal(percentile([5], 99), 5);
  assert.equal(percentile([], 50), null);
  assert.deepEqual(summarize([1, 2, 3]).n, 3);
});

test('classification metrics', () => {
  const m = classification({ tp: 8, fp: 2, tn: 18, fn: 2 });
  assert.equal(m.precision, 0.8);
  assert.equal(m.recall, 0.8);
  assert.equal(m.f1, 0.8);
  assert.equal(m.falsePositiveRate, 0.1);
  assert.equal(classification({ tp: 0, fp: 0, tn: 0, fn: 0 }).precision, null);
});

test('sanitize escapes control characters and truncates', () => {
  assert.equal(sanitize('a\u0000b\nc'), 'a\\x00b\\x0ac');
  assert.match(sanitize('x'.repeat(200), 10), /^x{10}… \(\+190 chars\)$/);
});

test('mdCode neutralises HTML and table syntax', () => {
  const s = mdCode('<script>alert(1)</script>|`x`');
  assert.ok(!s.includes('<script>'));
  assert.ok(!s.includes('|'));
  assert.ok(!s.includes('`'));
  assert.ok(s.startsWith('<code>'));
});

test('expected verdict mapping', () => {
  const ev = { categories: ['sqli'], blockReason: 'SCORE_THRESHOLD' };
  assert.equal(judge({ verdict: 'block', categories: ['sqli'] }, { action: 'blocked', status: 403, verdict: 'block' }, ev).pass, true);
  assert.equal(judge({ verdict: 'block' }, { action: 'allowed', status: 200, verdict: 'flag' }, ev).pass, false);
  assert.equal(judge({ verdict: 'allow' }, { action: 'allowed', status: 200, verdict: 'allow' }, { categories: [] }).pass, true);
  const fpFlag = judge({ verdict: 'allow' }, { action: 'allowed', status: 200, verdict: 'flag' }, { categories: [] });
  assert.equal(fpFlag.pass, false);
  assert.match(fpFlag.notes.join(), /soft false positive/);
  assert.equal(judge({ verdict: 'flag' }, { action: 'allowed', status: 200, verdict: 'flag' }, { categories: [] }).pass, true);
  assert.equal(judge({ verdict: 'flag' }, { action: 'blocked', status: 403, verdict: 'block' }, { categories: [] }).pass, false);
  const r413 = judge({ verdict: 'block' }, { action: 'blocked', status: 413, verdict: 'block' }, { categories: [], blockReason: 'BODY_TOO_LARGE' });
  assert.equal(r413.pass, true);
  assert.match(r413.notes.join(), /413/);
});

test('toRaw converts fixture requests', () => {
  const r = toRaw({ method: 'post', path: '/login', headers: { 'Content-Type': 'application/json' }, body: { a: 1 } });
  assert.equal(r.method, 'POST');
  assert.equal(r.headers['content-type'], 'application/json');
  assert.equal(r.body, '{"a":1}');
  const f = toRaw({ path: '/x', body: 'a=b' });
  assert.equal(f.headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(toRaw({ path: '/y' }).body, null);
});

test('wireSafePath keeps attack bytes but encodes what node:http refuses', () => {
  assert.equal(wireSafePath('/a/../b?q=%27'), '/a/../b?q=%27');
  assert.equal(wireSafePath('/s?q=a b'), '/s?q=a%20b');
  assert.equal(wireSafePath('/s?q=é'), '/s?q=%C3%A9');
});

test('fallback large-body generator respects size and payload position', () => {
  const b = fallbackMakeLargeBody(10240);
  assert.equal(Buffer.byteLength(b), 10240);
  const end = fallbackMakeLargeBody(200 * 1024, { payload: "' OR 1=1", position: 'end' });
  assert.ok(end.indexOf(encodeURIComponent("' OR 1=1")) > 65536);
  const start = fallbackMakeLargeBody(200 * 1024, { payload: "' OR 1=1", position: 'start' });
  assert.ok(start.indexOf(encodeURIComponent("' OR 1=1")) < 100);
  assert.equal(normalizeBody('{"a":1}').contentType, 'application/json');
  assert.equal(normalizeBody({ body: 'x', contentType: 'text/plain' }).contentType, 'text/plain');
});

test('render produces a markdown report without raw HTML from inputs', () => {
  const rec = { id: 'T1-X', input: { method: 'GET', path: '/s?q=<script>alert(1)</script>', bodyBytes: 0 }, expected: { verdict: 'block', categories: ['xss'] },
    actual: { status: 403, action: 'blocked', verdict: 'block' }, evidence: { eventId: 'evt_1', ruleIds: [941100], score: 5, categories: ['xss'], anomalies: [], decodedVia: [] }, pass: true, notes: [] };
  const md = render({ generatedAt: 'now', durationSec: 1, environment: { node: 'v', os: 'o', cpu: 'c', cpus: 1 }, cases: { T1: { title: 'x', status: 'run', samples: [rec], summary: { total: 1, passed: 1, failed: 0, passRate: 100 } }, T2: { title: 'y', status: 'not-run', reason: 'missing' } }, totals: { total: 1, passed: 1, failed: 0, passRate: 100 }, metrics: null });
  assert.ok(md.includes('# WAF Studio — Evaluation Results'));
  assert.ok(!md.includes('<script>'));
  assert.match(md, /941100/);
  assert.match(md, /not run/);
});

test('latency harness measures two local servers and computes overhead', async () => {
  const a = http.createServer(createTargetApp());
  const b = http.createServer(createTargetApp());
  await Promise.all([new Promise((r) => a.listen(0, '127.0.0.1', r)), new Promise((r) => b.listen(0, '127.0.0.1', r))]);
  try {
    const res = await measureOverhead({ directUrl: `http://127.0.0.1:${a.address().port}`, proxyUrl: `http://127.0.0.1:${b.address().port}`, n: 20, warmup: 2 });
    assert.equal(res.results.length, 2);
    for (const r of res.results) {
      assert.equal(r.direct.n, 20);
      assert.equal(r.proxy.n, 20);
      assert.equal(typeof r.overheadMs.p95, 'number');
      assert.equal(r.errors.nonSuccess, 0);
    }
    const one = await rawRequest(`http://127.0.0.1:${a.address().port}`, { path: '/files?name=../secret/flag.txt' });
    assert.equal(one.status, 200, 'raw client does not normalise ../');
  } finally {
    a.close(); b.close();
  }
});

test('rawRequest resolves (status 0) instead of throwing when nothing listens', async () => {
  const srv = http.createServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  await new Promise((r) => srv.close(r));
  const r = await rawRequest(`http://127.0.0.1:${port}`, { path: '/' });
  assert.equal(r.status, 0);
  assert.ok(r.error);
});
