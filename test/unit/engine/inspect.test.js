'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { engine, ctx } = require('./helpers');

function assertDecision(d) {
  assert.ok(['allow', 'flag', 'block'].includes(d.verdict));
  assert.ok(['allowed', 'blocked', 'logged'].includes(d.action));
  assert.equal(typeof d.wouldBlock, 'boolean');
  assert.ok(Array.isArray(d.matches) && Array.isArray(d.suppressed) && Array.isArray(d.anomalies) && Array.isArray(d.explanation));
  assert.equal(typeof d.score.total, 'number');
  for (const m of d.matches) assert.ok(m.excerpt.length <= 120);
  assert.doesNotThrow(() => JSON.stringify(d));
}

// deterministic random generator so failures are reproducible
function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

test('hostile non-request values never throw', () => {
  const values = [undefined, null, 0, 'GET /', [], [1, 2], () => 1, Symbol('x'), 10n, { method: {} }, { method: 'GET', url: {} },
    { method: 'GET', url: '/', headers: 'x' }, { method: 'GET', url: '/', headers: [['a', 'b']] }, { method: 'GET', url: '/', body: { a: 1 } },
    { method: 'GET', url: '/', body: 5 }, { method: 'GET', url: '/', bodyBytes: -1 }, { method: 'GET', url: '/', bodyBytes: 'NaN' },
    { method: 'GET', url: '/', headers: { 'x-a': null, 'x-b': ['1', 2], 'x-c': 3 } }];
  for (const v of values) {
    let d;
    assert.doesNotThrow(() => { d = engine.inspect(v, ctx()); });
    assertDecision(d);
  }
});

test('objects with throwing getters fall back to a safe MALFORMED_REQUEST decision', () => {
  const evil = { get method() { throw new Error('boom'); }, url: '/' };
  const d = engine.inspect(evil, ctx());
  assert.equal(d.verdict, 'block');
  assert.equal(d.blockReason, 'MALFORMED_REQUEST');
  assert.equal(d.statusCode, 400);
  assert.ok(!JSON.stringify(d).includes('boom'), 'no internal error text leaks');
  const evilHeaders = { method: 'GET', url: '/', headers: new Proxy({}, { ownKeys() { throw new Error('x'); } }) };
  assertDecision(engine.inspect(evilHeaders, ctx()));
  const m = engine.inspect(evil, ctx({ config: { ...engine.DEFAULT_CONFIG, mode: 'monitor' } }));
  assert.equal(m.action, 'logged');
});

test('hostile context values never throw', () => {
  const raw = { method: 'GET', url: '/?q=1', headers: {} };
  for (const c of [undefined, null, 5, { rules: 'x' }, { rules: [null, 1, {}, { test: 'x' }] }, { config: 'x' }, { config: { mode: 'weird', thresholds: 'x' } },
    { exceptions: 'x' }, { rateLimiter: {} }, { rateLimiter: { check() { throw new Error('x'); } } }, { now: 'yesterday' }]) {
    let d;
    assert.doesNotThrow(() => { d = engine.inspect(raw, c); });
    assertDecision(d);
  }
});

test('a rule whose test throws is skipped instead of breaking inspection', () => {
  const bad = { id: 1, name: 'bad', version: 1, severity: 'low', score: 1, category: 'x', tags: [], test() { throw new Error('x'); } };
  const d = engine.inspect({ method: 'GET', url: '/', headers: {} }, { rules: [bad] });
  assert.equal(d.verdict, 'allow');
});

test('fuzz: random bytes in method, url, headers and body never throw', () => {
  const rand = rng(1234);
  const bytes = (n) => Buffer.from(Array.from({ length: n }, () => Math.floor(rand() * 256)));
  const str = (n) => bytes(n).toString('latin1');
  const c = ctx();
  for (let i = 0; i < 300; i++) {
    const raw = {
      method: rand() < 0.7 ? ['GET', 'POST', 'PUT', 'TRACE'][i % 4] : str(1 + Math.floor(rand() * 8)),
      url: rand() < 0.5 ? `/${encodeURIComponent(str(Math.floor(rand() * 60)))}?a=${str(Math.floor(rand() * 40))}` : `/${str(Math.floor(rand() * 200))}`,
      headers: { 'content-type': ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'text/plain', str(10)][i % 5], cookie: str(30), 'user-agent': str(20) },
      body: rand() < 0.5 ? bytes(Math.floor(rand() * 2000)) : str(Math.floor(rand() * 2000)),
    };
    let d;
    assert.doesNotThrow(() => { d = engine.inspect(raw, c); }, `iteration ${i}`);
    assertDecision(d);
  }
});

test('fuzz: very long and deeply nested inputs never throw', () => {
  const c = ctx();
  const longs = [
    { method: 'GET', url: '/' + 'a'.repeat(100000) },
    { method: 'GET', url: '/?' + 'a=%25'.repeat(800) },
    { method: 'POST', url: '/', headers: { 'content-type': 'application/json' }, body: '['.repeat(50000) },
    { method: 'POST', url: '/', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ a: 'x'.repeat(60000) }) },
    { method: 'POST', url: '/', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: '&'.repeat(70000) },
    { method: 'POST', url: '/', headers: { 'content-type': 'text/plain' }, body: crypto.randomBytes(300000) },
    { method: 'POST', url: '/', headers: { 'content-type': 'multipart/form-data; boundary=b' }, body: '--b\r\n'.repeat(20000) },
    { method: 'GET', url: '/?q=' + '%F0%9F%98%80'.repeat(300), headers: { 'user-agent': '\uD800'.repeat(100) } },
  ];
  for (const raw of longs) {
    let d;
    assert.doesNotThrow(() => { d = engine.inspect(raw, c); });
    assertDecision(d);
  }
});

test('typical request inspection is fast (< 5 ms average with the default rules)', () => {
  const c = ctx();
  const raw = { method: 'POST', url: '/api/orders?ref=home', headers: { 'user-agent': 'Mozilla/5.0', 'content-type': 'application/json' }, body: JSON.stringify({ items: [{ sku: 'A1', qty: 2 }], note: 'Leave at the door' }) };
  for (let i = 0; i < 20; i++) engine.inspect(raw, c);
  const n = 200;
  const t = process.hrtime.bigint();
  for (let i = 0; i < n; i++) engine.inspect(raw, c);
  const avg = Number(process.hrtime.bigint() - t) / 1e6 / n;
  assert.ok(avg < 5, `average ${avg} ms`);
});
