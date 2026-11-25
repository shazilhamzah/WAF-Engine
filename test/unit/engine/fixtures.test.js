'use strict';
// Benign fixtures must be allowed by the default engine (false-positive target: 0); large-body generator.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { engine, ctx, fromSample, ROOT } = require('./helpers');
const { makeLargeBody, makeLargeRequest } = require('../../../fixtures/large-body');

const load = (f) => JSON.parse(fs.readFileSync(path.join(ROOT, 'fixtures', f), 'utf8'));

for (const [file, min] of [['t3-benign.json', 25], ['corpus-benign.json', 60]]) {
  const data = load(file);
  test(`${file} is well-formed with at least ${min} samples`, () => {
    assert.ok(typeof data.case === 'string' && data.title && data.description);
    assert.ok(data.samples.length >= min, `${data.samples.length}`);
    const ids = new Set();
    for (const s of data.samples) {
      assert.ok(!ids.has(s.id), `duplicate ${s.id}`);
      ids.add(s.id);
      assert.ok(s.description && s.request && s.expected);
      assert.ok(s.request.path.startsWith('/') && s.request.path.length <= 4096);
      assert.ok(s.request.body === null || typeof s.request.body === 'string');
      assert.deepEqual(s.expected, { verdict: 'allow', categories: [] });
      for (const name of Object.keys(s.request.headers || {})) assert.match(name, /^[a-z0-9-]+$/);
    }
  });
  for (const s of data.samples) {
    test(`${s.id} ${s.description} -> allow`, () => {
      for (const config of [engine.DEFAULT_CONFIG, { ...engine.DEFAULT_CONFIG, mode: 'monitor' }]) {
        const d = engine.inspect(fromSample(s.request), ctx({ config }));
        assert.equal(d.verdict, 'allow', `score ${d.score.total}: ${d.explanation.join(' | ')}`);
        assert.equal(d.action, 'allowed');
      }
    });
  }
}

test('import-sample.json is a valid import file whose samples are all allowed', () => {
  const data = load('import-sample.json');
  assert.ok(Array.isArray(data.samples) && data.samples.length >= 3 && data.samples.length <= 100);
  for (const s of data.samples) {
    assert.deepEqual(Object.keys(s).sort(), ['body', 'headers', 'method', 'path']);
    assert.equal(engine.inspect(fromSample(s), ctx()).verdict, 'allow');
  }
});

test('makeLargeBody produces exact sizes and places the payload where requested', () => {
  assert.equal(Buffer.byteLength(makeLargeBody(70000)), 70000);
  const marker = 'MARKER-123';
  const start = makeLargeBody(10000, { payload: marker, position: 'start' });
  const mid = makeLargeBody(10000, { payload: marker, position: 'middle' });
  const end = makeLargeBody(10000, { payload: marker, position: 'end' });
  for (const b of [start, mid, end]) assert.equal(Buffer.byteLength(b), 10000);
  assert.ok(start.indexOf(marker) < 5);
  assert.ok(Math.abs(mid.indexOf(marker) - 5000) < 20);
  assert.ok(end.indexOf(marker) > 9980);
  assert.equal(Buffer.byteLength(makeLargeBody(500, { payload: 'é€', position: 'end' })), 500);
  assert.throws(() => makeLargeBody(5, { payload: 'too long payload' }), RangeError);
  assert.throws(() => makeLargeBody(10, { position: 'side' }), RangeError);
  assert.throws(() => makeLargeBody(-1), RangeError);
});

test('large bodies: filler is benign, inspection window and size limit behave as documented (T4)', () => {
  const c = ctx();
  const filler = engine.inspect(makeLargeRequest(65536), c);
  assert.equal(filler.verdict, 'allow');
  assert.equal(filler.score.total, 0);
  const payload = '<script>alert(1)</script>';
  for (const position of ['start', 'middle', 'end']) {
    assert.equal(engine.inspect(makeLargeRequest(60000, { payload, position }), c).verdict, 'block', `inside window, ${position}`);
  }
  const partial = engine.inspect(makeLargeRequest(200000, { payload, position: 'end' }), c);
  assert.ok(partial.anomalies.some((a) => a.code === 'BODY_PARTIALLY_INSPECTED'));
  assert.equal(partial.request.truncated, true);
  assert.equal(partial.request.inspectedBytes, 65536);
  assert.equal(engine.inspect(makeLargeRequest(200000, { payload, position: 'start' }), c).verdict, 'block');
  const tooBig = engine.inspect(makeLargeRequest(1048577), c);
  assert.equal(tooBig.statusCode, 413);
  assert.equal(tooBig.blockReason, 'BODY_TOO_LARGE');
});
