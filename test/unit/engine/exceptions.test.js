'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, ctx, UA } = require('./helpers');

const attack = (path = '/search', method = 'GET', name = 'q') => ({ method, url: `${path}?${name}=${encodeURIComponent("' OR 1=1")}`, headers: UA });
const exc = (scope, extra = {}) => ({ id: 'exc_1', ruleId: 942100, scope: { pathPrefix: null, location: null, method: null, ...scope }, reason: 'test', status: 'approved', expiresAt: null, ...extra });

test('a matching scoped exception suppresses the rule and lists it in suppressed[]', () => {
  const d = engine.inspect(attack(), ctx({ exceptions: [exc({ pathPrefix: '/search', location: 'query.q', method: 'GET' })] }));
  assert.equal(d.verdict, 'allow');
  assert.deepEqual(d.matches, []);
  assert.equal(d.suppressed.length, 1);
  assert.equal(d.suppressed[0].ruleId, 942100);
  assert.equal(d.suppressed[0].suppressedBy, 'exc_1');
  assert.equal(d.suppressed[0].location, 'query.q');
  assert.equal(d.score.total, 0);
  assert.ok(d.explanation.some((l) => /suppressed by approved exception exc_1/.test(l)));
});

test('an exception with all-null scope covers the rule everywhere', () => {
  const d = engine.inspect(attack('/other', 'POST', 'x'), ctx({ exceptions: [exc({})] }));
  assert.equal(d.suppressed.length, 1);
});

test('non-matching scope fields do not suppress', () => {
  for (const scope of [{ pathPrefix: '/admin' }, { location: 'query.other' }, { method: 'POST' }]) {
    const d = engine.inspect(attack(), ctx({ exceptions: [exc(scope)] }));
    assert.equal(d.verdict, 'block', JSON.stringify(scope));
    assert.equal(d.suppressed.length, 0);
    assert.equal(d.matches[0].suppressedBy, null);
  }
});

test('an exception for another rule id does not suppress', () => {
  const d = engine.inspect(attack(), ctx({ exceptions: [exc({}, { ruleId: 941100 })] }));
  assert.equal(d.verdict, 'block');
});

test('the rule is suppressed only if every matched location is covered', () => {
  const raw = { method: 'GET', url: `/search?q=${encodeURIComponent("' OR 1=1")}&x=${encodeURIComponent('1 or 2=2')}`, headers: UA };
  const partial = engine.inspect(raw, ctx({ exceptions: [exc({ location: 'query.q' })] }));
  assert.equal(partial.verdict, 'block', 'payload in query.x is still detected');
  assert.equal(partial.suppressed.length, 0);
  const full = engine.inspect(raw, ctx({ exceptions: [exc({ location: 'query.q' }), exc({ location: 'query.x' }, { id: 'exc_2' })] }));
  assert.equal(full.verdict, 'allow');
});

test('pathPrefix is matched against the canonical path (no ../ escape into the exception)', () => {
  const raw = { method: 'GET', url: `/search/../admin?q=${encodeURIComponent("' OR 1=1")}`, headers: UA };
  const d = engine.inspect(raw, ctx({ exceptions: [exc({ pathPrefix: '/search' })] }));
  assert.equal(d.suppressed.length, 0);
  assert.ok(d.matches.some((m) => m.ruleId === 942100));
});

test('expired or non-approved exceptions are ignored (defence in depth)', () => {
  const now = Date.parse('2026-10-19T12:00:00Z');
  const expired = exc({}, { expiresAt: '2026-10-19T11:00:00Z' });
  const pending = exc({}, { status: 'pending' });
  const future = exc({}, { expiresAt: '2026-10-20T00:00:00Z' });
  assert.equal(engine.inspect(attack(), ctx({ now, exceptions: [expired, pending] })).verdict, 'block');
  assert.equal(engine.inspect(attack(), ctx({ now, exceptions: [future] })).verdict, 'allow');
});

test('method scope is case-insensitive and malformed exception entries are skipped', () => {
  const d = engine.inspect(attack(), ctx({ exceptions: [null, 'x', { ruleId: 'abc' }, exc({ method: 'get' })] }));
  assert.equal(d.verdict, 'allow');
});
