'use strict';
// FR-3 scoring and FR-4 block/monitor modes.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, ctx, getWith, UA } = require('./helpers');

const monitor = () => ({ ...engine.DEFAULT_CONFIG, mode: 'monitor' });

test('score = sum of rule points + anomaly points, with per-category breakdown and contributions', () => {
  // SQL tautology (5) inside a double-encoded value (DOUBLE_ENCODING +2)
  const d = engine.inspect({ method: 'GET', url: '/search?q=%2527%2520OR%25201%253D1', headers: UA }, ctx());
  assert.equal(d.score.total, 7);
  assert.deepEqual(d.score.byCategory, { sqli: 5, anomaly: 2 });
  assert.equal(d.score.flagThreshold, 3);
  assert.equal(d.score.blockThreshold, 5);
  assert.deepEqual(d.score.contributions.map((c) => [c.source, c.id, c.points]), [['rule', '942100', 5], ['anomaly', 'DOUBLE_ENCODING', 2]]);
  assert.ok(d.score.contributions.every((c) => typeof c.reason === 'string' && c.reason));
});

test('a rule counts once per request even when it matches several locations', () => {
  const d = engine.inspect({ method: 'GET', url: `/s?a=${encodeURIComponent("' OR 1=1")}&b=${encodeURIComponent('1 or 2=2')}`, headers: UA }, ctx());
  const m = d.matches.filter((x) => x.ruleId === 942100);
  assert.equal(m.length, 1);
  assert.deepEqual(m[0].locations, ['query.a', 'query.b']);
  assert.equal(d.score.total, 5);
});

test('verdicts follow thresholds: allow < flag <= flag verdict < block', () => {
  assert.equal(engine.inspect(getWith('q', 'hello'), ctx()).verdict, 'allow');
  // XSS embedding tag alone scores 3 -> flag
  const flag = engine.inspect(getWith('q', '<iframe>'), ctx());
  assert.equal(flag.score.total, 3);
  assert.equal(flag.verdict, 'flag');
  assert.equal(flag.action, 'allowed');
  assert.equal(flag.wouldBlock, false);
  const block = engine.inspect(getWith('q', '<script>alert(1)</script>'), ctx());
  assert.equal(block.verdict, 'block');
  // custom thresholds change the verdict
  const strict = engine.inspect(getWith('q', '<iframe>'), ctx({ config: { ...engine.DEFAULT_CONFIG, thresholds: { flag: 1, block: 3 } } }));
  assert.equal(strict.verdict, 'block');
});

test('same attack: blocked in block mode, logged with wouldBlock in monitor mode (FR-4)', () => {
  const raw = getWith('q', "' OR 1=1--");
  const b = engine.inspect(raw, ctx());
  assert.equal(b.mode, 'block');
  assert.equal(b.verdict, 'block');
  assert.equal(b.action, 'blocked');
  assert.equal(b.wouldBlock, true);
  assert.equal(b.statusCode, 403);
  assert.equal(b.blockReason, 'SCORE_THRESHOLD');
  const m = engine.inspect(raw, ctx({ config: monitor() }));
  assert.equal(m.mode, 'monitor');
  assert.equal(m.verdict, 'block');
  assert.equal(m.action, 'logged');
  assert.equal(m.wouldBlock, true);
  assert.equal(m.statusCode, null);
  assert.equal(m.blockReason, 'SCORE_THRESHOLD');
  assert.deepEqual(m.matches.map((x) => x.ruleId), b.matches.map((x) => x.ruleId));
  assert.ok(m.explanation.some((l) => /Mode monitor: the request would have been blocked/.test(l)));
});

test('benign request is allowed in both modes', () => {
  for (const config of [engine.DEFAULT_CONFIG, monitor()]) {
    const d = engine.inspect(getWith('q', 'blue shoes'), ctx({ config }));
    assert.equal(d.action, 'allowed');
    assert.equal(d.wouldBlock, false);
    assert.equal(d.statusCode, null);
    assert.equal(d.blockReason, null);
  }
});

test('malformed and oversized requests are rejected before rules (400 / 413) and logged in monitor mode', () => {
  const bad = engine.inspect({ method: 'G ET', url: '/' }, ctx());
  assert.equal(bad.verdict, 'block');
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.blockReason, 'MALFORMED_REQUEST');
  assert.deepEqual(bad.matches, []);
  assert.equal(bad.anomalies[0].code, 'INVALID_METHOD');
  const big = engine.inspect({ method: 'POST', url: '/', body: '<script>', bodyBytes: 5_000_000, headers: UA }, ctx());
  assert.equal(big.statusCode, 413);
  assert.equal(big.blockReason, 'BODY_TOO_LARGE');
  assert.deepEqual(big.matches, [], 'rules never run on rejected input');
  assert.equal(big.request.bodyBytes, 5_000_000);
  const mon = engine.inspect({ method: 'POST', url: '/', body: 'x', bodyBytes: 5_000_000, headers: UA }, ctx({ config: monitor() }));
  assert.equal(mon.action, 'logged');
  assert.equal(mon.wouldBlock, true);
  assert.equal(mon.statusCode, null);
});

test('decision has every field of the contract schema (§3.6)', () => {
  const d = engine.inspect(getWith('q', "' OR 1=1"), ctx());
  for (const k of ['verdict', 'action', 'wouldBlock', 'statusCode', 'blockReason', 'mode', 'score', 'matches', 'suppressed', 'anomalies',
    'rateLimit', 'request', 'explanation', 'recommendation', 'engine', 'timings']) assert.ok(k in d, k);
  const m = d.matches[0];
  for (const k of ['ruleId', 'ruleName', 'ruleVersion', 'severity', 'points', 'category', 'tags', 'location', 'operator', 'excerpt', 'decodedVia', 'suppressedBy']) {
    assert.ok(k in m, k);
  }
  for (const k of ['method', 'path', 'queryNames', 'bodyNames', 'contentType', 'bodyBytes', 'inspectedBytes', 'truncated', 'userAgent']) assert.ok(k in d.request, k);
  assert.deepEqual(Object.keys(d.engine), ['engineVersion', 'rulesetVersion', 'configVersion']);
  assert.equal(d.engine.configVersion, 1);
  assert.match(d.engine.rulesetVersion, /^[0-9a-f]{16}$/);
  for (const k of ['parseMs', 'rulesMs', 'totalMs']) assert.equal(typeof d.timings[k], 'number');
  assert.doesNotThrow(() => JSON.stringify(d));
});

test('explanations are specific: rule id, name, location, decoding and points', () => {
  const d = engine.inspect({ method: 'GET', url: '/search?q=%27%20OR%201%3D1', headers: UA }, ctx());
  assert.equal(d.explanation[0], "Rule 942100 'SQLi boolean tautology' matched query.q after URL decoding (+5)");
  assert.ok(d.explanation.includes('Total score 5 >= block threshold 5 -> score verdict block'));
  assert.ok(d.explanation.some((l) => l === 'Mode block: request blocked with HTTP 403 (SCORE_THRESHOLD)'));
  assert.match(d.recommendation, /^Block: input contains SQL injection indicators/);
  assert.match(engine.inspect(getWith('q', 'hello'), ctx()).recommendation, /^Allow: no rule matched/);
});
