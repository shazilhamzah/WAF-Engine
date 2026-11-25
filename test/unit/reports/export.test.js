'use strict';
// Unit tests for src/reports/export.js (owner Wahaj): escaping, CSV injection, redaction, formats.
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildReport, sanitizeEvent, safeExcerpt, redactPath, escapeHtml, csvCell, summarize, CONTENT_TYPES,
} = require('../../../src/reports/export');

const XSS = '<script>alert(1)</script>';
const IMG = '<img src=x onerror=alert(1)>';

function makeEvent(overrides = {}) {
  const base = {
    id: 'evt_1', ts: '2026-10-19T10:00:00.000Z', source: 'console', label: 'normal search', method: 'GET',
    path: '/search', verdict: 'block', action: 'blocked', score: 8, mode: 'block', latencyMs: 0.6,
    matchedRuleIds: [941100], rulesetVersion: 'sha256-abc', configVersion: 3, clientId: 'c_0123456789abcdef',
    submittedBy: 'alice', replayOf: null,
    sample: { method: 'GET', path: '/search', headers: { authorization: 'Bearer TOPSECRET-SAMPLE', cookie: 'waf_sid=SESSIONTOKEN' }, body: 'password=hunter2' },
    decision: {
      verdict: 'block', action: 'blocked', wouldBlock: true, statusCode: 403, blockReason: 'SCORE_THRESHOLD', mode: 'block',
      score: { total: 8, flagThreshold: 3, blockThreshold: 5, byCategory: { xss: 5, sqli: 3 }, contributions: [] },
      matches: [{
        ruleId: 941100, ruleName: 'XSS script tag', ruleVersion: 2, severity: 'critical', points: 5, category: 'xss',
        tags: ['xss'], location: 'body.text', operator: 'matches', excerpt: XSS, decodedVia: ['url'], suppressedBy: null,
      }],
      suppressed: [],
      anomalies: [{ code: 'DOUBLE_ENCODING', message: 'Value was URL-encoded twice', points: 2 }],
      rateLimit: { checked: false },
      request: { method: 'GET', path: '/search', queryNames: ['q'], bodyNames: [], userAgent: 'curl/8' },
      explanation: [`Rule 941100 'XSS script tag' matched body.text (+5): ${XSS}`],
      recommendation: 'Block: input contains a script tag.',
      engine: { engineVersion: '1.0.0', rulesetVersion: 'sha256-abc', configVersion: 3 },
      timings: { parseMs: 0.1, rulesMs: 0.4, totalMs: 0.6 },
    },
  };
  return { ...base, ...overrides };
}

const ctx = (events, extra = {}) => ({
  events,
  config: { mode: 'block', thresholds: { flag: 3, block: 5 }, limits: { maxBodyBytes: 1048576 }, rateLimit: { enabled: true, windowMs: 60000, maxRequests: 300 }, secretKey: 'NOPE' },
  rulesetVersion: 'sha256-abc',
  configVersion: 3,
  generatedBy: { username: 'alice', role: 'operator' },
  generatedAt: '2026-10-19T10:30:00.000Z',
  filters: { verdict: 'block' },
  ...extra,
});

test('supports json, csv and html with correct content types and filenames', () => {
  for (const fmt of ['json', 'csv', 'html']) {
    const r = buildReport(ctx([makeEvent()]), fmt);
    assert.equal(r.contentType, CONTENT_TYPES[fmt]);
    assert.equal(r.filename, `waf-studio-report-20261019T103000Z.${fmt}`);
    assert.match(r.filename, /^waf-studio-report-\d{8}T\d{6}Z\.(json|csv|html)$/);
    assert.equal(r.count, 1);
    assert.ok(r.body.length > 100);
  }
});

test('rejects unsupported formats', () => {
  assert.throws(() => buildReport(ctx([]), 'pdf'), TypeError);
  assert.throws(() => buildReport(ctx([]), '../etc'), TypeError);
});

test('HTML report escapes attack payloads everywhere and contains no script', () => {
  const evt = makeEvent({ label: IMG, path: `/a?q=${XSS}` });
  evt.decision.matches[0].ruleName = `Rule ${IMG}`;
  evt.decision.recommendation = `"><svg onload=alert(1)>`;
  const { body } = buildReport(ctx([evt], { generatedBy: { username: '<b>mallory</b>', role: 'operator' }, filters: { q: XSS } }), 'html');
  assert.ok(!/<script/i.test(body), 'no script element');
  assert.ok(!body.includes('<img'), 'no img element from payload');
  assert.ok(!body.includes('<svg'), 'no svg element from payload');
  assert.ok(!body.includes('<b>mallory'), 'generator name escaped');
  assert.ok(body.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'payload shown as escaped text');
  assert.ok(body.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(!/\son\w+=/i.test(body.replace(/&lt;[^&]*&gt;/g, '')), 'no live event-handler attributes');
  assert.match(body, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">/);
  assert.ok(body.startsWith('<!doctype html>'));
});

test('escapeHtml covers the dangerous characters', () => {
  assert.equal(escapeHtml(`<a href="x" onclick='y'>&\``), '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;');
  assert.equal(escapeHtml(null), '');
});

test('CSV cells are formula-injection safe and RFC 4180 quoted', () => {
  assert.equal(csvCell('=1+1'), `"'=1+1"`);
  assert.equal(csvCell('+SUM(A1)'), `"'+SUM(A1)"`);
  assert.equal(csvCell('-2+3'), `"'-2+3"`);
  assert.equal(csvCell('@cmd'), `"'@cmd"`);
  assert.equal(csvCell('\tx'), `"'\tx"`);
  assert.equal(csvCell('\rx'), `"'\rx"`);
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('a,b\nc'), '"a,b\nc"');
  assert.equal(csvCell(5), '"5"');
  assert.equal(csvCell(null), '""');
});

test('CSV report neutralizes formulas coming from event data', () => {
  const evt = makeEvent({ label: '=HYPERLINK("http://evil.example","click")' });
  evt.decision.recommendation = '+cmd|calc';
  evt.decision.matches[0].ruleName = '@SUM(1)';
  const { body } = buildReport(ctx([evt]), 'csv');
  const lines = body.replace(/^﻿/, '').split('\r\n').filter(Boolean);
  assert.equal(lines.length, 2, 'header + one row');
  assert.ok(lines[0].startsWith('"id","timestamp"'));
  assert.ok(lines[1].includes(`"'=HYPERLINK(""http://evil.example"",""click"")"`));
  assert.ok(lines[1].includes(`"'+cmd|calc"`));
  // No cell (after the opening quote) starts with a formula trigger.
  const cells = lines[1].match(/"(?:[^"]|"")*"/g);
  for (const c of cells) assert.ok(!/^"[=+\-@\t\r]/.test(c), `unsafe cell ${c}`);
});

test('reports never contain stored samples, secret headers, client ids or config secrets', () => {
  for (const fmt of ['json', 'csv', 'html']) {
    const { body } = buildReport(ctx([makeEvent()]), fmt);
    assert.ok(!body.includes('TOPSECRET-SAMPLE'), `${fmt}: sample header leaked`);
    assert.ok(!body.includes('SESSIONTOKEN'), `${fmt}: cookie leaked`);
    assert.ok(!body.includes('hunter2'), `${fmt}: password leaked`);
    assert.ok(!body.includes('c_0123456789abcdef'), `${fmt}: client pseudonym included`);
    assert.ok(!body.includes('NOPE'), `${fmt}: unknown config field included`);
  }
});

test('excerpts are redacted, control-char escaped and capped at 120 chars', () => {
  assert.equal(safeExcerpt('Bearer abcdef123456', 'header.authorization'), '[REDACTED]');
  assert.equal(safeExcerpt('whatever', 'cookie.waf_sid'), '[REDACTED]');
  assert.equal(safeExcerpt('hunter2', 'body.password'), '[REDACTED]');
  assert.equal(safeExcerpt('x=1&password=hunter2', 'body'), 'x=1&password=[REDACTED]');
  assert.equal(safeExcerpt('auth: Bearer abcdefghijkl', 'body'), 'auth: Bearer [REDACTED]');
  assert.equal(safeExcerpt('a\nb\u0000c', 'query.q'), 'a\\nb\\u0000c');
  const long = safeExcerpt('x'.repeat(500), 'query.q');
  assert.ok(long.length <= 120);
  assert.equal(safeExcerpt("' OR 1=1--", 'query.q'), "' OR 1=1--");
});

test('secret query parameters in paths are masked', () => {
  assert.equal(redactPath('/login?user=a&password=x&token=y'), '/login?user=a&password=[REDACTED]&token=[REDACTED]');
  assert.equal(redactPath('/search?q=shoes'), '/search?q=shoes');
  assert.equal(redactPath('/plain'), '/plain');
});

test('sanitizeEvent whitelists fields and keeps suppressed matches as evidence', () => {
  const evt = makeEvent();
  evt.decision.suppressed = [{ ruleId: 942100, ruleName: 'SQLi', location: 'query.q', excerpt: "' or 1=1", suppressedBy: 'exc_1' }];
  const s = sanitizeEvent(evt);
  assert.equal(s.sample, undefined);
  assert.equal(s.clientId, undefined);
  assert.deepEqual(s.matchedRuleIds, [941100]);
  assert.equal(s.suppressed.length, 1);
  assert.equal(s.suppressed[0].suppressedBy, 'exc_1');
  assert.equal(s.flagThreshold, 3);
  assert.equal(s.blockThreshold, 5);
  assert.equal(s.wouldBlock, true);
});

test('JSON report carries metadata, summary metrics and per-event explanation', () => {
  const allow = makeEvent({ id: 'evt_2', verdict: 'allow', action: 'allowed', score: 0, source: 'proxy' });
  allow.decision = { ...allow.decision, verdict: 'allow', action: 'allowed', wouldBlock: false, statusCode: null, matches: [], explanation: [], score: { total: 0, flagThreshold: 3, blockThreshold: 5, byCategory: {} } };
  const monitor = makeEvent({ id: 'evt_3', action: 'logged', mode: 'monitor' });
  monitor.decision = { ...monitor.decision, action: 'logged', mode: 'monitor' };
  const r = buildReport(ctx([makeEvent(), allow, monitor]), 'json');
  const data = JSON.parse(r.body);
  assert.equal(data.report.generatedBy, 'alice (operator)');
  assert.equal(data.report.generatedAt, '2026-10-19T10:30:00.000Z');
  assert.equal(data.report.rulesetVersion, 'sha256-abc');
  assert.equal(data.report.configVersion, 3);
  assert.deepEqual(data.report.filters, { verdict: 'block' });
  assert.deepEqual(data.report.config.thresholds, { flag: 3, block: 5 });
  assert.equal(data.summary.totalEvents, 3);
  assert.deepEqual(data.summary.byVerdict, { allow: 1, flag: 0, block: 2 });
  assert.deepEqual(data.summary.byAction, { allowed: 1, logged: 1, blocked: 1 });
  assert.equal(data.summary.falsePositiveReview.wouldBlockButLogged, 1);
  assert.equal(data.summary.falsePositiveReview.allowedWithoutMatches, 1);
  assert.equal(data.summary.topRules[0].ruleId, 941100);
  assert.equal(data.summary.topRules[0].count, 2);
  assert.equal(data.events[0].explanation.length, 1);
  assert.equal(data.events[0].recommendation, 'Block: input contains a script tag.');
});

test('summarize handles an empty list', () => {
  const s = summarize([]);
  assert.equal(s.totalEvents, 0);
  assert.equal(s.latency.p50Ms, null);
  const r = buildReport(ctx([]), 'html');
  assert.ok(r.body.includes('No events matched the filters.'));
});

test('hostile decision shapes do not crash the builder', () => {
  const weird = [null, {}, { decision: 'not-an-object' }, { decision: { matches: [null, 5], explanation: 'x', score: null } }];
  for (const fmt of ['json', 'csv', 'html']) {
    assert.doesNotThrow(() => buildReport({ events: weird }, fmt));
  }
});
