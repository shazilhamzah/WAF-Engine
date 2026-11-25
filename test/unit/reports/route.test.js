'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createReportsRouter, validateQuery } = require('../../../src/api/routes/reports');

function sampleEvent(i, extra = {}) {
  return {
    id: `evt_${i}`, ts: new Date(Date.UTC(2026, 9, 19, 10, 0, i)).toISOString(), source: 'console', label: null,
    method: 'GET', path: '/search', verdict: 'block', action: 'blocked', score: 5, mode: 'block',
    sample: { headers: { authorization: 'Bearer SHOULD-NOT-LEAK' } },
    decision: { verdict: 'block', action: 'blocked', score: { total: 5, flagThreshold: 3, blockThreshold: 5 }, matches: [], explanation: ['x'] },
    ...extra,
  };
}

async function startApp({ user, options = {} }) {
  const audits = [];
  const audit = (req, action, opts) => audits.push({ action, ...opts, actor: req.auth && req.auth.user && req.auth.user.username });
  const app = express();
  app.use((req, res, next) => { req.auth = user ? { user } : null; next(); });
  app.use('/api/reports', createReportsRouter({
    engineState: {
      getConfig: () => ({ mode: 'block', thresholds: { flag: 3, block: 5 } }),
      getRulesetVersion: () => 'sha256-test',
      getConfigVersion: () => 4,
    },
    audit,
    now: () => Date.UTC(2026, 9, 19, 12, 0, 0),
    ...options,
  }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ error: { code: err.code || 'INTERNAL_ERROR', message: 'x', details: err.details } });
  });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}/api/reports`;
  return { base, audits, close: () => new Promise((r) => server.close(r)) };
}

const operator = { id: 'usr_op', username: 'olivia', role: 'operator' };

test('operator downloads an HTML report with attachment headers and an audit event', async (t) => {
  let seen = null;
  const app = await startApp({ user: operator, options: { listEventsForReport: (f) => { seen = f; return [sampleEvent(1), sampleEvent(2)]; } } });
  t.after(app.close);
  const res = await fetch(`${app.base}/export?format=html&verdict=block&from=2026-10-01&to=2026-10-20T00:00:00Z`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(res.headers.get('content-disposition'), 'attachment; filename="waf-studio-report-20261019T120000Z.html"');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.text();
  assert.ok(!body.includes('SHOULD-NOT-LEAK'));
  assert.ok(body.includes('olivia (operator)'));
  assert.deepEqual(seen, { verdict: 'block', from: '2026-10-01T00:00:00.000Z', to: '2026-10-20T00:00:00.000Z', max: 1000 });
  const a = app.audits.find((x) => x.action === 'report.export');
  assert.ok(a, 'report.export audited');
  assert.equal(a.details.format, 'html');
  assert.equal(a.details.count, 2);
  assert.equal(a.details.filters.verdict, 'block');
  assert.ok(!JSON.stringify(a).includes('evt_1'), 'audit details contain no report content');
});

test('csv and json formats are served with their content types', async (t) => {
  const app = await startApp({ user: { id: 'usr_a', username: 'root', role: 'admin' }, options: { listEventsForReport: () => [sampleEvent(1)] } });
  t.after(app.close);
  const csv = await fetch(`${app.base}/export?format=csv&ids=evt_1`);
  assert.equal(csv.status, 200);
  assert.equal(csv.headers.get('content-type'), 'text/csv; charset=utf-8');
  assert.match(csv.headers.get('content-disposition'), /\.csv"$/);
  const json = await fetch(`${app.base}/export?format=json`);
  assert.equal(json.status, 200);
  const data = await json.json();
  assert.equal(data.report.rulesetVersion, 'sha256-test');
  assert.equal(data.report.configVersion, 4);
});

test('viewer gets a generic 403 and an auth.denied audit event', async (t) => {
  let called = false;
  const app = await startApp({ user: { id: 'usr_v', username: 'vic', role: 'viewer' }, options: { listEventsForReport: () => { called = true; return []; } } });
  t.after(app.close);
  const res = await fetch(`${app.base}/export?format=html`);
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error.code, 'FORBIDDEN');
  assert.equal(called, false, 'no records read for a denied request');
  assert.ok(app.audits.some((x) => x.action === 'auth.denied' && x.outcome === 'denied'));
});

test('missing session → 401', async (t) => {
  const app = await startApp({ user: null, options: { listEventsForReport: () => [] } });
  t.after(app.close);
  const res = await fetch(`${app.base}/export`);
  assert.equal(res.status, 401);
});

test('invalid queries are rejected with VALIDATION_FAILED', async (t) => {
  const app = await startApp({ user: operator, options: { listEventsForReport: () => [] } });
  t.after(app.close);
  const bad = [
    'format=pdf', 'format=html&verdict=evil', 'from=yesterday', 'to=2026-13-45', 'ids=evt_1,<script>',
    'format=html&format=csv', 'unknown=1', 'from=2026-10-20&to=2026-10-01',
    `ids=${Array.from({ length: 501 }, (_, i) => `evt_${i}`).join(',')}`,
  ];
  for (const qs of bad) {
    const res = await fetch(`${app.base}/export?${qs}`);
    assert.equal(res.status, 400, qs);
    const body = await res.json();
    assert.equal(body.error.code, 'VALIDATION_FAILED', qs);
  }
  assert.ok(app.audits.some((x) => x.action === 'request.rejected'));
});

test('validateQuery defaults to html and normalizes ids', () => {
  assert.deepEqual(validateQuery({}).value, { format: 'html' });
  assert.deepEqual(validateQuery({ ids: 'evt_1, evt_2,evt_1' }).value.ids, ['evt_1', 'evt_2']);
  assert.equal(validateQuery({ format: 'CSV' }).value.format, 'csv');
});

test('repository path pages through events and chunks id lists', async (t) => {
  const calls = [];
  const all = Array.from({ length: 450 }, (_, i) => sampleEvent(i));
  const db = {
    events: {
      list(f) {
        calls.push(f);
        assert.equal(f.full, true);
        assert.ok(f.limit <= 200);
        let items = all;
        if (f.ids) items = all.filter((e) => f.ids.includes(e.id));
        return { items: items.slice(f.offset, f.offset + f.limit), total: items.length };
      },
    },
  };
  const app = await startApp({ user: operator, options: { db } });
  t.after(app.close);
  const res = await fetch(`${app.base}/export?format=json`);
  const data = await res.json();
  assert.equal(data.events.length, 450);
  assert.equal(calls.length, 3);

  calls.length = 0;
  const ids = Array.from({ length: 450 }, (_, i) => `evt_${i}`).join(',');
  const res2 = await fetch(`${app.base}/export?format=json&ids=${ids}`);
  const data2 = await res2.json();
  assert.equal(data2.events.length, 450);
  assert.equal(calls.length, 3, 'ids chunked into batches of ≤ 200');
  assert.ok(calls.every((c) => c.ids.length <= 200));
});
