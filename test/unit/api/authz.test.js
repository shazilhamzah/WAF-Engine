'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startHarness } = require('./harness');

const ALL = ['admin', 'operator', 'viewer'];
const AO = ['admin', 'operator'];
const A = ['admin'];

describe('api: authorization matrix (role × endpoint)', () => {
  let h; const c = {}; const ids = {};

  before(async () => {
    h = await startHarness();
    for (const r of ALL) c[r] = await h.as(r);
    c.anonymous = h.client();
    const ev = await c.operator.post('/api/analyze', { label: 'MATRIX-LABEL', sample: { method: 'GET', path: '/search?q=x%20or%201=1', headers: { 'x-marker': 'MATRIX-SECRET' }, body: null } });
    ids.event = ev.body.event.id;
    ids.event2 = (await c.operator.post('/api/analyze', { sample: { method: 'GET', path: '/ok' } })).body.event.id;
    ids.exception = (await c.operator.post('/api/exceptions', { ruleId: 942100, scope: { pathPrefix: '/search' }, reason: 'matrix' })).body.exception.id;
    ids.viewer = (await c.admin.get('/api/users')).body.items.find((u) => u.username === 'viewer').id;
  });
  after(async () => { await h.close(); });

  const endpoints = [
    ['GET', () => '/api/auth/me', ALL],
    ['POST', () => '/api/auth/password', ALL, () => ({ currentPassword: 'x', newPassword: 'short' })],
    ['GET', () => '/api/stats', ALL],
    ['GET', () => '/api/events', ALL],
    ['GET', () => `/api/events/${ids.event}`, AO],
    ['GET', () => `/api/events/compare?a=${ids.event}&b=${ids.event2}`, AO],
    ['POST', () => '/api/analyze', AO, () => ({ sample: { method: 'GET', path: '/x' } })],
    ['POST', () => '/api/import', AO, () => ({ filename: 'a.json', samples: [{ method: 'GET', path: '/y' }] })],
    ['POST', () => `/api/events/${ids.event}/replay`, AO],
    ['GET', () => '/api/rules', AO],
    ['GET', () => '/api/rules/942100/history', AO],
    ['POST', () => '/api/rules/validate', AO, () => ({ source: 'rule 1 "x" {' })],
    ['POST', () => '/api/rules', A, () => ({ source: '' })],
    ['PUT', () => '/api/rules/942100', A, () => ({ enabled: true })],
    ['DELETE', () => '/api/rules/942100', A, () => ({})],
    ['GET', () => '/api/config', AO],
    ['PUT', () => '/api/config', A, () => ({ config: { mode: 'nope' }, reason: 'm' })],
    ['GET', () => '/api/config/history', AO],
    ['GET', () => '/api/exceptions', AO],
    ['POST', () => '/api/exceptions/preview', AO, () => ({ ruleId: 942100, scope: { pathPrefix: '/' } })],
    ['POST', () => '/api/exceptions', AO, () => ({ ruleId: 942100, scope: {}, reason: 'x' })],
    ['POST', () => `/api/exceptions/${ids.exception}/approve`, A, () => ({})],
    ['POST', () => `/api/exceptions/${ids.exception}/reject`, A, () => ({ note: 1 })],
    ['POST', () => `/api/exceptions/${ids.exception}/revoke`, A, () => ({})],
    ['GET', () => '/api/audit', A],
    ['GET', () => '/api/audit/verify', A],
    ['GET', () => '/api/reports/export?format=json', AO],
    ['GET', () => '/api/users', A],
    ['POST', () => '/api/users', A, () => ({ username: '', password: 'x', role: 'root' })],
    ['PUT', () => `/api/users/${ids.viewer}`, A, () => ({ disabled: false })],
  ];

  for (const [method, pathFn, allowed, bodyFn] of endpoints) {
    for (const role of ['anonymous', ...ALL]) {
      it(`${role} ${method} ${pathFn.toString().replace(/^\(\) => /, '')}`, async () => {
        const body = bodyFn ? bodyFn() : (method === 'GET' ? undefined : undefined);
        const r = await c[role].request(method, pathFn(), { body });
        if (role === 'anonymous') {
          assert.equal(r.status, 401, r.text);
          assert.equal(r.body.error.code, 'AUTH_REQUIRED');
        } else if (allowed.includes(role)) {
          assert.ok(![401, 403].includes(r.status), `${role} allowed but got ${r.status} ${r.text.slice(0, 200)}`);
          assert.ok(r.status < 500, `no server error: ${r.status} ${r.text.slice(0, 200)}`);
        } else {
          assert.equal(r.status, 403, r.text);
          assert.deepEqual(Object.keys(r.body.error).sort(), ['code', 'message', 'requestId']);
          assert.equal(r.body.error.code, 'FORBIDDEN');
          assert.doesNotMatch(r.text, /MATRIX|decision|evt_/);
        }
      });
    }
  }

  it('state was not changed by the matrix (rule 942100 still enabled, exception still pending)', async () => {
    const rules = await c.admin.get('/api/rules');
    assert.equal(rules.body.items.find((r) => r.id === 942100).enabled, true);
    const ex = await c.admin.get('/api/exceptions?status=pending');
    assert.ok(ex.body.items.some((x) => x.id === ids.exception));
  });

  it('viewers only ever receive EventSummary objects', async () => {
    const r = await c.viewer.get('/api/events?limit=200');
    assert.equal(r.status, 200);
    assert.ok(r.body.items.length >= 2);
    for (const e of r.body.items) {
      assert.deepEqual(Object.keys(e).sort(), ['action', 'id', 'label', 'latencyMs', 'matchedRuleIds', 'method', 'mode', 'path', 'score', 'source', 'ts', 'verdict']);
    }
    assert.doesNotMatch(r.text, /MATRIX-SECRET/);
  });

  it('each denial is audited as auth.denied with the actor and no record content', async () => {
    const denied = (await c.admin.get('/api/audit?action=auth.denied&limit=200')).body.items;
    assert.ok(denied.some((d) => d.actorName === 'viewer' && d.outcome === 'denied'));
    assert.ok(denied.some((d) => d.actorName === 'operator'));
    assert.doesNotMatch(JSON.stringify(denied), /MATRIX-SECRET/);
  });
});
