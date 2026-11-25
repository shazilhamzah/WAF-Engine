'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');
const { analyze, audit } = require('../helpers/api');

const ALL = ['admin', 'operator', 'viewer'];
const AO = ['admin', 'operator'];
const A = ['admin'];

describe('authorization matrix', { skip: skipUnlessStack() }, () => {
  let stack;
  const clients = {};
  const ids = {};

  before(async () => {
    stack = await startStack();
    for (const r of ALL) clients[r] = await stack.login(r);
    clients.anonymous = stack.client();
    const ev = await analyze(clients.operator, { path: '/search?q=%27%20OR%201%3D1--', headers: { 'x-secret-marker': 'MATRIX-RECORD-MARKER' } }, 'matrix-record-label');
    ids.event = ev.id;
    ids.event2 = (await analyze(clients.operator, { path: '/search?q=hello' }, 'matrix benign')).id;
    const rules = await clients.admin.get('/api/rules');
    ids.rule = (rules.body && rules.body.items && rules.body.items[0] && rules.body.items[0].id) || 942100;
    const ex = await clients.operator.post('/api/exceptions', { ruleId: Number((ev.decision.matches[0] && ev.decision.matches[0].ruleId) || ids.rule), scope: { pathPrefix: '/matrix', location: null, method: null }, reason: 'matrix' });
    ids.exception = ex.body && ex.body.exception && ex.body.exception.id;
    const users = await clients.admin.get('/api/users');
    ids.viewerUser = users.body.items.find((u) => u.username === 'viewer').id;
  });
  after(async () => { if (stack) await stack.stop(); });

  // each row is method then path then allowed roles then body
  const endpoints = [
    ['GET', () => '/api/auth/me', ALL],
    ['GET', () => '/api/stats', ALL],
    ['GET', () => '/api/events', ALL],
    ['GET', () => `/api/events/${ids.event}`, AO],
    ['GET', () => `/api/events/compare?a=${ids.event}&b=${ids.event2}`, AO],
    ['POST', () => '/api/analyze', AO, () => ({ label: 'matrix', sample: { method: 'GET', path: '/x', headers: {}, body: null } })],
    ['POST', () => '/api/import', AO, () => ({ filename: 'm.json', samples: [{ method: 'GET', path: '/y', headers: {}, body: null }] })],
    ['POST', () => `/api/events/${ids.event}/replay`, AO],
    ['GET', () => '/api/rules', AO],
    ['GET', () => `/api/rules/${ids.rule}/history`, AO],
    ['POST', () => '/api/rules/validate', AO, () => ({ source: 'rule 1 "x" {' })],
    ['POST', () => '/api/rules', A, () => ({ source: '', enabled: true })],
    ['PUT', () => `/api/rules/${ids.rule}`, A, () => ({ enabled: true })],
    ['DELETE', () => `/api/rules/${ids.rule}`, A, () => ({})],
    ['GET', () => '/api/config', AO],
    ['PUT', () => '/api/config', A, () => ({ config: {}, reason: 'matrix' })],
    ['GET', () => '/api/config/history', AO],
    ['GET', () => '/api/exceptions', AO],
    ['POST', () => '/api/exceptions/preview', AO, () => ({ ruleId: ids.rule, scope: { pathPrefix: '/', location: null, method: null } })],
    ['POST', () => '/api/exceptions', AO, () => ({ ruleId: ids.rule, scope: { pathPrefix: '/m2', location: null, method: null }, reason: 'matrix' })],
    ['POST', () => `/api/exceptions/${ids.exception}/approve`, A, () => ({})],
    ['POST', () => `/api/exceptions/${ids.exception}/reject`, A, () => ({ note: 1234 })],
    ['POST', () => `/api/exceptions/${ids.exception}/revoke`, A, () => ({})],
    ['GET', () => '/api/audit', A],
    ['GET', () => '/api/audit/verify', A],
    ['GET', () => '/api/reports/export?format=json', AO],
    ['GET', () => '/api/users', A],
    ['POST', () => '/api/users', A, () => ({ username: '', password: 'short', role: 'nope' })],
    ['PUT', () => `/api/users/${ids.viewerUser}`, A, () => ({ disabled: false })],
    ['POST', () => '/api/auth/password', ALL, (role) => ({ currentPassword: stack.passwords[role] || 'x', newPassword: 'short' })]
  ];

  for (const [method, pathFn, allowed, bodyFn] of endpoints) {
    for (const role of ['anonymous', ...ALL]) {
      const name = `${role.padEnd(9)} ${method} ${pathFn.toString().replace(/^\(\) => /, '').replace(/[`'$]/g, '')}`;
      it(name, async () => {
        const c = clients[role];
        const path = pathFn();
        const body = bodyFn ? bodyFn(role) : (method === 'GET' ? undefined : {});
        const r = await c.request(method, path, { body });
        if (role === 'anonymous') {
          assert.equal(r.status, 401, `${method} ${path} anonymous → ${r.status}`);
          assert.ok(['AUTH_REQUIRED', 'SESSION_EXPIRED', 'AUTH_INVALID'].includes(r.body?.error?.code));
        } else if (allowed.includes(role)) {
          assert.ok(![401, 403].includes(r.status), `${role} should be allowed: ${method} ${path} → ${r.status} ${r.text.slice(0, 160)}`);
        } else {
          assert.equal(r.status, 403, `${role} must be denied: ${method} ${path} → ${r.status}`);
          assert.equal(r.body.error.code, 'FORBIDDEN');
          assert.doesNotMatch(r.text, /MATRIX-RECORD-MARKER|matrix-record-label|decision|matches|evt_[0-9a-f]{6}/i, 'denial must not leak record data');
        }
      });
    }
  }

  it('viewer sees only EventSummary objects (no decision/sample/evidence)', async () => {
    const r = await clients.viewer.get('/api/events?limit=100');
    assert.equal(r.status, 200);
    assert.ok(r.body.items.length > 0);
    for (const e of r.body.items) {
      for (const k of ['decision', 'sample', 'clientId', 'submittedBy']) assert.ok(!(k in e), `viewer summary leaks ${k}`);
    }
    assert.doesNotMatch(r.text, /MATRIX-RECORD-MARKER/);
  });

  it('viewer denial is audited as auth.denied without exposing the record', async () => {
    const before = (await audit(clients.admin, { action: 'auth.denied' })).filter((i) => i.action === 'auth.denied').length;
    const r = await clients.viewer.get(`/api/events/${ids.event}`);
    assert.equal(r.status, 403);
    const after = (await audit(clients.admin, { action: 'auth.denied' })).filter((i) => i.action === 'auth.denied');
    assert.ok(after.length > before, 'auth.denied recorded');
    const last = after.find((i) => i.actorName === 'viewer');
    assert.ok(last, 'denied actor recorded');
    assert.equal(last.outcome, 'denied');
    assert.doesNotMatch(JSON.stringify(last), /MATRIX-RECORD-MARKER/);
  });

  it('operator cannot escalate own role via users API', async () => {
    const me = clients.operator.user.id;
    const r = await clients.operator.put(`/api/users/${me}`, { role: 'admin', confirm: true });
    assert.equal(r.status, 403);
    const check = await clients.operator.get('/api/auth/me');
    assert.equal(check.body.user.role, 'operator');
  });

  it('unknown/forged event ids give 404 (not 500) to authorized users', async () => {
    for (const id of ['evt_doesnotexist', "evt_' OR 1=1 --", '../../etc/passwd', '%00']) {
      const r = await clients.admin.get('/api/events/' + encodeURIComponent(id));
      assert.ok([400, 404].includes(r.status), `${id} → ${r.status}`);
    }
  });
});
