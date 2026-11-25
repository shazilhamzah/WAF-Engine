'use strict';
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../../../src/db');
const { createSessionManager } = require('../../../src/auth/sessions');
const { createAuthMiddleware } = require('../../../src/auth/middleware');
const { createAuditor } = require('../../../src/services/audit');

function fakeReq({ method = 'GET', url = '/api/x', cookie, csrf } = {}) {
  return {
    method, originalUrl: url, url, path: url, headers: { cookie }, secure: false, clientId: 'c_test', requestId: 'req_x',
    get(h) { return h.toLowerCase() === 'x-csrf-token' ? csrf : undefined; },
  };
}
function fakeRes() { return { headers: [], append(k, v) { this.headers.push([k, v]); } }; }
function run(mw, req, res = fakeRes()) { let out; mw(req, res, (e) => { out = e || null; }); return out; }

describe('auth middleware', () => {
  let db; let sessions; let auth; let op; let token; let csrf;
  beforeEach(() => {
    db = openDatabase(':memory:');
    sessions = createSessionManager({ db });
    auth = createAuthMiddleware({ sessions, audit: createAuditor({ db }) });
    op = db.users.create({ username: 'operator', passwordHash: 'h', role: 'operator' });
    ({ token, csrfToken: csrf } = sessions.create(op.id));
  });
  afterEach(() => db.close());

  it('loadSession attaches the user for a valid cookie and clears a stale one', () => {
    const req = fakeReq({ cookie: `waf_sid=${token}` });
    run(auth.loadSession, req);
    assert.equal(req.auth.user.username, 'operator');
    const stale = fakeReq({ cookie: 'waf_sid=' + 'A'.repeat(43) });
    const res = fakeRes();
    run(auth.loadSession, stale, res);
    assert.equal(stale.auth, null);
    assert.equal(stale.sessionStatus, 'expired');
    assert.match(res.headers[0][1], /Max-Age=0/);
  });

  it('requireAuth: AUTH_REQUIRED without cookie, SESSION_EXPIRED with a stale cookie', () => {
    const a = fakeReq();
    run(auth.loadSession, a);
    assert.equal(run(auth.requireAuth, a).code, 'AUTH_REQUIRED');
    const b = fakeReq({ cookie: 'waf_sid=' + 'B'.repeat(43) });
    run(auth.loadSession, b);
    assert.equal(run(auth.requireAuth, b).code, 'SESSION_EXPIRED');
  });

  it('requireRole: generic FORBIDDEN and an auth.denied audit entry', () => {
    const req = fakeReq({ cookie: `waf_sid=${token}`, url: '/api/audit' });
    run(auth.loadSession, req);
    const err = run(auth.requireRole('admin'), req);
    assert.equal(err.code, 'FORBIDDEN');
    assert.equal(err.status, 403);
    const entry = db.audit.list({ action: 'auth.denied' }).items[0];
    assert.equal(entry.actorName, 'operator');
    assert.equal(entry.outcome, 'denied');
    assert.equal(run(auth.requireRole('admin', 'operator'), req), null);
  });

  it('requireCsrf: state-changing methods need the session token; GET and login are exempt', () => {
    const post = (csrfHeader, url = '/api/analyze') => {
      const req = fakeReq({ method: 'POST', url, cookie: `waf_sid=${token}`, csrf: csrfHeader });
      run(auth.loadSession, req);
      return run(auth.requireCsrf, req);
    };
    assert.equal(post(undefined).code, 'CSRF_INVALID');
    assert.equal(post('wrong').code, 'CSRF_INVALID');
    assert.equal(post(csrf), null);
    assert.equal(post(undefined, '/api/auth/login'), null);
    const get = fakeReq({ cookie: `waf_sid=${token}` });
    run(auth.loadSession, get);
    assert.equal(run(auth.requireCsrf, get), null);
    for (const m of ['PUT', 'PATCH', 'DELETE']) {
      const req = fakeReq({ method: m, cookie: `waf_sid=${token}` });
      run(auth.loadSession, req);
      assert.equal(run(auth.requireCsrf, req).code, 'CSRF_INVALID', m);
    }
    assert.ok(db.audit.list({ action: 'auth.denied' }).total >= 2, 'CSRF failures audited');
  });
});
