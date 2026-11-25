'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startHarness, PASSWORDS } = require('./harness');

const SQLI = { method: 'GET', path: '/search?q=a%27%20or%201=1', headers: {}, body: null };
const BENIGN = { method: 'GET', path: '/search?q=mug', headers: {}, body: null };
const LEAK = /\bat [\w.<>$]+ \(|node:internal|node_modules|[A-Za-z]:\\|SqliteError|TypeError|ReferenceError/;

describe('api: transport, headers and error envelope', () => {
  let h;
  before(async () => { h = await startHarness(); });
  after(async () => { await h.close(); });

  it('sets security headers on API and static responses; no x-powered-by', async () => {
    for (const p of ['/api/health', '/', '/no-such-page']) {
      const r = await h.client().get(p);
      assert.match(r.headers.get('content-security-policy'), /default-src 'self'; script-src 'self'.*object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'/);
      assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
      assert.equal(r.headers.get('x-frame-options'), 'DENY');
      assert.ok(r.headers.get('permissions-policy'));
      assert.match(r.headers.get('x-request-id'), /^req_/);
      assert.equal(r.headers.get('x-powered-by'), null);
    }
    const api = await h.client().get('/api/health');
    assert.equal(api.headers.get('cache-control'), 'no-store');
    assert.deepEqual(Object.keys(api.body).sort(), ['status', 'version']);
  });

  it('unknown API routes → 404 NOT_FOUND JSON; SPA fallback serves index.html for app routes', async () => {
    const r = await h.client().get('/api/nope');
    assert.equal(r.status, 404);
    assert.equal(r.body.error.code, 'NOT_FOUND');
    assert.match(r.body.error.requestId, /^req_/);
    const spa = await h.client().get('/dashboard');
    assert.equal(spa.status, 200);
    assert.match(spa.text, /<!doctype html>/i);
    const missingAsset = await h.client().get('/js/definitely-missing.js');
    assert.equal(missingAsset.status, 404);
  });

  it('non-JSON bodies → 415; malformed JSON → 400 MALFORMED_JSON; > 256 KB → 413', async () => {
    const admin = await h.as('admin');
    const form = await admin.request('POST', '/api/rules/validate', { rawBody: 'source=x', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    assert.equal(form.status, 415);
    assert.equal(form.body.error.code, 'UNSUPPORTED_MEDIA_TYPE');
    const bad = await admin.request('POST', '/api/rules/validate', { rawBody: '{"source": ', headers: { 'content-type': 'application/json' } });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error.code, 'MALFORMED_JSON');
    const big = await admin.post('/api/rules/validate', { source: 'x'.repeat(300 * 1024) });
    assert.equal(big.status, 413);
    assert.equal(big.body.error.code, 'PAYLOAD_TOO_LARGE');
    const rejected = await admin.get('/api/audit?action=request.rejected');
    assert.ok(rejected.body.total >= 3, 'rejected input audited');
  });

  it('validation errors list fields; unknown fields are rejected; prototype keys are inert', async () => {
    const admin = await h.as('admin');
    const r = await admin.post('/api/users', { username: 'x', password: 1, role: 'root', extra: true });
    assert.equal(r.status, 400);
    const fields = r.body.error.details.map((d) => d.field).sort();
    assert.deepEqual(fields, ['extra', 'password', 'role', 'username']);
    const proto = await admin.request('PUT', '/api/config', { rawBody: '{"config":{"__proto__":{"admin":true},"mode":"block"},"confirm":true}', headers: { 'content-type': 'application/json' } });
    assert.ok([200, 400].includes(proto.status));
    assert.equal({}.admin, undefined);
  });

  it('a server error returns INTERNAL_ERROR without stack traces and is logged + audited', async () => {
    const op = await h.as('operator');
    const r = await op.post('/api/analyze', { sample: { ...BENIGN, headers: { 'x-fake-engine-throw': '1' } } });
    assert.equal(r.status, 500);
    assert.equal(r.body.error.code, 'INTERNAL_ERROR');
    assert.doesNotMatch(r.text, LEAK);
    assert.ok(h.logs.some(([lvl]) => lvl === 'error'), 'internal log written');
    const admin = await h.as('admin');
    const audit = await admin.get('/api/audit?action=system.error');
    assert.ok(audit.body.total >= 1);
  });

  it('rejects requests for foreign Host names and cross-origin state changes', async () => {
    const http = require('node:http');
    const status = await new Promise((resolve) => {
      const req = http.request(`${h.base}/api/health`, { headers: { host: 'evil.example:80' } }, (res) => { res.resume(); resolve(res.statusCode); });
      req.end();
    });
    assert.equal(status, 403);
    const admin = await h.as('admin');
    const cross = await admin.post('/api/rules/validate', { source: 'x' }, { headers: { origin: 'http://evil.example' } });
    assert.equal(cross.status, 403);
    assert.equal(cross.body.error.code, 'CSRF_INVALID');
  });
});

describe('api: authentication', () => {
  let h;
  before(async () => { h = await startHarness(); });
  after(async () => { await h.close(); });

  it('login returns user, csrfToken, expiresAt and a hardened cookie; me echoes the token', async () => {
    const c = h.client();
    const r = await c.login('operator', PASSWORDS.operator);
    assert.equal(r.status, 200);
    assert.deepEqual(Object.keys(r.body).sort(), ['csrfToken', 'expiresAt', 'user']);
    assert.deepEqual(Object.keys(r.body.user).sort(), ['id', 'role', 'username']);
    const cookie = r.headers.getSetCookie()[0];
    assert.match(cookie, /^waf_sid=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict$/);
    const me = await c.get('/api/auth/me');
    assert.equal(me.body.csrfToken, r.body.csrfToken);
  });

  it('unknown user, wrong password and disabled user share one generic 401', async () => {
    const admin = await h.as('admin');
    const created = await admin.post('/api/users', { username: 'temp1', password: 'Temp-User-Passw0rd', role: 'viewer' });
    await admin.put(`/api/users/${created.body.user.id}`, { disabled: true, confirm: true });
    const msgs = [];
    for (const [u, p] of [['nobody', 'Wrong-Passw0rd-1'], ['viewer', 'Wrong-Passw0rd-1'], ['temp1', 'Temp-User-Passw0rd']]) {
      const r = await h.client().login(u, p);
      assert.equal(r.status, 401);
      assert.equal(r.body.error.code, 'AUTH_INVALID');
      msgs.push(r.body.error.message);
    }
    assert.equal(new Set(msgs).size, 1);
  });

  it('session rotation: the cookie presented at login is destroyed and replaced', async () => {
    const c = await h.as('viewer');
    const old = c.sid;
    await c.login('viewer', PASSWORDS.viewer);
    assert.notEqual(c.sid, old);
    const replay = h.client(); replay.sid = old;
    assert.equal((await replay.get('/api/auth/me')).status, 401);
  });

  it('logout requires CSRF, returns 204 and kills the session', async () => {
    const c = await h.as('viewer');
    assert.equal((await c.post('/api/auth/logout', undefined, { csrf: null })).status, 403);
    const sid = c.sid;
    assert.equal((await c.post('/api/auth/logout')).status, 204);
    const replay = h.client(); replay.sid = sid;
    const r = await replay.get('/api/auth/me');
    assert.equal(r.status, 401);
    assert.equal(r.body.error.code, 'SESSION_EXPIRED');
  });

  it('idle expiry is enforced server-side (clock advanced 31 minutes)', async () => {
    const c = await h.as('viewer');
    h.advance(31 * 60 * 1000);
    try {
      const r = await c.get('/api/stats');
      assert.equal(r.status, 401);
      assert.equal(r.body.error.code, 'SESSION_EXPIRED');
    } finally { h.advance(-31 * 60 * 1000); }
  });

  it('password change: checks policy and current password, then ends all sessions', async () => {
    const admin = await h.as('admin');
    await admin.post('/api/users', { username: 'pwchange', password: 'Original-Passw0rd', role: 'operator' });
    const a = h.client(); await a.login('pwchange', 'Original-Passw0rd');
    const b = h.client(); await b.login('pwchange', 'Original-Passw0rd');
    assert.equal((await a.post('/api/auth/password', { currentPassword: 'Original-Passw0rd', newPassword: 'short' })).status, 400);
    assert.equal((await a.post('/api/auth/password', { currentPassword: 'Original-Passw0rd', newPassword: 'pwchange' })).status, 400);
    const wrong = await a.post('/api/auth/password', { currentPassword: 'Not-The-Passw0rd', newPassword: 'Brand-New-Passw0rd' });
    assert.equal(wrong.status, 400);
    assert.equal(wrong.body.error.details[0].field, 'currentPassword');
    const ok = await a.post('/api/auth/password', { currentPassword: 'Original-Passw0rd', newPassword: 'Brand-New-Passw0rd' });
    assert.equal(ok.status, 204);
    assert.equal((await b.get('/api/auth/me')).status, 401, 'other sessions revoked');
    assert.equal((await h.client().login('pwchange', 'Original-Passw0rd')).status, 401);
    assert.equal((await h.client().login('pwchange', 'Brand-New-Passw0rd')).status, 200);
    const audit = await admin.get('/api/audit?action=auth.password.change');
    assert.ok(audit.body.items.some((i) => i.outcome === 'success'));
    assert.doesNotMatch(JSON.stringify(audit.body), /Brand-New|Original-Passw0rd/);
  });
});

describe('api: login throttling', () => {
  it('locks a username after 5 failures (429 + Retry-After) and audits auth.lockout', async () => {
    const h = await startHarness();
    try {
      for (let i = 0; i < 5; i += 1) assert.equal((await h.client().login('operator', `Wrong-Passw0rd-${i}`)).status, 401);
      const locked = await h.client().login('operator', PASSWORDS.operator);
      assert.equal(locked.status, 429);
      assert.equal(locked.body.error.code, 'RATE_LIMITED');
      assert.ok(Number(locked.headers.get('retry-after')) > 0);
      assert.ok(locked.body.retryAfterSeconds > 0);
      // unknown usernames lock the same way (no enumeration through lockout behaviour)
      for (let i = 0; i < 5; i += 1) await h.client().login('ghost-user', `Wrong-Passw0rd-${i}`);
      assert.equal((await h.client().login('ghost-user', 'Wrong-Passw0rd-x')).status, 429);
      const admin = await h.as('admin');
      const users = await admin.get('/api/users');
      assert.ok(users.body.items.find((u) => u.username === 'operator').lockedUntil);
      const audit = await admin.get('/api/audit?action=auth&limit=200');
      assert.ok(audit.body.items.some((i) => i.action === 'auth.lockout'));
      assert.doesNotMatch(JSON.stringify(audit.body), /Wrong-Passw0rd/);
      const op = users.body.items.find((u) => u.username === 'operator');
      assert.equal((await admin.put(`/api/users/${op.id}`, { password: 'Reset-Operator-Pw1' })).status, 200);
      assert.equal((await h.client().login('operator', 'Reset-Operator-Pw1')).status, 200);
    } finally { await h.close(); }
  });

  it('limits a client to 20 login attempts per minute', async () => {
    const h = await startHarness();
    try {
      const statuses = [];
      for (let i = 0; i < 22; i += 1) statuses.push((await h.client().login(`spray-${i}`, 'Wrong-Passw0rd-1')).status);
      assert.deepEqual(statuses.slice(0, 20), Array(20).fill(401));
      assert.deepEqual(statuses.slice(20), [429, 429]);
    } finally { await h.close(); }
  });
});

describe('api: analysis workflow', () => {
  let h; let op; let admin; let admin2;
  before(async () => {
    h = await startHarness({ options: { analysisPerMinute: 40 } });
    op = await h.as('operator'); admin = await h.as('admin'); admin2 = await h.as('admin2');
  });
  after(async () => { await h.close(); });

  it('analyze stores a console event with the redacted sample and audits analysis.submit', async () => {
    const r = await op.post('/api/analyze', { label: 'first', sample: { ...SQLI, headers: { authorization: 'Bearer abc', 'user-agent': 'ua' } } });
    assert.equal(r.status, 201);
    const e = r.body.event;
    assert.equal(e.source, 'console');
    assert.equal(e.verdict, 'block');
    assert.deepEqual(e.matchedRuleIds, [942100]);
    assert.equal(e.sample.headers.authorization, '[REDACTED]');
    assert.equal(e.submittedBy, 'operator');
    assert.match(e.clientId, /^c_[0-9a-f]{16}$/);
    const audit = await admin.get('/api/audit?action=analysis.submit');
    assert.equal(audit.body.items[0].targetId, e.id);
  });

  it('sample validation: method enum, path must start with /, header names, 50 headers max', async () => {
    const bad = [
      { method: 'TRACE', path: '/' },
      { method: 'GET', path: 'search' },
      { method: 'GET', path: '/', headers: { 'bad header': 'x' } },
      { method: 'GET', path: '/', headers: Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`h${i}`, 'v'])) },
      { method: 'GET', path: '/', body: 5 },
    ];
    for (const sample of bad) {
      const r = await op.post('/api/analyze', { sample });
      assert.equal(r.status, 400, JSON.stringify(sample).slice(0, 80));
      assert.equal(r.body.error.code, 'VALIDATION_FAILED');
    }
  });

  it('event filters accept hostile strings safely; limit is clamped', async () => {
    for (const q of ["' OR 1=1 --", '%', '_', '"; DROP TABLE events;--', '\\']) {
      const r = await op.get('/api/events?q=' + encodeURIComponent(q));
      assert.equal(r.status, 200);
    }
    assert.equal((await op.get('/api/events?verdict=evil')).status, 400);
    assert.equal((await op.get('/api/events?ruleId=1%20OR%201')).status, 400);
    assert.equal((await op.get('/api/events?verdict=block&verdict=allow')).status, 400);
    const r = await op.get('/api/events?limit=5000');
    assert.equal(r.status, 200);
    assert.equal(r.body.limit, 200);
  });

  it('forged or unknown ids → 404, never 500', async () => {
    for (const id of ['evt_nope', "evt_' OR 1=1 --", '..%2F..%2Fetc%2Fpasswd', '%2500']) {
      const r = await op.get('/api/events/' + id);
      assert.ok([400, 404].includes(r.status), `${id} → ${r.status}`);
    }
  });

  it('import validates the file name and each sample, reporting rejects by index', async () => {
    assert.equal((await op.post('/api/import', { filename: '../evil.json', samples: [BENIGN] })).status, 400);
    assert.equal((await op.post('/api/import', { filename: 'a.txt', samples: [BENIGN] })).status, 400);
    assert.equal((await op.post('/api/import', { filename: 'a.json', samples: Array(101).fill(BENIGN) })).status, 400);
    const r = await op.post('/api/import', { filename: 'batch.json', samples: [BENIGN, { method: 'GET' }, { label: 'wrapped', sample: SQLI }, 'nope'] });
    assert.equal(r.status, 201);
    assert.equal(r.body.imported, 2);
    assert.deepEqual(r.body.rejected.map((x) => x.index), [1, 3]);
    assert.equal(r.body.events[1].label, 'wrapped');
    assert.ok(!('decision' in r.body.events[0]), 'import returns summaries');
  });

  it('compare computes the diff fields', async () => {
    const a = (await op.post('/api/analyze', { sample: BENIGN })).body.event;
    const b = (await op.post('/api/analyze', { sample: SQLI })).body.event;
    const r = await op.get(`/api/events/compare?a=${a.id}&b=${b.id}`);
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.diff, { verdictChanged: true, actionChanged: true, scoreDelta: 5, rulesAdded: [942100], rulesRemoved: [], rulesetChanged: false, configChanged: false });
    assert.equal((await op.get(`/api/events/compare?a=${a.id}`)).status, 400);
    assert.equal((await op.get(`/api/events/compare?a=${a.id}&b=evt_x`)).status, 404);
  });

  it('exception workflow: preview, request, SoD, confirm, approve → replay suppressed, revoke → restored', async () => {
    const original = (await op.post('/api/analyze', { label: 'exc', sample: SQLI })).body.event;
    const prev = await op.post('/api/exceptions/preview', { ruleId: 942100, scope: { pathPrefix: '/search', location: 'query.q', method: 'GET' } });
    assert.equal(prev.status, 200);
    assert.ok(prev.body.affectedEvents >= 1);
    assert.equal((await op.post('/api/exceptions', { ruleId: 942100, scope: {}, reason: 'unscoped' })).status, 400);
    assert.equal((await op.post('/api/exceptions', { ruleId: 123456, scope: { method: 'GET' }, reason: 'no rule' })).status, 400);
    const req = await op.post('/api/exceptions', { ruleId: 942100, scope: { pathPrefix: '/search', location: 'query.q', method: 'GET' }, reason: 'lab search box', sourceEventId: original.id });
    assert.equal(req.status, 201);
    const x = req.body.exception;
    assert.equal(x.status, 'pending');
    assert.equal(x.requestedBy, 'operator');

    const own = (await admin.post('/api/exceptions', { ruleId: 942100, scope: { pathPrefix: '/own' }, reason: 'self' })).body.exception;
    const self = await admin.post(`/api/exceptions/${own.id}/approve`, { confirm: true });
    assert.equal(self.status, 403);
    assert.match(self.body.error.message, /[Ss]eparation of duties/);

    assert.equal((await admin.post(`/api/exceptions/${x.id}/approve`, {})).status, 428);
    const ok = await admin.post(`/api/exceptions/${x.id}/approve`, { confirm: true, note: 'fine' });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.exception.status, 'approved');
    assert.equal(ok.body.exception.reviewedBy, 'admin');
    assert.equal((await admin.post(`/api/exceptions/${x.id}/approve`, { confirm: true })).status, 409, 'only pending can be approved');
    assert.equal((await admin.post(`/api/exceptions/${x.id}/reject`, {})).status, 409);

    const rep = await op.post(`/api/events/${original.id}/replay`);
    assert.equal(rep.status, 201);
    assert.equal(rep.body.event.replayOf, original.id);
    assert.equal(rep.body.event.source, 'replay');
    assert.equal(rep.body.previous.id, original.id);
    assert.ok(!('decision' in rep.body.previous));
    assert.equal(rep.body.event.verdict, 'allow');
    assert.equal(rep.body.event.decision.suppressed[0].suppressedBy, x.id);

    assert.equal((await admin2.post(`/api/exceptions/${x.id}/revoke`, {})).status, 428);
    const rv = await admin2.post(`/api/exceptions/${x.id}/revoke`, { confirm: true });
    assert.equal(rv.status, 200);
    assert.equal(rv.body.exception.status, 'revoked');
    assert.equal((await admin2.post(`/api/exceptions/${x.id}/revoke`, { confirm: true })).status, 409, 'only approved can be revoked');
    const rep2 = await op.post(`/api/events/${original.id}/replay`);
    assert.equal(rep2.body.event.verdict, 'block');

    const rj = await admin2.post(`/api/exceptions/${own.id}/reject`, { note: 'no' });
    assert.equal(rj.body.exception.status, 'rejected');
    const audit = (await admin.get('/api/audit?action=exception&limit=200')).body.items;
    for (const a of ['exception.request', 'exception.approve', 'exception.revoke', 'exception.reject']) assert.ok(audit.some((i) => i.action === a), a);
    assert.ok(audit.some((i) => i.action === 'exception.approve' && i.outcome === 'denied'));
  });

  it('proxy events cannot be replayed (409)', async () => {
    const e = h.db.events.record({ source: 'proxy', decision: { verdict: 'allow', action: 'allowed', matches: [], request: { method: 'GET', path: '/' } } });
    const r = await op.post(`/api/events/${e.id}/replay`);
    assert.equal(r.status, 409);
    assert.equal(r.body.error.code, 'CONFLICT');
  });

  it('analysis submissions are rate limited per user (429)', async () => {
    const h2 = await startHarness({ options: { analysisPerMinute: 3 } });
    try {
      const c = await h2.as('operator');
      const s = [];
      for (let i = 0; i < 4; i += 1) s.push((await c.post('/api/analyze', { sample: BENIGN })).status);
      assert.deepEqual(s, [201, 201, 201, 429]);
    } finally { await h2.close(); }
  });
});

describe('api: rules, config and users administration', () => {
  let h; let admin; let op;
  before(async () => { h = await startHarness(); admin = await h.as('admin'); op = await h.as('operator'); });
  after(async () => { await h.close(); });

  it('validate returns ok/errors without saving', async () => {
    const good = await op.post('/api/rules/validate', { source: 'rule 100001 "Test" {\n when args contains "evil"\n score 5\n}' });
    assert.equal(good.status, 200);
    assert.equal(good.body.ok, true);
    const bad = await op.post('/api/rules/validate', { source: 'rule x' });
    assert.equal(bad.body.ok, false);
    assert.ok(bad.body.errors[0].line);
  });

  it('create/update/disable/delete rules with versions, confirmations, history and immediate reload', async () => {
    const src = 'rule 100001 "Evil word" {\n when args contains "evilword"\n severity high\n score 5\n category test\n}';
    const before = (await admin.get('/api/rules')).body.rulesetVersion;
    const c = await admin.post('/api/rules', { source: src, enabled: true });
    assert.equal(c.status, 201);
    assert.equal(c.body.rule.version, 1);
    assert.equal(c.body.rule.category, 'test');
    assert.notEqual((await admin.get('/api/rules')).body.rulesetVersion, before, 'engine state reloaded');
    assert.equal((await admin.post('/api/rules', { source: src })).status, 409);
    const invalid = await admin.post('/api/rules', { source: 'rule 100002 "x" { }' });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.error.details[0].field, 'source');

    const blocked = await op.post('/api/analyze', { sample: { method: 'GET', path: '/?q=evilword', headers: {}, body: null } });
    assert.equal(blocked.body.event.verdict, 'block');

    const mismatch = await admin.put('/api/rules/100001', { source: src.replace('100001', '100003') });
    assert.equal(mismatch.status, 400);
    assert.equal((await admin.put('/api/rules/100001', { enabled: false })).status, 428);
    const dis = await admin.put('/api/rules/100001', { enabled: false, confirm: true });
    assert.equal(dis.status, 200);
    assert.equal(dis.body.rule.enabled, false);
    const allowed = await op.post('/api/analyze', { sample: { method: 'GET', path: '/?q=evilword', headers: {}, body: null } });
    assert.equal(allowed.body.event.verdict, 'allow', 'disabled rule no longer applies');
    assert.equal((await admin.put('/api/rules/100001', { enabled: true })).status, 200, 'enabling needs no confirm');
    const upd = await admin.put('/api/rules/100001', { source: src.replace('Evil word', 'Evil word v2') });
    assert.equal(upd.body.rule.name, 'Evil word v2');
    assert.equal(upd.body.rule.version, 4);

    assert.equal((await admin.del('/api/rules/100001', {})).status, 428);
    assert.equal((await admin.del('/api/rules/100001', { confirm: true })).status, 204);
    assert.equal((await admin.del('/api/rules/100001', { confirm: true })).status, 404);
    const hist = await op.get('/api/rules/100001/history');
    assert.deepEqual(hist.body.items.map((v) => v.change), ['delete', 'update', 'enable', 'disable', 'create']);
    assert.equal(hist.body.items[0].changedBy, 'admin');
    const audit = (await admin.get('/api/audit?action=rule&limit=50')).body.items.map((i) => i.action);
    for (const a of ['rule.create', 'rule.disable', 'rule.enable', 'rule.update', 'rule.delete']) assert.ok(audit.includes(a), a);
    assert.equal((await op.get('/api/rules/abc/history')).status, 404);
  });

  it('config: validated by the engine, needs confirm, versions increment, audit records the diff', async () => {
    const cur = (await op.get('/api/config')).body;
    assert.equal(cur.version, 1);
    assert.equal(cur.changedBy, 'system');
    const invalid = await admin.put('/api/config', { config: { ...cur.config, thresholds: { flag: 9, block: 2 } }, confirm: true });
    assert.equal(invalid.status, 400);
    assert.ok(invalid.body.error.details[0].field.startsWith('config.'));
    const next = { ...cur.config, mode: 'monitor' };
    assert.equal((await admin.put('/api/config', { config: next, reason: 'demo' })).status, 428);
    const ok = await admin.put('/api/config', { config: next, reason: 'demo', confirm: true });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.version, 2);
    assert.equal(h.engineState.getConfig().mode, 'monitor', 'engine state reloaded');
    const ev = await op.post('/api/analyze', { sample: SQLI });
    assert.equal(ev.body.event.action, 'logged');
    assert.equal(ev.body.event.configVersion, 2);
    const hist = await op.get('/api/config/history');
    assert.deepEqual(hist.body.items.map((i) => i.version), [2, 1]);
    assert.equal(hist.body.items[0].reason, 'demo');
    const audit = (await admin.get('/api/audit?action=config.update')).body.items[0];
    assert.equal(audit.targetId, '2');
    assert.deepEqual(audit.details.changes, [{ field: 'mode', from: 'block', to: 'monitor' }]);
    const stats = await op.get('/api/stats?hours=1');
    assert.equal(stats.body.mode, 'monitor');
    assert.equal(stats.body.configVersion, 2);
    assert.equal((await op.get('/api/stats?hours=0')).status, 400);
  });

  it('users: create with policy, conflicts, confirmations and last-admin protection', async () => {
    assert.equal((await admin.post('/api/users', { username: 'newbie', password: 'short', role: 'viewer' })).status, 400);
    const created = await admin.post('/api/users', { username: 'newbie', password: 'Newbie-Passw0rd!', role: 'viewer' });
    assert.equal(created.status, 201);
    assert.deepEqual(Object.keys(created.body.user).sort(), ['createdAt', 'disabled', 'id', 'lockedUntil', 'role', 'username']);
    assert.equal((await admin.post('/api/users', { username: 'NEWBIE', password: 'Newbie-Passw0rd!', role: 'viewer' })).status, 409);
    const id = created.body.user.id;
    assert.equal((await admin.put(`/api/users/${id}`, { role: 'operator' })).status, 428);
    assert.equal((await admin.put(`/api/users/${id}`, { role: 'operator', confirm: true })).body.user.role, 'operator');
    const nb = h.client(); await nb.login('newbie', 'Newbie-Passw0rd!');
    assert.equal((await admin.put(`/api/users/${id}`, { disabled: true, confirm: true })).status, 200);
    assert.equal((await nb.get('/api/auth/me')).status, 401, 'disabled user loses access immediately');
    assert.equal((await admin.put('/api/users/usr_00000000-0000-0000-0000-000000000000', { disabled: true, confirm: true })).status, 404);
    // demote admin2 and try to remove the last admin
    const list = (await admin.get('/api/users')).body.items;
    assert.ok(list.every((u) => !('passwordHash' in u) && !('password_hash' in u)));
    const a2 = list.find((u) => u.username === 'admin2');
    await admin.put(`/api/users/${a2.id}`, { disabled: true, confirm: true });
    const me = list.find((u) => u.username === 'admin');
    const last = await admin.put(`/api/users/${me.id}`, { role: 'viewer', confirm: true });
    assert.equal(last.status, 409);
    const audit = (await admin.get('/api/audit?action=user&limit=50')).body.items;
    assert.ok(audit.some((i) => i.action === 'user.create'));
    assert.ok(audit.some((i) => i.action === 'user.update' && i.details.changes.includes('disable')));
  });

  it('operator cannot escalate their own role', async () => {
    const r = await op.put(`/api/users/${op.user.id}`, { role: 'admin', confirm: true });
    assert.equal(r.status, 403);
    assert.equal((await op.get('/api/auth/me')).body.user.role, 'operator');
  });

  it('audit verify reports an intact chain to admins', async () => {
    const r = await admin.get('/api/audit/verify');
    assert.equal(r.body.ok, true);
    assert.ok(r.body.checked > 10);
    assert.equal(r.body.brokenAt, null);
  });
});
