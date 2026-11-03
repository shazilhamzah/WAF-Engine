'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startStack, skipUnlessStack } = require('../helpers/stack');
const { ApiClient } = require('../helpers/http');

const SAMPLE = { label: 'csrf', sample: { method: 'GET', path: '/search?q=csrf', headers: {}, body: null } };

describe('sessions and CSRF', { skip: skipUnlessStack() }, () => {
  let stack;
  before(async () => { stack = await startStack(); });
  after(async () => { if (stack) await stack.stop(); });

  it('login sets waf_sid with HttpOnly, SameSite=Strict, Path=/ and returns a CSRF token', async () => {
    const c = stack.client();
    const r = await c.login('operator', stack.passwords.operator);
    assert.equal(r.status, 200);
    const cookie = c.lastSetCookie.find((s) => s.startsWith('waf_sid='));
    assert.ok(cookie, 'waf_sid cookie set');
    assert.match(cookie, /;\s*HttpOnly/i);
    assert.match(cookie, /;\s*SameSite=Strict/i);
    assert.match(cookie, /;\s*Path=\//i);
    assert.ok(c.sid.length >= 32, 'session token has enough entropy');
    assert.ok(r.body.csrfToken && r.body.csrfToken !== c.sid, 'distinct CSRF token');
    assert.ok(r.body.expiresAt, 'expiry returned');
    assert.ok(!('passwordHash' in r.body.user) && !('password_hash' in r.body.user));
  });

  it('raw session token is never stored (only its hash)', async () => {
    const c = await stack.login('operator');
    const db = stack.openRawDb();
    try {
      const rows = db.prepare('SELECT * FROM sessions').all();
      const dump = JSON.stringify(rows);
      assert.ok(!dump.includes(c.sid), 'raw cookie value must not be in the sessions table');
      const hash = crypto.createHash('sha256').update(c.sid).digest('hex');
      assert.ok(rows.some((r) => r.token_hash === hash), 'sessions keyed by SHA-256(token)');
    } finally { db.close(); }
  });

  it('a new session id is issued at every login (no fixation)', async () => {
    const a = await stack.login('operator');
    const b = await stack.login('operator');
    assert.notEqual(a.sid, b.sid);
    const fix = new ApiClient(stack.studioUrl);
    fix.sid = 'attacker-chosen-session-id-000000000000';
    await fix.login('operator', stack.passwords.operator);
    assert.notEqual(fix.sid, 'attacker-chosen-session-id-000000000000');
  });

  it('state-changing request without CSRF token → 403 CSRF_INVALID', async () => {
    const c = await stack.login('operator');
    const r = await c.request('POST', '/api/analyze', { body: SAMPLE, csrf: false });
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, 'CSRF_INVALID');
  });

  it('wrong CSRF token → 403; token from another session → 403', async () => {
    const c = await stack.login('operator');
    const other = await stack.login('admin');
    const wrong = await c.request('POST', '/api/analyze', { body: SAMPLE, csrf: 'x'.repeat(c.csrfToken.length) });
    assert.equal(wrong.status, 403);
    assert.equal(wrong.body.error.code, 'CSRF_INVALID');
    const cross = await c.request('POST', '/api/analyze', { body: SAMPLE, csrf: other.csrfToken });
    assert.equal(cross.status, 403);
    for (const m of ['PUT', 'DELETE']) {
      const r = await other.request(m, '/api/config', { body: { config: {}, reason: 'x', confirm: true }, csrf: false });
      assert.equal(r.status, 403, `${m} without CSRF`);
    }
  });

  it('correct CSRF token → accepted; /api/auth/me returns the same token', async () => {
    const c = await stack.login('operator');
    const r = await c.post('/api/analyze', SAMPLE);
    assert.equal(r.status, 201);
    const me = await c.get('/api/auth/me');
    assert.equal(me.body.csrfToken, c.csrfToken);
  });

  it('GET requests do not change state and need no CSRF token', async () => {
    const c = await stack.login('viewer');
    const r = await c.get('/api/stats');
    assert.equal(r.status, 200);
  });

  it('logout returns 204, clears the cookie and invalidates the session server-side', async () => {
    const c = await stack.login('operator');
    const oldSid = c.sid;
    const out = await c.logout();
    assert.equal(out.status, 204);
    const replay = new ApiClient(stack.studioUrl);
    replay.sid = oldSid;
    const r = await replay.get('/api/auth/me');
    assert.equal(r.status, 401, 'old cookie no longer works');
  });

  it('logout requires CSRF (no forced logout from other sites)', async () => {
    const c = await stack.login('operator');
    const r = await c.request('POST', '/api/auth/logout', { csrf: false });
    assert.equal(r.status, 403);
    assert.equal((await c.get('/api/auth/me')).status, 200);
  });

  function ageSession(client, fields) {
    const db = stack.openRawDb();
    try {
      const hash = crypto.createHash('sha256').update(client.sid).digest('hex');
      const sets = Object.keys(fields).map((k) => `${k} = ?`).join(', ');
      const res = db.prepare(`UPDATE sessions SET ${sets} WHERE token_hash = ?`).run(...Object.values(fields), hash);
      assert.equal(Number(res.changes), 1, 'session row found');
    } finally { db.close(); }
  }

  it('idle timeout: session unused for > 30 min → 401', async () => {
    const c = await stack.login('operator');
    ageSession(c, { last_seen_at: new Date(Date.now() - 31 * 60 * 1000).toISOString() });
    const r = await c.get('/api/auth/me');
    assert.equal(r.status, 401);
    assert.ok(['SESSION_EXPIRED', 'AUTH_REQUIRED'].includes(r.body.error.code));
  });

  it('absolute lifetime: session older than 8 h → 401 even if active', async () => {
    const c = await stack.login('operator');
    const past = new Date(Date.now() - 9 * 3600 * 1000).toISOString();
    ageSession(c, { created_at: past, expires_at: new Date(Date.now() - 3600 * 1000).toISOString(), last_seen_at: new Date().toISOString() });
    const r = await c.get('/api/auth/me');
    assert.equal(r.status, 401);
  });
});
