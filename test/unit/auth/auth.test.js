'use strict';
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { openDatabase } = require('../../../src/db');
const pw = require('../../../src/auth/passwords');
const { createSessionManager, hashToken, parseCookies, serializeCookie, safeEqual } = require('../../../src/auth/sessions');
const { createLoginThrottle, createSlidingWindowLimiter } = require('../../../src/auth/rateLimit');

describe('auth: password hashing', () => {
  it('uses scrypt N=16384 r=8 p=1 with a 16-byte salt and 64-byte key', async () => {
    const h = await pw.hashPassword('correct horse battery staple');
    const parts = h.split('$');
    assert.equal(parts[0], 'scrypt');
    assert.deepEqual(parts.slice(1, 4).map(Number), [16384, 8, 1]);
    assert.equal(Buffer.from(parts[4], 'base64').length, 16);
    assert.equal(Buffer.from(parts[5], 'base64').length, 64);
  });

  it('salts per hash and verifies correctly', async () => {
    const a = await pw.hashPassword('Same-Password-123');
    const b = await pw.hashPassword('Same-Password-123');
    assert.notEqual(a, b);
    assert.equal(await pw.verifyPassword('Same-Password-123', a), true);
    assert.equal(await pw.verifyPassword('same-password-123', a), false);
    assert.equal(await pw.verifyPassword('', a), false);
  });

  it('never throws on malformed or hostile stored hashes', async () => {
    for (const bad of [null, '', 'plain', 'scrypt$1$1$1$a$b', `scrypt$${2 ** 30}$8$1$${'A'.repeat(24)}$${'A'.repeat(88)}`, 'bcrypt$x']) {
      assert.equal(await pw.verifyPassword('whatever-password', bad), false);
    }
  });

  it('dummyVerify always resolves false (used for unknown users)', async () => {
    assert.equal(await pw.dummyVerify('anything at all'), false);
    assert.equal(await pw.dummyVerify(undefined), false);
  });

  it('policy: ≥12 chars, ≤256, not the username, not one repeated character', () => {
    assert.deepEqual(pw.checkPasswordPolicy('Long-Enough-Pw1', 'alice'), []);
    assert.ok(pw.checkPasswordPolicy('short', 'alice').length > 0);
    assert.ok(pw.checkPasswordPolicy('alice-account', 'Alice-Account').length > 0);
    assert.ok(pw.checkPasswordPolicy('aaaaaaaaaaaaaa', 'bob').length > 0);
    assert.ok(pw.checkPasswordPolicy('x'.repeat(300), 'bob').length > 0);
    assert.ok(pw.generatePassword().length >= 20);
  });
});

describe('auth: sessions', () => {
  let db; let user; let now; let sessions;
  beforeEach(() => {
    db = openDatabase(':memory:');
    user = db.users.create({ username: 'operator', passwordHash: 'h', role: 'operator' });
    now = Date.parse('2026-10-19T10:00:00.000Z');
    sessions = createSessionManager({ db, clock: () => now });
  });
  afterEach(() => db.close());

  it('stores only the SHA-256 of a 32-byte random token', () => {
    const s = sessions.create(user.id, 'c_1');
    assert.equal(Buffer.from(s.token, 'base64url').length, 32);
    const rows = db.raw.prepare('SELECT * FROM sessions').all();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].token_hash, crypto.createHash('sha256').update(s.token).digest('hex'));
    assert.ok(!JSON.stringify(rows).includes(s.token));
    assert.notEqual(s.csrfToken, s.token);
  });

  it('validates, slides the idle window and expires after 30 minutes idle', () => {
    const s = sessions.create(user.id);
    now += 29 * 60 * 1000;
    assert.equal(sessions.validate(s.token).status, 'ok');
    now += 29 * 60 * 1000; // still within 30 min of the last activity
    assert.equal(sessions.validate(s.token).status, 'ok');
    now += 31 * 60 * 1000;
    assert.equal(sessions.validate(s.token).status, 'expired');
    assert.equal(db.sessions.get(hashToken(s.token)), null, 'expired session deleted');
  });

  it('expires after the 8-hour absolute lifetime even when active', () => {
    const s = sessions.create(user.id);
    for (let i = 0; i < 16; i += 1) { now += 29 * 60 * 1000; sessions.validate(s.token); }
    now += 29 * 60 * 1000; // 8h 13m since creation
    assert.equal(sessions.validate(s.token).status, 'expired');
  });

  it('reports expiresAt as min(idle, absolute)', () => {
    const s = sessions.create(user.id);
    assert.equal(s.expiresAt, new Date(now + 30 * 60 * 1000).toISOString());
  });

  it('rejects unknown/malformed tokens and sessions of disabled users', () => {
    assert.equal(sessions.validate(undefined).status, 'missing');
    assert.equal(sessions.validate('not-a-token').status, 'expired');
    assert.equal(sessions.validate(crypto.randomBytes(32).toString('base64url')).status, 'expired');
    const s = sessions.create(user.id);
    db.users.setDisabled(user.id, true);
    assert.equal(sessions.validate(s.token).status, 'expired');
  });

  it('destroy / destroyAllForUser invalidate sessions', () => {
    const a = sessions.create(user.id);
    const b = sessions.create(user.id);
    sessions.destroy(a.token);
    assert.equal(sessions.validate(a.token).status, 'expired');
    assert.equal(sessions.validate(b.token).status, 'ok');
    assert.equal(sessions.destroyAllForUser(user.id), 1);
    assert.equal(sessions.validate(b.token).status, 'expired');
  });

  it('CSRF check is exact and timing-safe', () => {
    const s = sessions.create(user.id);
    const v = sessions.validate(s.token);
    assert.equal(sessions.checkCsrf(v.session, s.csrfToken), true);
    assert.equal(sessions.checkCsrf(v.session, s.csrfToken.slice(0, -1)), false);
    assert.equal(sessions.checkCsrf(v.session, ''), false);
    assert.equal(sessions.checkCsrf(v.session, undefined), false);
    assert.equal(sessions.checkCsrf(v.session, 'x'.repeat(1000)), false);
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
  });

  it('cookie helpers: HttpOnly, SameSite=Strict, Path=/, Secure on HTTPS, clearing', () => {
    const c = serializeCookie('tok');
    assert.match(c, /^waf_sid=tok; Path=\/; HttpOnly; SameSite=Strict$/);
    assert.match(serializeCookie('tok', { secure: true }), /; Secure/);
    assert.match(serializeCookie('', { clear: true }), /Max-Age=0/);
    assert.deepEqual(parseCookies('a=1; waf_sid=xyz; waf_sid=evil'), { a: '1', waf_sid: 'xyz' });
    assert.deepEqual(parseCookies('x'.repeat(9000)), {});
  });
});

describe('auth: throttling', () => {
  it('locks a username after 5 failures in 15 minutes for 15 minutes', () => {
    let now = 0;
    const t = createLoginThrottle({ clock: () => now });
    for (let i = 1; i <= 4; i += 1) assert.equal(t.recordFailure('Alice').lockedNow, false);
    const fifth = t.recordFailure('alice');
    assert.equal(fifth.lockedNow, true);
    assert.equal(t.lockStatus('ALICE').locked, true, 'case-insensitive');
    assert.equal(t.lockStatus('bob').locked, false, 'other users unaffected');
    now += 15 * 60 * 1000 + 1;
    assert.equal(t.lockStatus('alice').locked, false);
  });

  it('failures outside the 15-minute window do not count', () => {
    let now = 0;
    const t = createLoginThrottle({ clock: () => now });
    for (let i = 0; i < 4; i += 1) t.recordFailure('carol');
    now += 16 * 60 * 1000;
    assert.equal(t.recordFailure('carol').lockedNow, false);
  });

  it('honours a persisted lock (survives restart) and resets on success', () => {
    const t = createLoginThrottle({ clock: () => 1000 });
    assert.equal(t.lockStatus('dave', new Date(5000).toISOString()).locked, true);
    t.recordFailure('erin'); t.recordSuccess('erin');
    assert.equal(t.recordFailure('erin').failures, 1);
  });

  it('limits a client to 20 attempts per minute', () => {
    let now = 0;
    const t = createLoginThrottle({ clock: () => now });
    for (let i = 0; i < 20; i += 1) assert.equal(t.checkClient('c_1').limited, false);
    const r = t.checkClient('c_1');
    assert.equal(r.limited, true);
    assert.ok(r.retryAfterSeconds >= 1 && r.retryAfterSeconds <= 60);
    assert.equal(t.checkClient('c_2').limited, false);
    now += 60 * 1000 + 1;
    assert.equal(t.checkClient('c_1').limited, false);
  });

  it('sliding window limiter bounds memory', () => {
    const l = createSlidingWindowLimiter({ windowMs: 1000, max: 1, clock: () => 0, maxKeys: 10 });
    for (let i = 0; i < 100; i += 1) l.hit(`k${i}`);
    assert.equal(l.hit('k99').limited, true);
  });
});
