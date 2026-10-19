'use strict';
/**
 * Login brute-force protection (FR-5, NFR-7, contract §5.2):
 *  - generic 401 AUTH_INVALID for wrong password AND unknown user (no user enumeration)
 *  - 5 failures / 15 min per username → 429 RATE_LIMITED with Retry-After (even with the right password)
 *  - lockout is audited (auth.login.failure + auth.lockout), passwords never appear in the audit log
 *  - 20 attempts / min per client → 429
 *  - SQLi strings as usernames do not break the query or log anyone in
 * Each describe block gets its own stack so the counters never interfere with other files.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');
const { audit } = require('../helpers/api');

const WRONG = 'Definitely-Wrong-Passw0rd!';

describe('login lockout per username', { skip: skipUnlessStack() }, () => {
  let stack;
  before(async () => { stack = await startStack(); });
  after(async () => { if (stack) await stack.stop(); });

  it('wrong password and unknown user give the same generic 401', async () => {
    const a = await stack.client().login('operator', WRONG);
    const b = await stack.client().login('no-such-user-xyz', WRONG);
    assert.equal(a.status, 401);
    assert.equal(b.status, 401);
    assert.equal(a.body.error.code, 'AUTH_INVALID');
    assert.equal(a.body.error.code, b.body.error.code);
    assert.equal(a.body.error.message, b.body.error.message, 'identical message → no enumeration');
  });

  it('missing / non-string credentials → 400 or 401, never 500', async () => {
    for (const body of [{}, { username: 'admin' }, { username: ['admin'], password: { $ne: 1 } }, { username: 'a'.repeat(10000), password: 'x' }]) {
      const r = await stack.client().post('/api/auth/login', body);
      assert.ok([400, 401, 413].includes(r.status), `${JSON.stringify(body).slice(0, 60)} → ${r.status}`);
    }
  });

  it('5 failures lock the username → 429 with Retry-After, even with the correct password', async () => {
    // one failure already happened in the first test; make sure we reach ≥ 5
    let locked = null;
    for (let i = 0; i < 6; i++) {
      const r = await stack.client().login('operator', WRONG + i);
      if (r.status === 429) { locked = r; break; }
      assert.equal(r.status, 401);
    }
    assert.ok(locked, 'lockout reached within 5–6 failures');
    assert.equal(locked.body.error.code, 'RATE_LIMITED');
    assert.ok(Number(locked.headers.get('retry-after')) > 0, 'Retry-After header');
    assert.ok(locked.body.error.retryAfterSeconds > 0 || locked.body.retryAfterSeconds > 0, 'retryAfterSeconds in body');
    const right = await stack.client().login('operator', stack.passwords.operator);
    assert.equal(right.status, 429, 'locked account refuses even the correct password');
  });

  it('other accounts are unaffected by the lockout', async () => {
    const r = await stack.client().login('viewer', stack.passwords.viewer);
    assert.equal(r.status, 200);
  });

  it('failures and the lockout are audited; attempted passwords are never stored', async () => {
    const admin = await stack.login('admin');
    const items = await audit(admin);
    assert.ok(items.filter((i) => i.action === 'auth.login.failure').length >= 5);
    assert.ok(items.some((i) => i.action === 'auth.lockout'), 'auth.lockout recorded');
    const dump = JSON.stringify(items);
    assert.ok(!dump.includes(WRONG), 'attempted password not in audit details');
    assert.ok(!dump.includes(stack.passwords.operator));
  });

  it('SQL injection in the username does not bypass login', async () => {
    for (const u of ["admin' --", "' OR '1'='1", "admin'/*", '" OR ""="', "admin' OR 1=1 LIMIT 1 --"]) {
      const r = await stack.client().login(u, 'anything-at-all');
      assert.ok([401, 429].includes(r.status), `${u} → ${r.status}`);
    }
  });
});

describe('login rate limit per client', { skip: skipUnlessStack() }, () => {
  let stack;
  before(async () => { stack = await startStack(); });
  after(async () => { if (stack) await stack.stop(); });

  it('more than 20 attempts per minute from one client → 429', async () => {
    const statuses = [];
    for (let i = 0; i < 24; i++) {
      // different usernames so the per-username lockout is not what triggers
      const r = await stack.client().login(`spray-user-${i}`, WRONG);
      statuses.push(r.status);
    }
    assert.ok(statuses.slice(0, 20).every((s) => s === 401), `first 20 → 401: ${statuses}`);
    assert.ok(statuses.slice(20).every((s) => s === 429), `after 20 → 429: ${statuses}`);
  });
});
