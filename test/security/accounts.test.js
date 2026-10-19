'use strict';
/**
 * Account lifecycle security (NFR-2): disabling a user revokes access immediately; password change
 * requires the current password, enforces the 12-char minimum, and the old password stops working.
 * Kept separate from session-csrf.test.js so per-client login rate limits never interfere.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');

describe('account lifecycle', { skip: skipUnlessStack() }, () => {
  let stack;
  before(async () => { stack = await startStack(); });
  after(async () => { if (stack) await stack.stop(); });

  it('disabled user loses access immediately', async () => {
    const admin = await stack.login('admin');
    const created = await admin.post('/api/users', { username: 'tempviewer', password: 'Temp-Viewer-Passw0rd!', role: 'viewer' });
    assert.equal(created.status, 201);
    const tv = await stack.login('viewer', { username: 'tempviewer', password: 'Temp-Viewer-Passw0rd!' });
    const dis = await admin.put(`/api/users/${created.body.user.id}`, { disabled: true, confirm: true });
    assert.equal(dis.status, 200, dis.text);
    assert.equal((await tv.get('/api/stats')).status, 401);
    const again = await stack.client().login('tempviewer', 'Temp-Viewer-Passw0rd!');
    assert.equal(again.status, 401);
  });

  it('password change: requires current password, enforces min length, new password works', async () => {
    const admin = await stack.login('admin');
    await admin.post('/api/users', { username: 'pwuser', password: 'Pw-User-Original-1!', role: 'operator' });
    const c = await stack.login('operator', { username: 'pwuser', password: 'Pw-User-Original-1!' });
    const wrong = await c.post('/api/auth/password', { currentPassword: 'not-the-password', newPassword: 'Pw-User-Changed-22!' });
    assert.ok([400, 401, 403].includes(wrong.status));
    const short = await c.post('/api/auth/password', { currentPassword: 'Pw-User-Original-1!', newPassword: 'short' });
    assert.equal(short.status, 400);
    const ok = await c.post('/api/auth/password', { currentPassword: 'Pw-User-Original-1!', newPassword: 'Pw-User-Changed-22!' });
    assert.equal(ok.status, 204, ok.text);
    assert.equal((await stack.client().login('pwuser', 'Pw-User-Original-1!')).status, 401);
    assert.equal((await stack.client().login('pwuser', 'Pw-User-Changed-22!')).status, 200);
  });
});
