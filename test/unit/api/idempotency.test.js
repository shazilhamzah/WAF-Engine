'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startHarness } = require('./harness');

const BENIGN = { method: 'GET', path: '/search?q=mug', headers: {}, body: null };
const key = (suffix) => `test-key-${suffix}-${Math.random().toString(36).slice(2, 10)}`;

describe('api: Idempotency-Key on record-creating endpoints', () => {
  let h; let admin; let op;
  before(async () => {
    h = await startHarness();
    admin = await h.as('admin');
    op = await h.as('operator');
  });
  after(async () => { await h.close(); });

  it('a retried analysis with the same key returns the first event instead of creating a second one', async () => {
    const k = key('analyze');
    const first = await op.post('/api/analyze', { sample: BENIGN }, { headers: { 'idempotency-key': k } });
    assert.equal(first.status, 201);
    const before = (await op.get('/api/events?limit=1')).body.total;
    const again = await op.post('/api/analyze', { sample: BENIGN }, { headers: { 'idempotency-key': k } });
    assert.equal(again.status, 201);
    assert.equal(again.headers.get('idempotent-replayed'), 'true');
    assert.equal(again.body.event.id, first.body.event.id);
    assert.equal((await op.get('/api/events?limit=1')).body.total, before);
  });

  it('without a key every request is processed as before', async () => {
    const a = await op.post('/api/analyze', { sample: BENIGN });
    const b = await op.post('/api/analyze', { sample: BENIGN });
    assert.equal(a.status, 201);
    assert.notEqual(a.body.event.id, b.body.event.id);
    assert.equal(b.headers.get('idempotent-replayed'), null);
  });

  it('reusing a key with a different body is rejected with 422', async () => {
    const k = key('reuse');
    const first = await op.post('/api/analyze', { sample: BENIGN }, { headers: { 'idempotency-key': k } });
    assert.equal(first.status, 201);
    const other = await op.post('/api/analyze', { label: 'different', sample: BENIGN }, { headers: { 'idempotency-key': k } });
    assert.equal(other.status, 422);
    assert.equal(other.body.error.code, 'IDEMPOTENCY_KEY_REUSED');
  });

  it('keys are scoped per user, so another account never receives a replayed response', async () => {
    const k = key('scope');
    const mine = await op.post('/api/analyze', { sample: BENIGN }, { headers: { 'idempotency-key': k } });
    const theirs = await admin.post('/api/analyze', { sample: BENIGN }, { headers: { 'idempotency-key': k } });
    assert.equal(theirs.status, 201);
    assert.equal(theirs.headers.get('idempotent-replayed'), null);
    assert.notEqual(theirs.body.event.id, mine.body.event.id);
  });

  it('failed attempts are not stored, so the same key can be retried after fixing the input', async () => {
    const k = key('user');
    const bad = await admin.post('/api/users', { username: 'idem-user', password: 'short', role: 'viewer' }, { headers: { 'idempotency-key': k } });
    assert.equal(bad.status, 400);
    const ok = await admin.post('/api/users', { username: 'idem-user', password: 'Idem-User-Passw0rd!', role: 'viewer' }, { headers: { 'idempotency-key': k } });
    assert.equal(ok.status, 201);
    const replay = await admin.post('/api/users', { username: 'idem-user', password: 'Idem-User-Passw0rd!', role: 'viewer' }, { headers: { 'idempotency-key': k } });
    assert.equal(replay.status, 201);
    assert.equal(replay.headers.get('idempotent-replayed'), 'true');
    assert.equal(replay.body.user.id, ok.body.user.id);
    const users = (await admin.get('/api/users')).body.items.filter((u) => u.username === 'idem-user');
    assert.equal(users.length, 1);
  });

  it('malformed keys are rejected before the route runs', async () => {
    const r = await op.post('/api/analyze', { sample: BENIGN }, { headers: { 'idempotency-key': 'bad key!' } });
    assert.equal(r.status, 400);
    assert.equal(r.body.error.code, 'VALIDATION_FAILED');
  });

  it('read-only and non-creating endpoints ignore the header', async () => {
    const k = key('validate');
    const a = await admin.post('/api/rules/validate', { source: 'not a rule' }, { headers: { 'idempotency-key': k } });
    const b = await admin.post('/api/rules/validate', { source: 'also not a rule' }, { headers: { 'idempotency-key': k } });
    assert.equal(a.status, 200);
    assert.equal(b.status, 200);
    assert.equal(b.headers.get('idempotent-replayed'), null);
  });
});
