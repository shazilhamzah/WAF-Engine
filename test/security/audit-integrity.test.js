'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');
const { audit } = require('../helpers/api');

describe('append-only, hash-chained audit log', { skip: skipUnlessStack() }, () => {
  let stack, admin;
  before(async () => {
    stack = await startStack();
    admin = await stack.login('admin');
    const op = await stack.login('operator');
    await op.post('/api/analyze', { label: 'audit seed', sample: { method: 'GET', path: '/search?q=x', headers: {}, body: null } });
    await stack.client().login('viewer', 'wrong-password-for-audit');
  });
  after(async () => { if (stack) await stack.stop(); });

  it('audit entries follow the documented format', async () => {
    const items = await audit(admin);
    assert.ok(items.length >= 4);
    for (const i of items) {
      for (const k of ['seq', 'id', 'ts', 'actorName', 'action', 'outcome', 'prevHash', 'hash']) assert.ok(k in i, `missing ${k}`);
      assert.match(i.id, /^aud_/);
      assert.ok(['success', 'failure', 'denied'].includes(i.outcome), i.outcome);
      assert.match(i.hash, /^[0-9a-f]{64}$/);
      assert.ok(!Number.isNaN(Date.parse(i.ts)));
      if (i.clientId) assert.match(i.clientId, /^c_[0-9a-f]{16}$/);
    }
    const actions = new Set(items.map((i) => i.action));
    for (const a of ['system.start', 'auth.login.success', 'auth.login.failure', 'analysis.submit']) assert.ok(actions.has(a), `${a} audited`);
  });

  it('entries are chained (prevHash = previous hash) and the chain verifies', async () => {
    const items = (await audit(admin)).slice().sort((a, b) => a.seq - b.seq);
    for (let k = 1; k < items.length; k++) {
      if (items[k].seq === items[k - 1].seq + 1) assert.equal(items[k].prevHash, items[k - 1].hash, `link at seq ${items[k].seq}`);
    }
    const v = await admin.get('/api/audit/verify');
    assert.equal(v.status, 200);
    assert.equal(v.body.ok, true);
    assert.equal(v.body.brokenAt, null);
    assert.ok(v.body.checked >= items.length);
  });

  it('audit filters work (action, actor, outcome)', async () => {
    const r = await admin.get('/api/audit?action=auth.login.failure');
    assert.equal(r.status, 200);
    assert.ok(r.body.items.length >= 1 && r.body.items.every((i) => i.action === 'auth.login.failure'));
    const o = await admin.get('/api/audit?outcome=success&actor=admin');
    assert.ok(o.body.items.every((i) => i.outcome === 'success'));
  });

  it('UPDATE on audit_log is rejected by the database', () => {
    const db = stack.openRawDb();
    try {
      assert.throws(() => db.prepare("UPDATE audit_log SET action = 'forged' WHERE seq = 1").run(), /append-only|abort|constraint/i);
      assert.throws(() => db.prepare("UPDATE audit_log SET outcome = 'success'").run());
    } finally { db.close(); }
  });

  it('DELETE on audit_log is rejected by the database', () => {
    const db = stack.openRawDb();
    try {
      const before = db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
      assert.throws(() => db.prepare('DELETE FROM audit_log WHERE seq = 1').run(), /append-only|abort|constraint/i);
      assert.throws(() => db.prepare('DELETE FROM audit_log').run());
      assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n, before);
    } finally { db.close(); }
  });

  it('there is no API to modify or delete audit entries', async () => {
    for (const m of ['PUT', 'PATCH', 'DELETE']) {
      const r = await admin.request(m, '/api/audit/1', { body: {} });
      assert.ok([404, 405].includes(r.status), `${m} /api/audit/1 → ${r.status}`);
    }
  });

  it('tampering that bypasses the triggers is detected by chain verification', async () => {
    const db = stack.openRawDb();
    let tamperedSeq;
    try {
      const triggers = db.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_log'").all();
      assert.ok(triggers.length >= 2, 'append-only triggers present');
      // simulate an attacker with raw file access by dropping the triggers
      for (const t of triggers) db.exec(`DROP TRIGGER "${t.name}"`);
      const row = db.prepare("SELECT seq FROM audit_log WHERE action = 'auth.login.failure' ORDER BY seq LIMIT 1").get();
      tamperedSeq = row.seq;
      db.prepare("UPDATE audit_log SET outcome = 'success', action = 'auth.login.success' WHERE seq = ?").run(tamperedSeq);
      for (const t of triggers) db.exec(t.sql);
    } finally { db.close(); }
    const v = await admin.get('/api/audit/verify');
    assert.equal(v.status, 200);
    assert.equal(v.body.ok, false, 'tampering detected');
    assert.equal(Number(v.body.brokenAt), Number(tamperedSeq), 'points at the tampered entry');
  });
});
