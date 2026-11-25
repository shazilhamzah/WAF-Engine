'use strict';
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { openDatabase } = require('../../../src/db');
const { computeHash, GENESIS_HASH } = require('../../../src/db/repositories/audit');
const { canonicalJson, sha256Hex } = require('../../../src/db/util');

function fill(db, n = 5) {
  for (let i = 0; i < n; i += 1) {
    db.audit.append({ actorId: null, actorName: i % 2 ? 'admin' : 'system', actorRole: i % 2 ? 'admin' : null, action: i % 2 ? 'config.update' : 'system.start', targetType: 'config', targetId: String(i), outcome: 'success', clientId: 'c_abc', details: { i, nested: { b: 2, a: 1 } } });
  }
}

describe('audit log: hash chain', () => {
  let db;
  beforeEach(() => { db = openDatabase(':memory:'); });
  afterEach(() => db.close());

  it('chains each entry to the previous hash starting from the genesis hash', () => {
    fill(db, 3);
    const items = db.audit.list({ limit: 10 }).items.reverse();
    assert.equal(items[0].seq, 1);
    assert.equal(items[0].prevHash, GENESIS_HASH);
    assert.equal(items[1].prevHash, items[0].hash);
    assert.equal(items[2].prevHash, items[1].hash);
    for (const e of items) assert.equal(computeHash(e), e.hash);
  });

  it('hash = sha256(prevHash + canonicalJSON(all fields except hash))', () => {
    const e = db.audit.append({ actorName: 'admin', action: 'rule.update', details: { z: 1, a: 2 } });
    const { hash, ...rest } = e;
    assert.equal(hash, sha256Hex(e.prevHash + canonicalJson(rest)));
  });

  it('verifyChain passes on an untouched log', () => {
    fill(db, 10);
    assert.deepEqual(db.audit.verifyChain(), { ok: true, checked: 10, brokenAt: null });
  });

  it('details are redacted before hashing and storage', () => {
    const e = db.audit.append({ actorName: 'anonymous', action: 'auth.login.failure', outcome: 'failure', details: { username: 'bob', password: 'hunter2hunter2', nested: { token: 'abc' } } });
    assert.equal(e.details.password, '[REDACTED]');
    assert.equal(e.details.nested.token, '[REDACTED]');
    const raw = db.raw.prepare('SELECT details_json FROM audit_log WHERE seq = ?').get(e.seq).details_json;
    assert.ok(!raw.includes('hunter2'));
  });

  it('rejects invalid outcomes and missing actions', () => {
    assert.throws(() => db.audit.append({ actorName: 'x', action: 'a', outcome: 'maybe' }));
    assert.throws(() => db.audit.append({ actorName: 'x' }));
  });

  it('filters by action family, actor, outcome and caps the page size', () => {
    fill(db, 6);
    db.audit.append({ actorName: 'mallory', action: 'auth.denied', outcome: 'denied' });
    assert.equal(db.audit.list({ action: 'config' }).total, 3, 'prefix family match');
    assert.equal(db.audit.list({ action: 'config.update' }).total, 3);
    assert.equal(db.audit.list({ actor: 'mallory' }).total, 1);
    assert.equal(db.audit.list({ outcome: 'denied' }).total, 1);
    assert.equal(db.audit.list({ action: "x' OR '1'='1" }).total, 0);
    assert.ok(db.audit.list({ limit: 9999 }).items.length <= 200);
  });
});

describe('audit log: append-only enforcement and tamper detection', () => {
  it('UPDATE and DELETE are aborted by triggers', () => {
    const db = openDatabase(':memory:');
    try {
      fill(db, 2);
      assert.throws(() => db.raw.prepare("UPDATE audit_log SET outcome = 'failure' WHERE seq = 1").run(), /append-only/);
      assert.throws(() => db.raw.prepare('DELETE FROM audit_log WHERE seq = 2').run(), /append-only/);
      assert.throws(() => db.raw.exec('DELETE FROM audit_log'), /append-only/);
      assert.equal(db.audit.count(), 2);
      assert.equal(db.audit.verifyChain().ok, true);
    } finally { db.close(); }
  });

  it('an edit made on a raw copy of the file (triggers dropped) is detected by verifyChain', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waf-audit-'));
    const file = path.join(dir, 'a.db');
    try {
      let db = openDatabase(file);
      fill(db, 5);
      db.close();
      // Attacker with file access bypasses the application and the triggers.
      const raw = new DatabaseSync(file);
      raw.exec('DROP TRIGGER audit_log_no_update');
      raw.prepare("UPDATE audit_log SET actor_name = 'someone-else' WHERE seq = 3").run();
      raw.close();
      db = openDatabase(file);
      assert.deepEqual(db.audit.verifyChain(), { ok: false, checked: 2, brokenAt: 3 });
      db.close();
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('deleting a row (gap) or recomputing one hash without the rest is detected', () => {
    const db = openDatabase(':memory:');
    try {
      fill(db, 5);
      db.raw.exec('DROP TRIGGER audit_log_no_delete');
      db.raw.exec('DROP TRIGGER audit_log_no_update');
      db.raw.prepare('DELETE FROM audit_log WHERE seq = 4').run();
      assert.equal(db.audit.verifyChain().brokenAt, 5, 'gap detected');
    } finally { db.close(); }
    const db2 = openDatabase(':memory:');
    try {
      fill(db2, 5);
      db2.raw.exec('DROP TRIGGER audit_log_no_update');
      const row = db2.audit.get(2);
      const forged = { ...row, details: { forged: true } };
      forged.hash = computeHash(forged);
      db2.raw.prepare('UPDATE audit_log SET details_json = ?, hash = ? WHERE seq = 2').run(JSON.stringify(forged.details), forged.hash);
      assert.equal(db2.audit.verifyChain().brokenAt, 3, 'next link no longer matches');
    } finally { db2.close(); }
  });
});
