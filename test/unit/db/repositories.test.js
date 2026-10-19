'use strict';
const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDatabase } = require('../../../src/db');
const { LATEST_VERSION } = require('../../../src/db/schema');
const { canonicalJson, escapeLike, newId, isId } = require('../../../src/db/util');

function decision(over = {}) {
  return {
    verdict: 'block', action: 'blocked', wouldBlock: true, statusCode: 403, blockReason: 'SCORE_THRESHOLD', mode: 'block',
    score: { total: 8, flagThreshold: 3, blockThreshold: 5, byCategory: { sqli: 5, xss: 3 }, contributions: [] },
    matches: [
      { ruleId: 942100, ruleName: 'SQLi', category: 'sqli', location: 'query.q', suppressedBy: null },
      { ruleId: 941100, ruleName: 'XSS', category: 'xss', location: 'query.q', suppressedBy: null },
    ],
    suppressed: [], anomalies: [],
    request: { method: 'GET', path: '/search' },
    engine: { engineVersion: '1', rulesetVersion: 'rs1', configVersion: 1 },
    timings: { totalMs: 0.4 },
    ...over,
  };
}

describe('db: bootstrap and migrations', () => {
  it('migrates a new in-memory database to the latest user_version with foreign keys on', () => {
    const db = openDatabase(':memory:');
    try {
      assert.equal(db.raw.prepare('PRAGMA user_version').get().user_version, LATEST_VERSION);
      assert.equal(db.raw.prepare('PRAGMA foreign_keys').get().foreign_keys, 1);
      const tables = db.raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);
      for (const t of ['users', 'sessions', 'rules', 'rule_versions', 'config_versions', 'events', 'exceptions', 'audit_log']) assert.ok(tables.includes(t), t);
    } finally { db.close(); }
  });

  it('uses WAL for file databases and survives reopen (restart) with data intact', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waf-db-'));
    const file = path.join(dir, 'x.db');
    try {
      let db = openDatabase(file);
      assert.equal(db.raw.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
      db.users.create({ username: 'alice', passwordHash: 'h', role: 'viewer' });
      db.audit.append({ actorName: 'system', action: 'system.start' });
      db.close();
      db = openDatabase(file);
      assert.equal(db.users.count(), 1);
      assert.equal(db.audit.verifyChain().ok, true);
      assert.equal(db.migration.from, LATEST_VERSION, 'no migration needed on second open');
      db.close();
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('refuses a database whose schema is newer than the code', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waf-db-'));
    const file = path.join(dir, 'x.db');
    try {
      const db = openDatabase(file);
      db.raw.exec(`PRAGMA user_version = ${LATEST_VERSION + 5}`);
      db.close();
      assert.throws(() => openDatabase(file), /newer than this build/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('transaction() rolls back on error, including nested savepoints', () => {
    const db = openDatabase(':memory:');
    try {
      assert.throws(() => db.transaction(() => {
        db.users.create({ username: 'bob', passwordHash: 'h', role: 'viewer' });
        throw new Error('boom');
      }), /boom/);
      assert.equal(db.users.count(), 0);
      db.transaction(() => {
        db.users.create({ username: 'carol', passwordHash: 'h', role: 'viewer' });
        assert.throws(() => db.transaction(() => { db.users.create({ username: 'dave', passwordHash: 'h', role: 'viewer' }); throw new Error('inner'); }));
      });
      assert.deepEqual(db.users.list().map((u) => u.username), ['carol']);
    } finally { db.close(); }
  });
});

describe('db: utilities', () => {
  it('canonicalJson sorts keys deterministically at every depth', () => {
    assert.equal(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } }), '{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}');
    assert.equal(canonicalJson({ a: undefined, b: 2 }), '{"b":2}');
  });
  it('escapeLike escapes %, _ and backslash', () => {
    assert.equal(escapeLike('50%_off\\'), '50\\%\\_off\\\\');
  });
  it('ids are server-generated with the contract prefixes', () => {
    for (const p of ['usr_', 'evt_', 'exc_', 'aud_', 'req_']) assert.ok(isId(newId(p), p));
    assert.throws(() => newId('bad_'));
    assert.equal(isId("evt_' OR 1=1", 'evt_'), false);
  });
});

describe('db: users and sessions', () => {
  let db;
  beforeEach(() => { db = openDatabase(':memory:'); });
  afterEach(() => db.close());

  it('creates users with unique case-insensitive usernames and role checks', () => {
    const u = db.users.create({ username: 'Admin', passwordHash: 'scrypt$x', role: 'admin' });
    assert.match(u.id, /^usr_/);
    assert.equal(db.users.findByUsername('admin').id, u.id);
    assert.throws(() => db.users.create({ username: 'ADMIN', passwordHash: 'h', role: 'admin' }), /UNIQUE/);
    assert.throws(() => db.users.create({ username: 'x1x', passwordHash: 'h', role: 'root' }));
    assert.throws(() => db.raw.prepare("INSERT INTO users VALUES ('usr_1','zed','h','root',0,0,NULL,'t','t')").run(), /CHECK/);
    assert.ok(!('passwordHash' in u) && !('password_hash' in u), 'mapped user never exposes the hash');
  });

  it('tracks failure state and counts active admins', () => {
    const a = db.users.create({ username: 'admin', passwordHash: 'h', role: 'admin' });
    db.users.setFailureState(a.id, 5, '2030-01-01T00:00:00.000Z');
    assert.equal(db.users.findById(a.id).lockedUntil, '2030-01-01T00:00:00.000Z');
    db.users.resetFailures(a.id);
    assert.equal(db.users.findById(a.id).failedAttempts, 0);
    assert.equal(db.users.countActiveAdmins(), 1);
    db.users.setDisabled(a.id, true);
    assert.equal(db.users.countActiveAdmins(), 0);
  });

  it('sessions are keyed by a 64-char hash and cascade on user deletion', () => {
    const u = db.users.create({ username: 'op1', passwordHash: 'h', role: 'operator' });
    assert.throws(() => db.sessions.create({ tokenHash: 'short', userId: u.id, csrfToken: 'c', createdAt: 't', expiresAt: 't' }), /CHECK/);
    db.sessions.create({ tokenHash: 'a'.repeat(64), userId: u.id, csrfToken: 'c', createdAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-01T08:00:00.000Z' });
    assert.equal(db.sessions.countForUser(u.id), 1);
    assert.equal(db.sessions.deleteExpired('2026-01-01T09:00:00.000Z', '2025-12-31T00:00:00.000Z'), 1);
  });
});

describe('db: rules and config versions', () => {
  let db;
  beforeEach(() => { db = openDatabase(':memory:'); });
  afterEach(() => db.close());

  it('records every change as an immutable version and keeps history after delete/re-create', () => {
    db.rules.create({ id: 942100, name: 'SQLi', source: 'rule 942100 "SQLi" {}', severity: 'critical', category: 'sqli' });
    db.rules.update(942100, { source: 'rule 942100 "SQLi v2" {}', name: 'SQLi v2' }, null, 'update');
    db.rules.update(942100, { enabled: false }, null, 'disable');
    assert.equal(db.rules.get(942100).version, 3);
    assert.equal(db.rules.get(942100).enabled, false);
    assert.deepEqual(db.rules.listForCompile(), [{ id: 942100, source: 'rule 942100 "SQLi v2" {}', enabled: false, version: 3 }]);
    assert.equal(db.rules.delete(942100), true);
    assert.equal(db.rules.get(942100), null);
    db.rules.create({ id: 942100, name: 'again', source: 's' });
    const hist = db.rules.history(942100);
    assert.deepEqual(hist.map((h) => [h.version, h.change]), [[5, 'create'], [4, 'delete'], [3, 'disable'], [2, 'update'], [1, 'create']]);
    assert.throws(() => db.rules.create({ id: 999, name: 'x', source: 's' }), /CHECK/, 'rule ids 1000–999999');
  });

  it('config versions increment; latest is active', () => {
    assert.equal(db.configs.latest(), null);
    db.configs.append({ mode: 'block' }, null, 'default');
    const v2 = db.configs.append({ mode: 'monitor' }, null, 'demo');
    assert.equal(v2.version, 2);
    assert.equal(db.configs.latest().config.mode, 'monitor');
    assert.deepEqual(db.configs.history().map((c) => c.version), [2, 1]);
  });
});

describe('db: events', () => {
  let db;
  beforeEach(() => { db = openDatabase(':memory:'); });
  afterEach(() => db.close());

  it('derives indexed columns from the decision and returns summaries vs full events', () => {
    const e = db.events.record({ source: 'proxy', decision: decision(), clientId: 'c_1', latencyMs: 0.4 });
    assert.match(e.id, /^evt_/);
    assert.deepEqual(e.matchedRuleIds, [942100, 941100]);
    assert.equal(e.path, '/search');
    assert.equal(e.rulesetVersion, 'rs1');
    const { items } = db.events.list({});
    assert.ok(!('decision' in items[0]) && !('sample' in items[0]) && !('clientId' in items[0]), 'summary only');
    assert.ok('decision' in db.events.list({ full: true }).items[0]);
  });

  it('filters by verdict/action/source/ruleId/q/from/to and caps limit at 200', () => {
    for (let i = 0; i < 5; i += 1) db.events.record({ source: 'console', decision: decision({ verdict: 'allow', action: 'allowed', matches: [], request: { method: 'GET', path: `/p${i}` } }), label: `lbl ${i}` });
    db.events.record({ source: 'proxy', decision: decision() });
    assert.equal(db.events.list({ verdict: 'block' }).total, 1);
    assert.equal(db.events.list({ action: 'allowed', source: 'console' }).total, 5);
    assert.equal(db.events.list({ ruleId: 941100 }).total, 1);
    assert.equal(db.events.list({ q: 'lbl 3' }).total, 1);
    assert.equal(db.events.list({ q: '/p' }).total, 5);
    assert.equal(db.events.list({ from: '2999-01-01T00:00:00.000Z' }).total, 0);
    assert.equal(db.events.list({ limit: 100000 }).items.length, 6);
    assert.equal(db.events.list({ limit: 2, offset: 1 }).items.length, 2);
  });

  it('SQL metacharacters and LIKE wildcards in filters are treated as data', () => {
    db.events.record({ source: 'console', decision: decision({ request: { method: 'GET', path: '/a%b' } }) });
    db.events.record({ source: 'console', decision: decision({ request: { method: 'GET', path: '/axb' } }) });
    for (const q of ["' OR 1=1 --", '"; DROP TABLE events; --', '%', '_', '\\']) {
      const r = db.events.list({ q });
      assert.equal(typeof r.total, 'number');
    }
    assert.equal(db.events.list({ q: '%' }).total, 1, '% matches only the literal percent');
    assert.equal(db.events.list({ q: "' OR 1=1 --" }).total, 0);
    assert.equal(db.events.count(), 2, 'table intact');
  });

  it('computes stats: totals, byCategory, topRules, latency percentiles and an hourly timeline', () => {
    db.events.record({ source: 'proxy', decision: decision(), latencyMs: 1 });
    db.events.record({ source: 'proxy', decision: decision({ verdict: 'flag', action: 'allowed', matches: [{ ruleId: 942100, category: 'sqli' }] }), latencyMs: 3 });
    db.events.record({ source: 'proxy', decision: decision({ verdict: 'block', action: 'logged', mode: 'monitor' }), latencyMs: 10 });
    const s = db.events.stats({ hours: 24 });
    assert.deepEqual(s.totals, { requests: 3, allowed: 1, logged: 1, blocked: 1, flagged: 1 });
    assert.deepEqual(s.byCategory, { sqli: 3, xss: 2 });
    assert.equal(s.topRules[0].ruleId, 942100);
    assert.equal(s.topRules[0].count, 3);
    assert.equal(s.latency.p50Ms, 3);
    assert.equal(s.latency.p95Ms, 10);
    assert.equal(s.timeline.length, 24);
    assert.equal(s.timeline.reduce((n, b) => n + b.allowed + b.blocked + b.logged, 0), 3);
  });

  it('prune keeps the newest N events and nulls replay links', () => {
    const first = db.events.record({ source: 'console', decision: decision() });
    db.events.record({ source: 'replay', decision: decision(), replayOf: first.id });
    db.events.record({ source: 'console', decision: decision() });
    assert.equal(db.events.prune(2), 1);
    assert.equal(db.events.count(), 2);
    assert.equal(db.events.list({ source: 'replay', full: true }).items[0].replayOf, null);
  });
});

describe('db: exceptions', () => {
  let db; let op; let admin;
  beforeEach(() => {
    db = openDatabase(':memory:');
    op = db.users.create({ username: 'operator', passwordHash: 'h', role: 'operator' });
    admin = db.users.create({ username: 'admin', passwordHash: 'h', role: 'admin' });
  });
  afterEach(() => db.close());

  it('follows the status machine with conditional transitions', () => {
    const x = db.exceptions.create({ ruleId: 942100, scope: { pathPrefix: '/search' }, reason: 'fp', requestedBy: op.id });
    assert.equal(x.status, 'pending');
    assert.equal(x.requestedBy, 'operator');
    assert.equal(db.exceptions.transition(x.id, 'approved', 'revoked', admin.id), null, 'not approved yet');
    const ap = db.exceptions.transition(x.id, 'pending', 'approved', admin.id, 'ok');
    assert.equal(ap.status, 'approved');
    assert.equal(ap.reviewedBy, 'admin');
    assert.equal(db.exceptions.transition(x.id, 'pending', 'rejected', admin.id), null, 'already approved');
    assert.deepEqual(db.exceptions.listActive().map((e) => e.id), [x.id]);
    assert.deepEqual(Object.keys(db.exceptions.listActive()[0]).sort(), ['expiresAt', 'id', 'reason', 'ruleId', 'scope', 'status']);
  });

  it('storage layer refuses self-approval (separation of duties CHECK)', () => {
    const x = db.exceptions.create({ ruleId: 942100, scope: { method: 'GET' }, reason: 'fp', requestedBy: admin.id });
    assert.throws(() => db.exceptions.transition(x.id, 'pending', 'approved', admin.id), /CHECK/);
  });

  it('listActive excludes expired exceptions', () => {
    const x = db.exceptions.create({ ruleId: 942100, scope: { method: 'GET' }, reason: 'fp', requestedBy: op.id, expiresAt: '2000-01-01T00:00:00.000Z' });
    db.exceptions.transition(x.id, 'pending', 'approved', admin.id);
    assert.equal(db.exceptions.listActive().length, 0);
    assert.equal(db.exceptions.listActive(Date.parse('1999-12-31T00:00:00Z')).length, 1);
  });
});
