'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { openDatabase } = require('../../../src/db');
const { createEngineState } = require('../../../src/services/engineState');
const { seedDatabase } = require('../../../src/services/seed');
const { analyzeSample, sampleToRaw } = require('../../../src/services/analysis');
const { clientIdFor, createClientIdentifier } = require('../../../src/services/clientId');
const { redact, redactSample } = require('../../../src/services/redact');
const { createConsoleLogger } = require('../../../src/services/logger');
const { loadConfig, loadSecret } = require('../../../src/config');
const { verifyPassword } = require('../../../src/auth/passwords');
const fakeEngine = require('./fakeEngine');

describe('services: config and secrets', () => {
  it('defaults to 127.0.0.1 and the contract ports; validates env', () => {
    const c = loadConfig({});
    assert.equal(c.host, '127.0.0.1');
    assert.deepEqual([c.studioPort, c.proxyPort, c.targetPort], [3000, 8080, 3001]);
    assert.equal(c.targetUrl, 'http://127.0.0.1:3001');
    assert.ok(c.dbPath.endsWith(path.join('data', 'waf-studio.db')));
    assert.throws(() => loadConfig({ STUDIO_PORT: 'abc' }), /STUDIO_PORT/);
    assert.throws(() => loadConfig({ TARGET_URL: 'file:///etc/passwd' }), /TARGET_URL/);
    assert.equal(loadConfig({ WAF_DB_PATH: ':memory:' }).dbPath, ':memory:');
  });

  it('generates a 32-byte hex secret file once and reuses it; WAF_SECRET overrides', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waf-secret-'));
    try {
      const a = loadSecret(dir, {});
      assert.equal(a.source, 'generated');
      assert.match(a.secret, /^[0-9a-f]{64}$/);
      const b = loadSecret(dir, {});
      assert.equal(b.source, 'file');
      assert.equal(b.secret, a.secret);
      if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(dir, 'secret.key')).mode & 0o777, 0o600);
      assert.equal(loadSecret(dir, { WAF_SECRET: 'x'.repeat(32) }).source, 'env');
      assert.throws(() => loadSecret(dir, { WAF_SECRET: 'short' }));
      fs.writeFileSync(path.join(dir, 'secret.key'), 'garbage');
      assert.throws(() => loadSecret(dir, {}), /corrupt/);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

describe('services: privacy helpers', () => {
  it('clientId is an HMAC pseudonym, stable per IP and secret, never the IP', () => {
    const a = clientIdFor('s1', '10.0.0.1');
    assert.match(a, /^c_[0-9a-f]{16}$/);
    assert.equal(clientIdFor('s1', '::ffff:10.0.0.1'), a);
    assert.notEqual(clientIdFor('s2', '10.0.0.1'), a);
    assert.notEqual(clientIdFor('s1', '10.0.0.2'), a);
    assert.equal(createClientIdentifier('s1')('10.0.0.1'), a);
  });

  it('redacts secret-looking keys, headers and body fields', () => {
    assert.deepEqual(redact({ password: 'p', nested: { apiKey: 'k', ok: 1 }, list: [{ token: 't' }] }), { password: '[REDACTED]', nested: { apiKey: '[REDACTED]', ok: 1 }, list: [{ token: '[REDACTED]' }] });
    const s = redactSample({ method: 'POST', path: '/login', headers: { Cookie: 'sid=1', Authorization: 'Bearer x', 'content-type': 'application/x-www-form-urlencoded' }, body: 'user=bob&password=hunter2&q=1' });
    assert.equal(s.headers.Cookie, '[REDACTED]');
    assert.equal(s.headers.Authorization, '[REDACTED]');
    assert.equal(s.body, 'user=bob&password=%5BREDACTED%5D&q=1');
    assert.equal(redactSample({ method: 'POST', path: '/', headers: {}, body: '{"pass":"x","a":1}' }).body, '{"pass":"[REDACTED]","a":1}');
    assert.equal(redactSample({ method: 'GET', path: '/login?token=abc&q=1&api_key=k#frag', headers: {}, body: null }).path, '/login?token=%5BREDACTED%5D&q=1&api_key=%5BREDACTED%5D#frag');
    assert.equal(redactSample({ method: 'GET', path: '/plain', headers: {}, body: null }).path, '/plain');
  });

  it('console logger redacts metadata', () => {
    const lines = [];
    const log = createConsoleLogger({ stream: { write: (l) => lines.push(l) } });
    log.info('login', { username: 'bob', password: 'hunter2', err: new Error('x') });
    assert.ok(!lines[0].includes('hunter2'));
    assert.ok(lines[0].includes('[REDACTED]'));
  });
});

describe('services: seed and engine state', () => {
  it('seeds users, rules and config idempotently; passwords returned, only hashes stored', async () => {
    const db = openDatabase(':memory:');
    try {
      const first = await seedDatabase(db, fakeEngine, { rulesText: fakeEngine.DEFAULT_RULES, passwords: { admin: 'Given-Admin-Passw0rd' } });
      assert.deepEqual(first.created.map((u) => u.username), ['admin', 'operator', 'viewer']);
      assert.equal(first.passwords.admin, 'Given-Admin-Passw0rd');
      assert.ok(first.passwords.operator.length >= 20, 'generated password returned');
      assert.equal(first.rules.loaded, 3);
      assert.equal(first.config.version, 1);
      assert.equal(await verifyPassword('Given-Admin-Passw0rd', db.users.getPasswordHash(db.users.findByUsername('admin').id)), true);
      assert.ok(!JSON.stringify(db.raw.prepare('SELECT * FROM users').all()).includes('Given-Admin-Passw0rd'));
      const second = await seedDatabase(db, fakeEngine, { rulesText: fakeEngine.DEFAULT_RULES, includeAdmin2: true });
      assert.deepEqual(second.created.map((u) => u.username), ['admin2']);
      assert.equal(second.rules.skipped, true);
      assert.equal(second.config.seeded, false);
      await assert.rejects(seedDatabase(db, fakeEngine, { resetPasswords: true, passwords: { admin: 'short' } }), /at least 12/);
      const reset = await seedDatabase(db, fakeEngine, { resetPasswords: true, passwords: { viewer: 'Reset-Viewer-Passw0rd' } });
      assert.ok(reset.updated.some((u) => u.username === 'viewer'));
    } finally { db.close(); }
  });

  it('engine state loads rules/config/exceptions, seeds a default config, and reloads on change', async () => {
    const db = openDatabase(':memory:');
    try {
      await seedDatabase(db, fakeEngine, { rulesText: fakeEngine.DEFAULT_RULES });
      db.raw.exec('DELETE FROM config_versions');
      const es = createEngineState({ db, engine: fakeEngine });
      assert.equal(es.getConfigVersion(), 1, 'default config written when missing');
      assert.equal(es.status().ruleCount, 3);
      const v1 = es.getRulesetVersion();
      db.rules.update(942100, { enabled: false }, null, 'disable');
      es.reload();
      assert.equal(es.status().ruleCount, 2, 'disabled rules are not compiled');
      assert.notEqual(es.getRulesetVersion(), v1);
      const ctx = es.getContext({ clientKey: 'c_1', withRateLimit: true });
      assert.ok(ctx.rateLimiter && ctx.clientKey === 'c_1' && Number.isFinite(ctx.now));
      assert.equal(es.getContext({}).rateLimiter, null);
      assert.throws(() => createEngineState({ db, engine: {} }), /engine/);
    } finally { db.close(); }
  });

  it('analyzeSample builds the raw request, skips the rate limiter and stores the redacted sample', async () => {
    const db = openDatabase(':memory:');
    try {
      await seedDatabase(db, fakeEngine, { rulesText: fakeEngine.DEFAULT_RULES });
      const es = createEngineState({ db, engine: fakeEngine });
      const raw = sampleToRaw({ method: 'POST', path: '/x?a=1', headers: { 'Content-Type': 'text/plain' }, body: 'héllo' });
      assert.equal(raw.headers['content-type'], 'text/plain');
      assert.equal(raw.bodyBytes, 6);
      assert.ok(Buffer.isBuffer(raw.body));
      const e = analyzeSample({ db, engineState: es, sample: { method: 'GET', path: '/q?q=or%201=1', headers: { authorization: 'Basic x' }, body: null }, source: 'console', clientId: 'c_x' });
      assert.equal(e.verdict, 'block');
      assert.equal(e.sample.headers.authorization, '[REDACTED]');
      assert.equal(e.decision.rateLimit.checked, false);
    } finally { db.close(); }
  });
});
