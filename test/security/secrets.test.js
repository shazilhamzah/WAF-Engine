'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startStack, skipUnlessStack } = require('../helpers/stack');

const CANARY = {
  bearer: 'CANARY-BEARER-7f3a9c',
  cookie: 'CANARY-COOKIE-51be20',
  formPw: 'CANARY-FORMPW-a8d1e4',
  jsonPw: 'CANARY-JSONPW-c0ffee',
  token: 'CANARY-APITOKEN-99aa11',
  apiKey: 'CANARY-APIKEY-4242ab',
  sqliPw: 'CANARY-SQLIPW-0b0b0b'
};

describe('secrets never persisted or exported', { skip: skipUnlessStack() }, () => {
  let stack, operator, admin;
  before(async () => {
    stack = await startStack();
    operator = await stack.login('operator');
    admin = await stack.login('admin');

    await stack.proxy({ path: '/search?q=hello&api_key=' + CANARY.apiKey, headers: { authorization: 'Bearer ' + CANARY.bearer, cookie: 'session=' + CANARY.cookie } });
    await stack.proxy({ method: 'POST', path: '/login', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `username=alice&password=${CANARY.formPw}` });
    await stack.proxy({ method: 'POST', path: '/login', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'bob', password: CANARY.jsonPw, token: CANARY.token }) });
    // attack hidden in a password field and the evidence excerpt must still be redacted
    await stack.proxy({ method: 'POST', path: '/login', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'username=alice&password=' + encodeURIComponent(`' OR 1=1 -- ${CANARY.sqliPw}`) });

    await operator.post('/api/analyze', { label: 'secret sample', sample: {
      method: 'POST', path: '/login?token=' + CANARY.token,
      headers: { authorization: 'Bearer ' + CANARY.bearer, cookie: 'sid=' + CANARY.cookie, 'content-type': 'application/json', 'x-api-key': CANARY.apiKey },
      body: JSON.stringify({ username: 'carol', password: CANARY.jsonPw }) } });
    await operator.post('/api/analyze', { label: 'secret form', sample: {
      method: 'POST', path: '/login', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'username=carol&password=' + encodeURIComponent(`' OR '1'='1 ${CANARY.sqliPw}`) } });

    await stack.client().login('operator', CANARY.formPw + '-login');
  });
  after(async () => { if (stack) await stack.stop(); });

  function dumpDb() {
    const db = stack.openRawDb();
    try {
      const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all().map((t) => t.name);
      const out = {};
      for (const t of tables) out[t] = JSON.stringify(db.prepare(`SELECT * FROM "${t}"`).all());
      return out;
    } finally { db.close(); }
  }

  it('no canary secret appears in any table', () => {
    const dump = dumpDb();
    for (const [table, text] of Object.entries(dump)) {
      for (const [name, value] of Object.entries(CANARY)) assert.ok(!text.includes(value), `${name} leaked into table ${table}`);
      assert.ok(!text.includes(stack.passwords.operator), `operator password in ${table}`);
      assert.ok(!text.includes(stack.passwords.admin), `admin password in ${table}`);
    }
  });

  it('raw database file + WAL contain no canary bytes', () => {
    for (const suffix of ['', '-wal']) {
      const f = stack.dbPath + suffix;
      if (!fs.existsSync(f)) continue;
      const buf = fs.readFileSync(f);
      for (const [name, value] of Object.entries(CANARY)) assert.equal(buf.indexOf(value), -1, `${name} in ${path.basename(f)}`);
    }
  });

  it('raw client IP is never stored (pseudonymous client id only)', () => {
    const dump = dumpDb();
    for (const t of ['events', 'audit_log']) {
      if (!dump[t]) continue;
      assert.ok(!dump[t].includes('127.0.0.1') && !dump[t].includes('::ffff:127'), `raw IP in ${t}`);
      assert.match(dump[t], /c_[0-9a-f]{16}/, `pseudonymous client ids in ${t}`);
    }
  });

  it('password hashes are scrypt with per-user salts (no plaintext, no shared salt)', () => {
    const db = stack.openRawDb();
    try {
      const rows = db.prepare('SELECT username, password_hash FROM users').all();
      assert.ok(rows.length >= 3);
      const hashes = rows.map((r) => r.password_hash);
      assert.equal(new Set(hashes).size, hashes.length);
      for (const h of hashes) {
        assert.ok(h.length >= 64, 'hash long enough');
        assert.ok(!Object.values(stack.passwords).some((p) => h.includes(p)));
      }
    } finally { db.close(); }
  });

  it('events and audit returned by the API contain no canaries; masked values are visible', async () => {
    const ev = await admin.get('/api/events?limit=200');
    const full = await Promise.all(ev.body.items.map((e) => admin.get('/api/events/' + e.id)));
    const text = full.map((r) => r.text).join('\n') + (await admin.get('/api/audit?limit=500')).text;
    for (const [name, value] of Object.entries(CANARY)) assert.ok(!text.includes(value), `${name} returned by API`);
    const sample = full.map((r) => r.body.event).find((e) => e.label === 'secret sample');
    assert.ok(sample && sample.sample, 'console sample stored for replay');
    assert.ok(JSON.stringify(sample.sample.headers).match(/\*|redact|mask/i), 'authorization header masked, not dropped silently');
  });

  it('exports (json, csv, html) contain no canaries', async () => {
    for (const format of ['json', 'csv', 'html']) {
      const r = await admin.get('/api/reports/export?format=' + format);
      assert.equal(r.status, 200, format);
      for (const [name, value] of Object.entries(CANARY)) assert.ok(!r.text.includes(value), `${name} in ${format} export`);
    }
  });

  it('secret key file exists in the data dir and is not world-readable (POSIX) / not served', async () => {
    const keyFile = path.join(stack.dataDir, 'secret.key');
    if (!process.env.WAF_SECRET) assert.ok(fs.existsSync(keyFile), 'secret.key generated');
    if (process.platform !== 'win32' && fs.existsSync(keyFile)) assert.equal(fs.statSync(keyFile).mode & 0o077, 0);
    const key = fs.existsSync(keyFile) ? fs.readFileSync(keyFile).toString('utf8').trim() : null;
    for (const p of ['/secret.key', '/data/secret.key', '/../data/secret.key', '/waf-studio.db', '/%2e%2e/data/secret.key']) {
      const r = await stack.client().get(p);
      if (key) assert.ok(!r.text.includes(key.slice(0, 24)), `${p} must not serve the secret key`);
      assert.doesNotMatch(r.text, /SQLite format 3/, `${p} must not serve the database`);
    }
  });
});
