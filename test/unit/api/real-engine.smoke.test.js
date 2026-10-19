'use strict';
/**
 * Smoke test of the backend with the REAL engine (src/engine), default rules and the lab target.
 * Skipped automatically while those modules are absent.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { Client } = require('./harness');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const available = ['src/engine/index.js', 'src/rules/default.rules', 'target/app.js'].every((p) => fs.existsSync(path.join(ROOT, p)));
const PASSWORDS = { admin: 'Smoke-Admin-Passw0rd', operator: 'Smoke-Operator-Passw0rd', viewer: 'Smoke-Viewer-Passw0rd' };

function get(url, headers = {}) {
  return new Promise((resolve) => {
    http.get(url, { headers, agent: false }, (res) => {
      const parts = [];
      res.on('data', (c) => parts.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(parts).toString('utf8') }));
    }).on('error', (e) => resolve({ status: 0, error: e.code }));
  });
}

describe('smoke: real engine + default rules + lab target', { skip: available ? false : 'engine, rules or target not present yet' }, () => {
  let stack; let dir;
  before(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'waf-smoke-'));
    const engine = require('../../../src/engine');
    const { openDatabase } = require('../../../src/db');
    const { seedDatabase } = require('../../../src/services/seed');
    const db = openDatabase(path.join(dir, 'waf-studio.db'));
    const seeded = await seedDatabase(db, engine, { passwords: PASSWORDS });
    assert.ok(seeded.rules.loaded > 0, 'default rules loaded');
    db.close();
    stack = await require('../../../src/index').startAll({ studioPort: 0, proxyPort: 0, targetPort: 0, dataDir: dir, quiet: true, env: {} });
  });
  after(async () => {
    if (stack) await stack.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('proxy allows benign traffic and blocks SQL injection without revealing rule details', async () => {
    const ok = await get(`${stack.urls.proxy}/search?q=mug`);
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['x-waf-action'], 'allowed');
    const bad = await get(`${stack.urls.proxy}/products?id=1%20OR%201%3D1`, { accept: 'text/html' });
    assert.equal(bad.status, 403);
    assert.equal(bad.headers['x-waf-action'], 'blocked');
    assert.ok(bad.text.includes(bad.headers['x-waf-event-id']));
    assert.doesNotMatch(bad.text, /942\d{3}|sqli|score/i);
  });

  it('console analysis returns an explainable decision; audit chain verifies', async () => {
    const op = new Client(stack.urls.studio);
    assert.equal((await op.login('operator', PASSWORDS.operator)).status, 200);
    const r = await op.post('/api/analyze', { label: 'smoke', sample: { method: 'GET', path: '/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--', headers: {}, body: null } });
    assert.equal(r.status, 201, r.text);
    const e = r.body.event;
    assert.ok(['block', 'flag'].includes(e.verdict));
    assert.ok(e.decision.matches.length > 0);
    assert.ok(e.decision.explanation.length > 0);
    assert.equal(e.configVersion, 1);
    const rep = await op.post(`/api/events/${e.id}/replay`);
    assert.equal(rep.status, 201);
    const admin = new Client(stack.urls.studio);
    await admin.login('admin', PASSWORDS.admin);
    const v = await admin.get('/api/audit/verify');
    assert.equal(v.body.ok, true);
    const rules = await admin.get('/api/rules');
    assert.ok(rules.body.items.length > 0);
    assert.deepEqual(rules.body.compileErrors, []);
    const cfg = await admin.get('/api/config');
    const put = await admin.put('/api/config', { config: { ...cfg.body.config, mode: 'monitor' }, reason: 'smoke', confirm: true });
    assert.equal(put.status, 200, put.text);
    const logged = await get(`${stack.urls.proxy}/products?id=1%20OR%201%3D1`);
    assert.equal(logged.headers['x-waf-action'], 'logged');
  });
});
