'use strict';
/**
 * Test harness for Shazil's unit tests: in-memory DB, fake engine, seeded users, Studio app on an
 * ephemeral port, and a cookie/CSRF-aware JSON client.
 */
const http = require('node:http');
const { openDatabase } = require('../../../src/db');
const { createEngineState } = require('../../../src/services/engineState');
const { seedDatabase } = require('../../../src/services/seed');
const { createStudioApp } = require('../../../src/api/app');
const fakeEngine = require('./fakeEngine');

const PASSWORDS = Object.freeze({
  admin: 'Unit-Admin-Passw0rd!',
  operator: 'Unit-Operator-Passw0rd!',
  viewer: 'Unit-Viewer-Passw0rd!',
  admin2: 'Unit-Admin2-Passw0rd!',
});
const SECRET = 'unit-test-secret-0123456789abcdef';

class Client {
  constructor(base) { this.base = base; this.sid = null; this.csrf = null; this.user = null; }
  async request(method, path, { body, rawBody, headers = {}, csrf } = {}) {
    const h = { accept: 'application/json', ...headers };
    if (this.sid) h.cookie = `waf_sid=${this.sid}`;
    if (!['GET', 'HEAD'].includes(method)) {
      const token = csrf === undefined ? this.csrf : csrf;
      if (token) h['x-csrf-token'] = token;
    }
    let payload;
    if (rawBody !== undefined) payload = rawBody;
    else if (body !== undefined) { payload = JSON.stringify(body); if (!h['content-type']) h['content-type'] = 'application/json'; }
    const res = await fetch(this.base + path, { method, headers: h, body: payload, redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const m = /^waf_sid=([^;]*)/.exec(c);
      if (m) this.sid = m[1] && !/Max-Age=0/i.test(c) ? m[1] : null;
    }
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: res.status, headers: res.headers, body: json, text };
  }
  get(p, o) { return this.request('GET', p, o); }
  post(p, body, o = {}) { return this.request('POST', p, { ...o, body }); }
  put(p, body, o = {}) { return this.request('PUT', p, { ...o, body }); }
  del(p, body, o = {}) { return this.request('DELETE', p, { ...o, body }); }
  async login(username, password) {
    const r = await this.post('/api/auth/login', { username, password });
    if (r.status === 200) { this.csrf = r.body.csrfToken; this.user = r.body.user; }
    return r;
  }
}

/**
 * @param {{ clock?: () => number, options?: object, engine?: object }} [opts]
 */
async function startHarness(opts = {}) {
  const clockState = { offset: 0 };
  const clock = opts.clock || (() => Date.now() + clockState.offset);
  const db = openDatabase(':memory:', { clock });
  const engine = opts.engine || fakeEngine;
  await seedDatabase(db, engine, { passwords: PASSWORDS, includeAdmin2: true, rulesText: fakeEngine.DEFAULT_RULES });
  const engineState = createEngineState({ db, engine });
  const logs = [];
  const logger = { info: (m, x) => logs.push(['info', m, x]), warn: (m, x) => logs.push(['warn', m, x]), error: (m, x) => logs.push(['error', m, x]) };
  const app = createStudioApp({ db, engineState, secret: SECRET, logger, clock, options: opts.options || {} });
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    db, engineState, app, server, base, logs, clockState,
    advance(ms) { clockState.offset += ms; },
    client() { return new Client(base); },
    async as(role) {
      const c = new Client(base);
      const r = await c.login(role, PASSWORDS[role]);
      if (r.status !== 200) throw new Error(`login ${role} failed: ${r.status} ${r.text}`);
      return c;
    },
    async close() {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
      db.close();
    },
  };
}

module.exports = { startHarness, Client, PASSWORDS, SECRET, fakeEngine };
