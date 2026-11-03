'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { openDatabase } = require('../../../src/db');
const { createEngineState } = require('../../../src/services/engineState');
const { seedDatabase } = require('../../../src/services/seed');
const { createProxyServer } = require('../../../src/proxy/server');
const { prefersJson } = require('../../../src/proxy/pages');
const fakeEngine = require('./fakeEngine');

function listen(server) {
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
}
function close(server) {
  return new Promise((r) => { server.closeAllConnections(); server.close(() => r()); });
}

function send(port, { method = 'GET', path = '/', headers = {}, body = null, chunks = null } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent: false }, (res) => {
      const parts = [];
      res.on('data', (c) => parts.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(parts).toString('utf8') }));
    });
    req.on('error', (e) => resolve({ status: 0, error: e.code }));
    if (chunks) { for (const c of chunks) req.write(c); req.end(); } else req.end(body);
  });
}

describe('proxy: inspect, store, block or forward', () => {
  let db; let engineState; let upstream; let upstreamPort; let proxy; let port; const seen = [];

  before(async () => {
    db = openDatabase(':memory:');
    await seedDatabase(db, fakeEngine, { rulesText: fakeEngine.DEFAULT_RULES });
    engineState = createEngineState({ db, engine: fakeEngine });
    upstream = http.createServer((req, res) => {
      const parts = [];
      req.on('data', (c) => parts.push(c));
      req.on('end', () => {
        const body = Buffer.concat(parts);
        seen.push({ method: req.method, url: req.url, headers: req.headers, bodyLength: body.length });
        res.setHeader('X-Powered-By', 'upstream');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ ok: true, url: req.url, bytes: body.length, body: body.toString('utf8').slice(0, 100) }));
      });
    });
    upstreamPort = await listen(upstream);
    proxy = createProxyServer({ db, engineState, targetUrl: `http://127.0.0.1:${upstreamPort}`, secret: 'proxy-test-secret-0123456789' });
    port = await listen(proxy);
  });
  after(async () => { await close(proxy); if (upstream.listening) await close(upstream); db.close(); });

  it('forwards benign requests with X-WAF headers and stores a proxy event (no bodies or raw IPs)', async () => {
    const r = await send(port, { path: '/search?q=mug', headers: { cookie: 'session=SECRET-COOKIE', 'user-agent': 'ut' } });
    assert.equal(r.status, 200);
    assert.equal(r.headers['x-waf-action'], 'allowed');
    assert.match(r.headers['x-waf-event-id'], /^evt_/);
    assert.equal(r.headers['x-powered-by'], undefined, 'upstream fingerprint stripped');
    const e = db.events.get(r.headers['x-waf-event-id']);
    assert.equal(e.source, 'proxy');
    assert.equal(e.sample, null);
    assert.match(e.clientId, /^c_[0-9a-f]{16}$/);
    const row = JSON.stringify(db.raw.prepare('SELECT * FROM events WHERE id = ?').get(e.id));
    assert.ok(!row.includes('127.0.0.1'), 'raw IP never stored');
    assert.ok(!row.includes('SECRET-COOKIE'), 'header values never stored');
  });

  it('re-streams the buffered body intact (content-length and chunked) and sets X-Forwarded-For', async () => {
    const body = 'author=t&text=' + 'x'.repeat(5000);
    const r = await send(port, { method: 'POST', path: '/comments', headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body) }, body });
    assert.equal(r.status, 200);
    assert.equal(JSON.parse(r.text).bytes, Buffer.byteLength(body));
    const c = await send(port, { method: 'POST', path: '/echo', headers: { 'content-type': 'text/plain' }, chunks: ['abc', 'def', 'ghi'] });
    assert.equal(JSON.parse(c.text).body, 'abcdefghi');
    const last = seen[seen.length - 1];
    assert.equal(last.headers['content-length'], '9');
    assert.equal(last.headers['transfer-encoding'], undefined);
    assert.equal(last.headers['x-forwarded-for'], '127.0.0.1');
  });

  it('strips hop-by-hop and proxy credential headers before forwarding', async () => {
    await send(port, { path: '/hop', headers: { connection: 'keep-alive, x-secret-hop', 'x-secret-hop': '1', 'proxy-authorization': 'Basic abc', te: 'trailers', 'keep-alive': 'timeout=5' } });
    const last = seen[seen.length - 1];
    for (const h of ['x-secret-hop', 'proxy-authorization', 'te', 'keep-alive']) assert.equal(last.headers[h], undefined, h);
  });

  it('blocks attacks with the decision status and reveals only the event id (HTML and JSON)', async () => {
    const before = seen.length;
    const r = await send(port, { path: '/search?q=x%20or%201=1', headers: { accept: 'text/html' } });
    assert.equal(r.status, 403);
    assert.equal(r.headers['x-waf-action'], 'blocked');
    assert.ok(r.text.includes(r.headers['x-waf-event-id']));
    assert.doesNotMatch(r.text, /942100|SQLi|tautology|or 1=1|score|threshold/i);
    assert.equal(r.headers['content-security-policy'].startsWith("default-src 'none'"), true);
    assert.equal(seen.length, before, 'not forwarded');
    const j = await send(port, { path: '/search?q=%3Cscript%3E', headers: { accept: 'application/json' } });
    assert.equal(j.status, 403);
    const body = JSON.parse(j.text);
    assert.deepEqual(Object.keys(body.error).sort(), ['code', 'eventId', 'message', 'status']);
    assert.equal(body.error.eventId, j.headers['x-waf-event-id']);
    assert.equal(db.events.get(body.error.eventId).verdict, 'block');
  });

  it('rejects oversized bodies with 413 without forwarding (declared length and streamed)', async () => {
    const before = seen.length;
    const declared = await send(port, { method: 'POST', path: '/big', headers: { 'content-type': 'text/plain', 'content-length': 2 * 1024 * 1024 }, body: null });
    assert.ok(declared.status === 413 || declared.status === 0, String(declared.status));
    const chunk = Buffer.alloc(256 * 1024, 97);
    const streamed = await send(port, { method: 'POST', path: '/big', headers: { 'content-type': 'text/plain' }, chunks: [chunk, chunk, chunk, chunk, chunk] });
    assert.ok(streamed.status === 413 || streamed.status === 0, String(streamed.status));
    if (streamed.status === 413) assert.equal(streamed.headers['x-waf-action'], 'blocked');
    assert.equal(seen.length, before);
    const ev = db.events.list({ q: '/big', full: true }).items;
    assert.ok(ev.length >= 1);
    assert.ok(ev.every((e) => e.decision.blockReason === 'BODY_TOO_LARGE' && e.action === 'blocked'));
  });

  it('monitor mode forwards attacks with X-WAF-Action: logged, and the 413 safety limit still applies', async () => {
    db.configs.append({ ...engineState.getConfig(), mode: 'monitor' }, null, 'test');
    engineState.reload();
    try {
      const r = await send(port, { path: '/search?q=x%20or%201=1' });
      assert.equal(r.status, 200);
      assert.equal(r.headers['x-waf-action'], 'logged');
      const e = db.events.get(r.headers['x-waf-event-id']);
      assert.equal(e.decision.wouldBlock, true);
      assert.equal(e.mode, 'monitor');
      const big = await send(port, { method: 'POST', path: '/big2', headers: { 'content-type': 'text/plain', 'content-length': 2 * 1024 * 1024 } });
      assert.ok(big.status === 413 || big.status === 0);
    } finally {
      db.configs.append({ ...engineState.getConfig(), mode: 'block' }, null, 'restore');
      engineState.reload();
    }
  });

  it('rate limiting returns 429 with Retry-After and recovers after reconfiguration', async () => {
    db.configs.append({ ...engineState.getConfig(), rateLimit: { enabled: true, windowMs: 60000, maxRequests: 3 } }, null, 'tight');
    engineState.reload();
    const s = [];
    let limited;
    for (let i = 0; i < 5; i += 1) { const r = await send(port, { path: `/rl${i}` }); s.push(r.status); if (r.status === 429) limited = r; }
    assert.deepEqual(s, [200, 200, 200, 429, 429]);
    assert.equal(limited.headers['retry-after'], '60');
    db.configs.append({ ...engineState.getConfig(), rateLimit: { enabled: true, windowMs: 60000, maxRequests: 1000 } }, null, 'relax');
    engineState.reload();
    assert.equal((await send(port, { path: '/rl-after' })).status, 200);
  });

  it('fails closed with a safe 503 if the engine throws', async () => {
    const before = seen.length;
    const r = await send(port, { path: '/', headers: { 'x-fake-engine-throw': '1' } });
    assert.equal(r.status, 503);
    assert.doesNotMatch(r.text, /fake engine failure|Error|at /);
    assert.equal(seen.length, before);
  });

  it('refuses upgrade requests', async () => {
    const r = await send(port, { path: '/ws', headers: { connection: 'Upgrade', upgrade: 'websocket' } });
    assert.ok([0, 501].includes(r.status));
  });

  it('target down → 502 safe page with event id, system.error audit, proxy keeps running', async () => {
    await close(upstream);
    const r = await send(port, { path: '/search?q=down', headers: { accept: 'text/html' } });
    assert.equal(r.status, 502);
    assert.doesNotMatch(r.text, /ECONNREFUSED|127\.0\.0\.1|\bat \w+ \(|node:/);
    assert.match(r.text, /evt_/);
    const audit = db.audit.list({ action: 'system.error' }).items;
    assert.ok(audit.length >= 1);
    assert.equal(audit[0].details.reason, 'target_unavailable');
    const again = await send(port, { path: '/search?q=down2', headers: { accept: 'application/json' } });
    assert.equal(again.status, 502);
    assert.equal(JSON.parse(again.text).error.code, 'TARGET_UNAVAILABLE');
  });

  it('prefersJson parses Accept order', () => {
    assert.equal(prefersJson('application/json'), true);
    assert.equal(prefersJson('text/html, application/json'), false);
    assert.equal(prefersJson('application/json, text/html'), true);
    assert.equal(prefersJson(undefined), false);
  });
});
