'use strict';
/**
 * Vulnerable target (target/app.js) — proves each deliberate vulnerability is real when hit DIRECTLY
 * (so the WAF has something meaningful to stop) and that the sandbox fences hold.
 * Runs without any other module, on an ephemeral port.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createTargetApp, resolveLabFile } = require('../../target/app');

let server;
let base;

test.before(async () => {
  server = http.createServer(createTargetApp());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => new Promise((r) => server.close(r)));

const get = (p, headers = {}) => fetch(base + p, { headers });
const postForm = (p, obj) => fetch(base + p, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(obj).toString(), redirect: 'manual'
});
const postJson = (p, obj) => fetch(base + p, {
  method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(obj)
});

test('home page shows the LAB ONLY banner and links', async () => {
  const res = await get('/');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /LAB ONLY/);
  for (const link of ['/search', '/products', '/comments', '/files', '/health']) assert.ok(html.includes(link), link);
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('health endpoint', async () => {
  const res = await get('/health');
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok', app: 'vulnerable-shop', lab: true });
});

test('reflected XSS: q is echoed unescaped', async () => {
  const payload = '<script>alert(1)</script>';
  const html = await (await get('/search?q=' + encodeURIComponent(payload))).text();
  assert.ok(html.includes(payload));
});

test('benign search returns results', async () => {
  const html = await (await get('/search?q=mug')).text();
  assert.match(html, /Packet Sniffer Mug/);
});

test('SQLi login bypass works directly against the target', async () => {
  const ok = await postJson('/login', { username: "' OR '1'='1' --", password: 'x' });
  assert.equal(ok.status, 200);
  const body = await ok.json();
  assert.equal(body.ok, true);
  const bad = await postJson('/login', { username: 'alice', password: 'wrong' });
  assert.equal(bad.status, 401);
  const good = await postForm('/login', { username: 'alice', password: 'fake-pass-alice-001' });
  assert.equal(good.status, 200);
  assert.match(await good.text(), /Welcome back, alice/);
});

test('SQLi on products: tautology and UNION expose all rows / fake users', async () => {
  const all = await (await get('/products?id=1%20OR%201=1', { accept: 'application/json' })).json();
  assert.equal(all.items.length, 5);
  const union = await (await get('/products?id=' + encodeURIComponent('0 UNION SELECT id, username, password FROM users'),
    { accept: 'application/json' })).json();
  assert.ok(union.items.some((r) => String(r.price).startsWith('FAKE-LAB-FLAG')));
});

test('SQLi stacked statements are ignored (prepare compiles only the first statement)', async () => {
  await get('/products?id=' + encodeURIComponent('1; DROP TABLE users'));
  const res = await postJson('/login', { username: 'alice', password: 'fake-pass-alice-001' });
  assert.equal(res.status, 200, 'users table must still exist');
});

test('SQL error is reported without stack traces or file paths', async () => {
  const res = await get("/products?id=1'");
  assert.equal(res.status, 500);
  const text = await res.text();
  assert.match(text, /Database error/);
  assert.doesNotMatch(text, /at \w+ \(|node:internal|[A-Z]:\\|\/target\//);
});

test('stored XSS: comment stored and rendered unescaped; capped at 100', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  const r = await postJson('/comments', { author: 'eve', text: payload });
  assert.equal(r.status, 201);
  const html = await (await get('/comments')).text();
  assert.ok(html.includes(payload));
  for (let i = 0; i < 120; i++) await postJson('/comments', { text: 'c' + i });
  const list = await (await get('/comments', { accept: 'application/json' })).json();
  assert.equal(list.items.length, 100);
  const formPost = await postForm('/comments', { text: 'hello' });
  assert.equal(formPost.status, 303);
});

test('path traversal reaches fake secret inside target/files', async () => {
  const pub = await get('/files?name=welcome.txt');
  assert.equal(pub.status, 200);
  const flag = await get('/files?name=' + encodeURIComponent('../secret/flag.txt'));
  assert.equal(flag.status, 200);
  assert.match(await flag.text(), /FAKE-LAB-FLAG/);
  const cfg = await get('/files?name=' + encodeURIComponent('../config/app.ini'));
  assert.equal(cfg.status, 200);
});

test('path traversal can NEVER leave target/files (sandbox guard)', async () => {
  const attempts = ['../../app.js', '../../../package.json', '../../../../../../../../etc/passwd',
    '..\\..\\app.js', 'C:\\Windows\\win.ini', '/etc/passwd', '\\\\localhost\\c$\\x', '../..', '..'];
  for (const name of attempts) {
    const res = await get('/files?name=' + encodeURIComponent(name));
    assert.ok([400, 403, 404].includes(res.status), `${name} -> ${res.status}`);
    const text = await res.text();
    assert.doesNotMatch(text, /createTargetApp|"dependencies"|root:/, name);
  }
  assert.equal(resolveLabFile('../../app.js').ok, false);
  assert.equal(resolveLabFile('a\0b').ok, false);
  assert.equal(resolveLabFile('').ok, false);
});

test('echo endpoint counts bytes and enforces 5 MB cap', async () => {
  const small = await fetch(base + '/api/echo', { method: 'POST', body: 'x'.repeat(10240), headers: { 'content-type': 'text/plain' } });
  assert.deepEqual(await small.json(), { ok: true, bytes: 10240, contentType: 'text/plain' });
  const big = await fetch(base + '/api/echo', { method: 'POST', body: Buffer.alloc(5 * 1024 * 1024 + 10, 97) }).catch(() => null);
  if (big) assert.equal(big.status, 413); // connection may be closed early instead — both are safe
});

test('malformed JSON gives a generic 400 without internals', async () => {
  const res = await fetch(base + '/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad' });
  assert.equal(res.status, 400);
  assert.equal(await res.text(), 'Bad request');
});

test('unknown route is 404', async () => {
  assert.equal((await get('/nope')).status, 404);
});
