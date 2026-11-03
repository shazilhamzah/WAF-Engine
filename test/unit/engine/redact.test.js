'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, ctx } = require('./helpers');

const SECRETS = ['hunter2-secret-pw', 'tok_9f8e7d6c5b4a', 'sess-abcdef123456', 'Basic dXNlcjpwYXNz', 'key-777-xyz', '4111111111111111'];

test('redact masks sensitive headers and secret-looking fields deeply without mutating the input', () => {
  const input = {
    method: 'POST',
    headers: { authorization: 'Bearer abc', cookie: 'sid=1', 'set-cookie': 'a=b', 'proxy-authorization': 'x', 'x-api-key': 'k', accept: '*/*' },
    body: { user: 'ann', password: 'p', nested: { apiKey: 'k2', api_key: 'k3', sessionId: 's', creditCard: 'c', cvv: '1', ssn: '2', note: 'ok' }, list: [{ token: 't' }] },
  };
  const copy = JSON.parse(JSON.stringify(input));
  const out = engine.redact(input);
  assert.deepEqual(input, copy, 'input unchanged');
  for (const h of ['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key']) assert.equal(out.headers[h], '[REDACTED]', h);
  assert.equal(out.headers.accept, '*/*');
  assert.equal(out.body.password, '[REDACTED]');
  for (const k of ['apiKey', 'api_key', 'sessionId', 'creditCard', 'cvv', 'ssn']) assert.equal(out.body.nested[k], '[REDACTED]', k);
  assert.equal(out.body.nested.note, 'ok');
  assert.equal(out.body.list[0].token, '[REDACTED]');
});

test('redact masks secrets embedded in query strings, form bodies, JSON text and auth schemes', () => {
  const out = engine.redact({
    path: '/login?user=ann&password=hunter2&next=/home',
    body: 'username=ann&pwd=s3cr3t&remember=1',
    json: '{"user":"ann","token":"abc123","n":1}',
    note: 'header was Authorization: Bearer abc.def.ghi',
  });
  assert.equal(out.path, '/login?user=ann&password=[REDACTED]&next=/home');
  assert.equal(out.body, 'username=ann&pwd=[REDACTED]&remember=1');
  assert.equal(out.json, '{"user":"ann","token":"[REDACTED]","n":1}');
  assert.ok(!out.note.includes('abc.def.ghi'));
});

test('redact handles cycles, depth, buffers and odd values without throwing', () => {
  const a = { name: 'x' };
  a.self = a;
  let deep = {};
  const root = deep;
  for (let i = 0; i < 50; i++) deep = deep.next = {};
  const out = engine.redact({ a, root, buf: Buffer.from('abc'), body: Buffer.from('password=x'), fn() {}, n: 1n, d: new Date(0), u: undefined });
  assert.equal(out.a.self, '[CIRCULAR]');
  assert.ok(JSON.stringify(out.root).includes('[TRUNCATED]'));
  assert.equal(out.buf, '[3 bytes]');
  assert.equal(out.body, 'password=[REDACTED]');
  assert.equal(out.n, '1');
  assert.equal(out.d, '1970-01-01T00:00:00.000Z');
  assert.ok(!('fn' in out));
  for (const v of [null, undefined, 1, 'x', true]) assert.doesNotThrow(() => engine.redact(v));
});

test('excerpt is at most 120 characters and escapes control, bidi and invisible characters', () => {
  const long = 'a'.repeat(500) + 'MATCH' + 'b'.repeat(500);
  const ex = engine.excerpt(long, 500, 5);
  assert.ok(ex.length <= 120);
  assert.ok(ex.includes('MATCH'));
  assert.ok(ex.startsWith('…') && ex.endsWith('…'));
  const ctl = engine.excerpt('a\r\nb\u0000c\u001bd‮e​f\u0085', 0, 0);
  assert.equal(ctl, 'a\\r\\nb\\x00c\\x1bd\\u202ee\\u200bf\\x85');
  assert.equal(engine.excerpt('\n'.repeat(500), 0, 0).length <= 120, true);
  assert.equal(engine.excerpt(null), '');
  assert.equal(engine.excerpt(12345, 2, 1), '12345');
  assert.equal(engine.excerpt('short', 99, 99), 'short');
});

test('decisions never contain secret values from headers, cookies or sensitive parameters', () => {
  const body = `username=ann&password=${SECRETS[0]}&comment=${encodeURIComponent("' OR 1=1")}`;
  const raw = {
    method: 'POST',
    url: `/login?api_key=${SECRETS[4]}&card=${SECRETS[5]}&q=${encodeURIComponent('<script>alert(1)</script>')}`,
    headers: {
      'user-agent': 'Mozilla/5.0 (unit)', 'content-type': 'application/x-www-form-urlencoded',
      authorization: SECRETS[3], cookie: `sid=${SECRETS[2]}; theme=dark`, 'x-api-key': SECRETS[1],
    },
    body,
  };
  for (const config of [engine.DEFAULT_CONFIG, { ...engine.DEFAULT_CONFIG, mode: 'monitor' }]) {
    const d = engine.inspect(raw, ctx({ config }));
    assert.equal(d.verdict, 'block');
    const json = JSON.stringify(d);
    for (const s of SECRETS) assert.ok(!json.includes(s), `decision leaked ${s}`);
  }
});

test('a payload inside a sensitive field is detected but its excerpt is redacted', () => {
  const raw = { method: 'POST', url: '/login', headers: { 'user-agent': 'x', 'content-type': 'application/x-www-form-urlencoded' }, body: `username=bob&password=${encodeURIComponent("x' OR 1=1--")}` };
  const d = engine.inspect(raw, ctx());
  const m = d.matches.find((x) => x.location === 'body.password');
  assert.ok(m, 'rule fired on body.password');
  assert.equal(m.excerpt, '[REDACTED]');
  assert.ok(!JSON.stringify(d).includes("x' OR 1=1"));
});

test('raw body excerpts mask secret parameters around the match', () => {
  const raw = { method: 'POST', url: '/x', headers: { 'user-agent': 'x', 'content-type': 'text/plain' }, body: `password=${SECRETS[0]} <script>alert(1)</script>` };
  const d = engine.inspect(raw, ctx());
  const m = d.matches.find((x) => x.ruleId === 941100);
  assert.equal(m.location, 'body');
  assert.ok(m.excerpt.includes('<script'));
  assert.ok(!JSON.stringify(d).includes(SECRETS[0]));
});

test('request summary has no raw header values except a truncated user agent', () => {
  const ua = 'U'.repeat(300);
  const d = engine.inspect({ method: 'GET', url: '/a?b=c', headers: { 'user-agent': ua, referer: 'http://secret.example/x', 'x-custom': 'zzz-private' } }, ctx());
  assert.equal(d.request.userAgent.length, 80);
  const json = JSON.stringify(d.request);
  assert.ok(!json.includes('secret.example'));
  assert.ok(!json.includes('zzz-private'));
});
