'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack, findLeak } = require('../helpers/stack');
const { rawRequest } = require('../helpers/http');

function assertSafeError(r, label) {
  assert.ok(r.status >= 400, `${label}: expected an error status, got ${r.status}`);
  assert.equal(findLeak(r.text), null, `${label}: response leaks internals → ${r.text.slice(0, 200)}`);
  if ((r.headers['content-type'] || r.headers.get?.('content-type') || '').includes('json')) {
    const body = JSON.parse(r.text);
    assert.ok(body.error && typeof body.error.code === 'string', `${label}: error envelope`);
    assert.match(body.error.code, /^[A-Z_]+$/);
    assert.ok(!('stack' in body.error), `${label}: no stack property`);
  }
}

describe('safe errors and security headers', { skip: skipUnlessStack() }, () => {
  let stack, op;
  before(async () => { stack = await startStack(); op = await stack.login('operator'); });
  after(async () => { if (stack) await stack.stop(); });

  const req = (o) => rawRequest(stack.studioUrl, {
    ...o, headers: { cookie: `waf_sid=${op.sid}`, 'x-csrf-token': op.csrfToken, accept: 'application/json', ...(o.headers || {}) }
  });

  it('malformed JSON → 400 MALFORMED_JSON with requestId', async () => {
    for (const body of ['{bad json', '{"a":', '[1,2', 'null', '"just a string"', '{"__proto__":{"admin":true}}']) {
      const r = await req({ method: 'POST', path: '/api/analyze', headers: { 'content-type': 'application/json' }, body });
      assertSafeError(r, `body ${body}`);
      assert.ok([400, 422].includes(r.status), `${body} → ${r.status}`);
      const e = JSON.parse(r.text).error;
      if (body.startsWith('{bad') || body.startsWith('{"a"') || body.startsWith('[1')) assert.equal(e.code, 'MALFORMED_JSON');
      assert.match(e.requestId || '', /^req_/);
    }
  });

  it('JSON over 256 KB on ordinary endpoints → 413 PAYLOAD_TOO_LARGE', async () => {
    const big = JSON.stringify({ source: 'a'.repeat(300 * 1024) });
    const r = await req({ method: 'POST', path: '/api/rules/validate', headers: { 'content-type': 'application/json' }, body: big });
    assertSafeError(r, 'huge json');
    assert.equal(r.status, 413);
    assert.equal(JSON.parse(r.text).error.code, 'PAYLOAD_TOO_LARGE');
  });

  it('JSON over 2 MiB on analyze/import (which allow 1 MiB sample bodies) → 413', async () => {
    const big = JSON.stringify({ label: 'big', sample: { method: 'POST', path: '/', headers: {}, body: 'a'.repeat(2.5 * 1024 * 1024) } });
    const r = await req({ method: 'POST', path: '/api/analyze', headers: { 'content-type': 'application/json' }, body: big });
    assertSafeError(r, 'huge analyze json');
    assert.equal(r.status, 413);
    assert.equal(JSON.parse(r.text).error.code, 'PAYLOAD_TOO_LARGE');
  });

  it('deeply nested JSON does not crash the server', async () => {
    const deep = '{"a":'.repeat(5000) + '1' + '}'.repeat(5000);
    const r = await req({ method: 'POST', path: '/api/analyze', headers: { 'content-type': 'application/json' }, body: deep });
    assertSafeError(r, 'deep json');
    assert.ok(r.status < 500, `deep json → ${r.status}`);
    assert.equal((await op.get('/api/auth/me')).status, 200, 'server still alive');
  });

  it('wrong content type → 415 UNSUPPORTED_MEDIA_TYPE', async () => {
    for (const ct of ['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'application/xml']) {
      const r = await req({ method: 'POST', path: '/api/analyze', headers: { 'content-type': ct }, body: 'label=x' });
      assertSafeError(r, ct);
      assert.equal(r.status, 415, `${ct} → ${r.status}`);
      assert.equal(JSON.parse(r.text).error.code, 'UNSUPPORTED_MEDIA_TYPE');
    }
  });

  it('weird methods and unknown routes → 404/405/501 with no internals', async () => {
    const cases = [['TRACE', '/api/events'], ['PATCH', '/api/analyze'], ['PROPFIND', '/api/'], ['DELETE', '/api/events'],
      ['GET', '/api/does-not-exist'], ['GET', '/api/../../etc/passwd'], ['GET', '/api/events/%E0%A4%A'], ['OPTIONS', '/api/config']];
    for (const [method, path] of cases) {
      const r = await req({ method, path, headers: { 'content-type': 'application/json' }, body: method === 'GET' || method === 'OPTIONS' || method === 'TRACE' ? null : '{}' });
      if (method === 'OPTIONS' && r.status < 400) continue; // a preflight answer without cors headers is fine
      assertSafeError(r, `${method} ${path}`);
      assert.ok([400, 403, 404, 405, 501].includes(r.status), `${method} ${path} → ${r.status}`);
    }
  });

  it('invalid sample fields → 400 VALIDATION_FAILED with field details', async () => {
    const bad = [
      { sample: { method: 'FOO', path: '/', headers: {}, body: null } },
      { sample: { method: 'GET', path: 'no-leading-slash', headers: {}, body: null } },
      { sample: { method: 'GET', path: '/' + 'a'.repeat(5000), headers: {}, body: null } },
      { sample: { method: 'GET', path: '/', headers: { 'bad header name': 'x' }, body: null } },
      { sample: { method: 'GET', path: '/', headers: Object.fromEntries(Array.from({ length: 60 }, (_, i) => ['h' + i, 'v'])), body: null } },
      { sample: { method: 'GET', path: '/', headers: {}, body: 12345 } },
      { sample: 'not an object' },
      {}
    ];
    for (const b of bad) {
      const r = await op.post('/api/analyze', b);
      assertSafeError({ ...r, headers: { 'content-type': r.headers.get('content-type') } }, JSON.stringify(b).slice(0, 50));
      assert.equal(r.status, 400, `${JSON.stringify(b).slice(0, 80)} → ${r.status}`);
      assert.equal(r.body.error.code, 'VALIDATION_FAILED');
      assert.ok(Array.isArray(r.body.error.details));
    }
  });

  it('malformed API input is audited as request.rejected', async () => {
    const admin = await stack.login('admin');
    const r = await admin.get('/api/audit?action=request.rejected&limit=50');
    assert.equal(r.status, 200);
    assert.ok(r.body.items.length >= 1, 'request.rejected events recorded');
  });

  it('Studio responses carry security headers (CSP, nosniff, frame, referrer) and no X-Powered-By', async () => {
    for (const path of ['/', '/api/health', '/api/events']) {
      const r = await rawRequest(stack.studioUrl, { path, headers: { cookie: `waf_sid=${op.sid}` } });
      const h = r.headers;
      const csp = h['content-security-policy'] || '';
      assert.match(csp, /default-src 'self'|default-src 'none'/, `${path} CSP`);
      assert.doesNotMatch(csp, /'unsafe-inline'[^;]*script|script-src[^;]*'unsafe-eval'/, `${path} CSP must not allow unsafe inline scripts`);
      assert.equal(h['x-content-type-options'], 'nosniff', `${path} nosniff`);
      assert.ok(/frame-ancestors 'none'|frame-ancestors 'self'/.test(csp) || /DENY|SAMEORIGIN/i.test(h['x-frame-options'] || ''), `${path} framing`);
      assert.ok(h['referrer-policy'], `${path} referrer-policy`);
      assert.equal(h['x-powered-by'], undefined, `${path} x-powered-by hidden`);
    }
  });

  it('API responses with session data are not cacheable', async () => {
    const r = await rawRequest(stack.studioUrl, { path: '/api/auth/me', headers: { cookie: `waf_sid=${op.sid}` } });
    assert.match(r.headers['cache-control'] || '', /no-store/);
  });

  it('studio and proxy listen on loopback only', () => {
    for (const s of [stack.raw.studio, stack.raw.proxy, stack.raw.target]) {
      const srv = s && (typeof s.address === 'function' ? s : s.server);
      if (srv && typeof srv.address === 'function') assert.ok(['127.0.0.1', '::1'].includes(srv.address().address), srv.address().address);
    }
  });

  it('proxy: malformed / hostile requests fail safely without internals', async () => {
    const cases = [
      { path: '/' + 'a'.repeat(9000) },
      { path: '/search?q=%' },
      { path: '/search?q=%ZZ%E0%A4' },
      { method: 'TRACE', path: '/' },
      { path: '/search', headers: Object.fromEntries(Array.from({ length: 150 }, (_, i) => ['x-h' + i, 'v'])) }
    ];
    for (const c of cases) {
      const r = await stack.proxy(c);
      assert.ok(r.status > 0, `${c.method || 'GET'} ${c.path.slice(0, 40)} got a response`);
      assert.ok(r.status < 500 || r.status === 502, `${c.path.slice(0, 40)} → ${r.status}`);
      assert.equal(findLeak(r.text), null, `${c.path.slice(0, 40)} leaks internals`);
    }
  });
});
