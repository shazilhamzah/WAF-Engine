'use strict';
/**
 * Injection & output-encoding defences in the Studio itself (NFR-4, contract §8):
 *  - SQLi strings in API filters (q, verdict, ruleId, from/to, limit/offset) never break queries
 *  - stored XSS payloads (labels, paths, headers) come back as inert JSON data, and the HTML export escapes them
 *  - CSV export neutralises formula injection (= + - @ prefixed with ')
 *  - identifiers are generated server-side (client-supplied ids ignored)
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack, findLeak } = require('../helpers/stack');
const { analyze } = require('../helpers/api');

const XSS = '<script>alert("waf-xss")</script>';
const IMG = '<img src=x onerror=alert(1)>';
const FORMULAS = ['=HYPERLINK("http://evil.invalid","x")', '+cmd|\' /C calc\'!A0', '-2+3+cmd|\' /C calc\'!A0', '@SUM(1+1)*cmd|\' /C calc\'!A0'];

/** Minimal RFC-4180 CSV parser (quoted fields, doubled quotes, CRLF/LF). */
function parseCsv(text) {
  const rows = []; let row = []; let field = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (q) {
      if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (ch === '"') q = false; else field += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { row.push(field); field = ''; } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      row.push(field); rows.push(row); row = []; field = '';
    } else field += ch;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

describe('injection and output encoding', { skip: skipUnlessStack() }, () => {
  let stack, operator, admin;
  const ids = [];
  before(async () => {
    stack = await startStack();
    operator = await stack.login('operator');
    admin = await stack.login('admin');
    ids.push((await analyze(operator, { path: '/search?q=' + encodeURIComponent(IMG), headers: { 'user-agent': XSS } }, XSS)).id);
    for (const f of FORMULAS) ids.push((await analyze(operator, { path: '/search?q=formula' }, f)).id);
  });
  after(async () => { if (stack) await stack.stop(); });

  const SQLI = ["' OR '1'='1", "1; DROP TABLE events; --", "' UNION SELECT password_hash FROM users --", '%', '_', '\\', "evt_'||'", '" OR ""="'];

  it('SQLi strings in event filters return 200/400, never 500, and never dump other rows', async () => {
    const total = (await admin.get('/api/events?limit=1')).body.total;
    for (const s of SQLI) {
      for (const param of ['q', 'verdict', 'action', 'source', 'ruleId', 'from', 'to', 'limit', 'offset']) {
        const r = await admin.get(`/api/events?${param}=${encodeURIComponent(s)}`);
        assert.ok([200, 400].includes(r.status), `${param}=${s} → ${r.status}`);
        assert.equal(findLeak(r.text), null, `${param}=${s} leaks internals`);
        if (r.status === 200 && param === 'q') assert.ok(r.body.total <= total);
        assert.doesNotMatch(r.text, /scrypt|password_hash|\$scrypt/i);
      }
    }
    const still = await admin.get('/api/events?limit=1');
    assert.equal(still.body.total, total, 'events table intact');
  });

  it('SQLi strings in audit filters and usernames are harmless', async () => {
    for (const s of SQLI) {
      const r = await admin.get(`/api/audit?actor=${encodeURIComponent(s)}&action=${encodeURIComponent(s)}`);
      assert.ok([200, 400].includes(r.status), `audit ${s} → ${r.status}`);
      assert.equal(findLeak(r.text), null);
    }
    const u = await admin.post('/api/users', { username: "x'); DROP TABLE users; --", password: 'Some-Long-Passw0rd!', role: 'viewer' });
    assert.ok([201, 400].includes(u.status), `odd username → ${u.status}`);
    assert.equal((await admin.get('/api/users')).status, 200, 'users table intact');
  });

  it('LIKE wildcards in q are treated literally (no match-everything)', async () => {
    const r = await admin.get('/api/events?q=' + encodeURIComponent('%'));
    assert.equal(r.status, 200);
    const all = await admin.get('/api/events?limit=1');
    assert.ok(r.body.total < all.body.total || all.body.total === 0, '% must not match every event');
  });

  it('client-supplied ids are ignored (ids generated server-side)', async () => {
    const r = await operator.post('/api/analyze', { id: 'evt_attacker', label: 'id test', sample: { method: 'GET', path: '/x', headers: {}, body: null } });
    assert.ok([201, 400].includes(r.status));
    if (r.status === 201) assert.notEqual(r.body.event.id, 'evt_attacker');
  });

  it('stored XSS payloads are returned as inert JSON data', async () => {
    const r = await operator.get('/api/events/' + ids[0]);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /application\/json/);
    assert.equal(r.body.event.label, XSS, 'label stored as data');
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  });

  it('HTML export escapes every stored payload', async () => {
    const r = await operator.get('/api/reports/export?format=html&ids=' + ids.join(','));
    assert.equal(r.status, 200);
    assert.ok(!r.text.includes(XSS), 'raw <script> payload must not appear');
    assert.ok(!r.text.includes(IMG), 'raw <img onerror> payload must not appear');
    assert.ok(!/<script[\s>]/i.test(r.text), 'no script elements at all');
    assert.ok(!/<[a-z][^>]*\son[a-z]+\s*=/i.test(r.text), 'no inline event handlers');
    assert.ok(r.text.includes('&lt;script&gt;') || r.text.includes('&lt;script'), 'payload present but escaped');
  });

  it('CSV export neutralises formula injection', async () => {
    const r = await operator.get('/api/reports/export?format=csv&ids=' + ids.join(','));
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type') || '', /csv/);
    const rows = parseCsv(r.text);
    assert.ok(rows.length >= 2);
    for (const row of rows) {
      for (const cell of row) assert.ok(!/^[=+\-@\t\r]/.test(cell) || /^-?\d+(\.\d+)?$/.test(cell), `dangerous cell: ${cell.slice(0, 60)}`);
    }
    const cells = rows.flat();
    for (const f of FORMULAS) {
      assert.ok(!cells.includes(f), `raw formula exported: ${f}`);
      if (cells.some((c) => c.includes(f))) assert.ok(cells.includes("'" + f), `formula label exported with a leading apostrophe: ${f}`);
    }
  });

  it('JSON export is valid JSON and does not contain raw secrets/excess data', async () => {
    const r = await operator.get('/api/reports/export?format=json&ids=' + ids.join(','));
    assert.equal(r.status, 200);
    const parsed = JSON.parse(r.text);
    assert.ok(parsed);
    assert.doesNotMatch(r.text, /password_hash|token_hash|csrf/i);
  });

  it('export rejects unknown formats', async () => {
    const r = await operator.get('/api/reports/export?format=exe');
    assert.equal(r.status, 400);
  });
});
