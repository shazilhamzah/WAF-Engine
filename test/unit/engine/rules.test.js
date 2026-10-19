'use strict';
// Default rule set: compiles cleanly, documented, each category fires on a textbook string, linear time.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, ctx, getWith, defaultRules, UA } = require('./helpers');
const { loadDefaultRules } = require('../../../src/rules');

test('default.rules loads and compiles without errors (30-45 rules, unique ids)', () => {
  const { rules, errors } = loadDefaultRules();
  assert.deepEqual(errors, []);
  assert.ok(rules.length >= 30 && rules.length <= 45, `${rules.length} rules`);
  assert.equal(new Set(rules.map((r) => r.id)).size, rules.length);
  const compiled = defaultRules();
  assert.deepEqual(compiled.errors, []);
  assert.equal(compiled.rules.length, rules.length);
});

test('every default rule has a description, tags and a known category', () => {
  const cats = new Set(['sqli', 'xss', 'traversal', 'cmdi', 'protocol', 'scanner']);
  for (const r of defaultRules().rules) {
    assert.ok(r.description.length >= 20, `${r.id} description`);
    assert.ok(r.tags.length >= 1, `${r.id} tags`);
    assert.ok(cats.has(r.category), `${r.id} category ${r.category}`);
  }
  const present = new Set(defaultRules().rules.map((r) => r.category));
  assert.deepEqual([...present].sort(), [...cats].sort());
});

const TEXTBOOK = [
  ['sqli', 'q', "' OR 1=1--"],
  ['sqli', 'q', '1 UNION SELECT username, password FROM users'],
  ['sqli', 'user', "admin'--"],
  ['xss', 'q', '<script>alert(1)</script>'],
  ['xss', 'q', '<img src=x onerror=alert(1)>'],
  ['xss', 'next', 'javascript:alert(1)'],
  ['traversal', 'file', '../../etc/passwd'],
  ['traversal', 'name', '../secret/flag.txt'],
  ['traversal', 'file', '..\\..\\windows\\win.ini'],
  ['cmdi', 'host', '127.0.0.1; cat /etc/passwd'],
  ['cmdi', 'host', '127.0.0.1 | whoami'],
  ['cmdi', 'host', '$(id)'],
];

for (const [category, name, payload] of TEXTBOOK) {
  test(`${category} fires and blocks on ${JSON.stringify(payload)}`, () => {
    const d = engine.inspect(getWith(name, payload), ctx());
    assert.ok((d.score.byCategory[category] || 0) >= 5, `${category} points ${JSON.stringify(d.score.byCategory)}`);
    assert.equal(d.verdict, 'block');
    assert.ok(d.matches.every((m) => m.location === `query.${name}` || m.location.startsWith('header.')));
  });
}

test('encoded forms of textbook strings are revealed by normalization', () => {
  const cases = [
    ['/s?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E', 'xss', 'url'],
    [`/s?q=${encodeURIComponent('&lt;script&gt;alert(1)&lt;/script&gt;')}`, 'xss', 'html'],
    [`/s?q=${encodeURIComponent('＜script＞')}`, 'xss', 'nfkc'],
    [`/s?q=${encodeURIComponent('1 UN/**/ION SEL/**/ECT 1')}`, 'sqli', 'sql_comment'],
  ];
  for (const [url, category, step] of cases) {
    const d = engine.inspect({ method: 'GET', url, headers: UA }, ctx());
    const m = d.matches.find((x) => x.category === category);
    assert.ok(m, url);
    assert.ok(m.decodedVia.includes(step), `${url}: ${m.decodedVia}`);
    assert.equal(d.verdict, 'block', url);
  }
});

test('protocol and scanner rules fire on their indicators', () => {
  const trace = engine.inspect({ method: 'TRACE', url: '/', headers: UA }, ctx());
  assert.ok(trace.matches.some((m) => m.ruleId === 920100));
  const scanner = engine.inspect({ method: 'GET', url: '/', headers: { 'user-agent': 'sqlmap/1.8' } }, ctx());
  assert.ok((scanner.score.byCategory.scanner || 0) >= 5);
  assert.equal(scanner.verdict, 'block');
  const crlf = engine.inspect({ method: 'GET', url: '/r?next=%0d%0aSet-Cookie:%20a=b', headers: UA }, ctx());
  assert.ok(crlf.matches.some((m) => m.ruleId === 920110));
  const noUa = engine.inspect({ method: 'GET', url: '/', headers: {} }, ctx());
  assert.deepEqual(noUa.matches.map((m) => m.ruleId), [920120]);
  assert.equal(noUa.verdict, 'allow', 'a missing user agent alone never flags');
});

test('benign look-alikes stay below the flag threshold', () => {
  for (const text of ["O'Brien", 'Tom & Jerry', 'select a size', '1+1=2', 'I <3 cats', 'union station', 'drop shipping', 'script writing',
    'alice+news@example.com', '**bold** [link](https://example.com)', '1.5 ../ratio', 'fish & chips; cat food', 'sleep (8 hours)']) {
    const d = engine.inspect(getWith('q', text), ctx());
    assert.ok(d.score.total < 3, `${text}: ${d.score.total} ${d.matches.map((m) => m.ruleId)}`);
  }
});

test('default rules stay fast on adversarial 64 KB bodies (no catastrophic backtracking)', () => {
  const bodies = ['<'.repeat(65000), "'".repeat(65000), ' or 1'.repeat(13000), '{{'.repeat(32000), '\\'.repeat(65000), '../'.repeat(21000),
    '/*'.repeat(32000), '%'.repeat(65000), '"'.repeat(65000) + '>', "a'".repeat(32000), '<a '.repeat(20000), 'curl '.repeat(13000)];
  for (const body of bodies) {
    for (const ct of ['text/plain', 'application/x-www-form-urlencoded']) {
      const t = process.hrtime.bigint();
      engine.inspect({ method: 'POST', url: '/p', headers: { ...UA, 'content-type': ct }, body: ct === 'text/plain' ? body : `f=${body}` }, ctx());
      const ms = Number(process.hrtime.bigint() - t) / 1e6;
      assert.ok(ms < 500, `${JSON.stringify(body.slice(0, 6))} ${ct} took ${ms} ms`);
    }
  }
});
