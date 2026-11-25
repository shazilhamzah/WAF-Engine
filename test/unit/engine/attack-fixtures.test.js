'use strict';
// Protection expectations stay adverse even for known misses; evaluation must report those failures.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { engine, ctx, fromSample, ROOT } = require('./helpers');
const { buildFixtures } = require('../../../scripts/build-attack-fixtures');

const fixtures = buildFixtures();
test('all mandatory adverse fixtures exist, match the reproducible source and have valid unique samples', () => {
  const ids = new Set();
  for (const [name, fixture] of Object.entries(fixtures)) {
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(ROOT, 'fixtures', name), 'utf8')), fixture);
    for (const s of fixture.samples) {
      assert.ok(!ids.has(s.id), `duplicate id ${s.id}`);
      ids.add(s.id);
      assert.ok(s.description && s.request.path.startsWith('/'));
      assert.ok(s.request.body === null || typeof s.request.body === 'string');
      assert.equal(s.expected.verdict, 'block', `${s.id}: never relabel a miss as benign`);
      assert.equal(s.expected.categories.length, 1);
    }
  }
  const counts = (name, category) => fixtures[name].samples.filter((s) => s.expected.categories.includes(category)).length;
  assert.ok(counts('t1-attacks.json', 'sqli') >= 8);
  assert.ok(counts('t1-attacks.json', 'xss') >= 8);
  assert.ok(counts('t1-attacks.json', 'traversal') >= 6);
  assert.ok(fixtures['t2-encoding.json'].samples.length >= 12);
  assert.ok(fixtures['t5-bypass.json'].samples.length >= 12);
  assert.ok(fixtures['corpus-attack.json'].samples.length >= 60);
});

for (const name of ['t1-attacks.json', 't2-encoding.json']) {
  for (const s of fixtures[name].samples) {
    test(`${s.id}: ${s.description} is blocked with the intended category`, () => {
      const d = engine.inspect(fromSample(s.request), ctx());
      assert.equal(d.verdict, 'block', d.explanation.join(' | '));
      assert.ok(d.matches.some((m) => s.expected.categories.includes(m.category)));
    });
  }
}

test('bypass attempts preserve known limitations and never hide a new unlabelled miss', () => {
  for (const s of fixtures['t5-bypass.json'].samples) {
    const d = engine.inspect(fromSample(s.request), ctx());
    assert.ok(d.explanation.length > 0);
    if (d.verdict !== 'block') assert.ok(s.knownLimitation, `untriaged miss ${s.id}`);
    // A later engine improvement may block a documented limitation; that is welcome.
    assert.equal(s.expected.verdict, 'block');
  }
});

test('controlled attack corpus meets the intended 95 percent detection target and labels every miss', () => {
  let detected = 0;
  for (const s of fixtures['corpus-attack.json'].samples) {
    const d = engine.inspect(fromSample(s.request), ctx());
    if (d.verdict === 'block' || d.verdict === 'flag') detected++;
    else assert.ok(s.knownLimitation, `untriaged corpus miss ${s.id}`);
  }
  assert.ok(detected / fixtures['corpus-attack.json'].samples.length >= 0.95);
});
