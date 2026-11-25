'use strict';
// Regression tests for the two T5 bypasses closed on 2026-11-25:
// T5-16 (hex literal tautology, rule 942100) and T5-17 (|| concatenated string tautology, rule 942110).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, ctx, getWith, UA } = require('./helpers');
const { loadDefaultRules } = require('../../../src/rules');
const { checkRegexSafety } = require('../../../src/engine/regexguard');

const ruleIds = (d) => d.matches.map((m) => m.ruleId);

test('942100 blocks hexadecimal tautologies as well as decimal ones', () => {
  for (const payload of ['1 OR 0x31=0x31', "' or 0X61 = 0x61--", '1 AND 0x1<>0x2', '1 or 1=0x1', '1 OR 0x31=0x31 OR 1=1']) {
    const d = engine.inspect(getWith('q', payload), ctx());
    assert.ok(ruleIds(d).includes(942100), `${payload}: ${ruleIds(d)}`);
    assert.equal(d.verdict, 'block', payload);
  }
});

test('942100 still matches the original decimal tautology', () => {
  const d = engine.inspect(getWith('q', "' OR 1=1--"), ctx());
  assert.ok(ruleIds(d).includes(942100));
  assert.equal(d.verdict, 'block');
});

test('942110 blocks a quote break-out compared with a || concatenation', () => {
  for (const payload of ["' OR ('a'||'b')=('a'||'b')", `" and ( "x" || "y" ) <> ("z")`, "x' or ('ad'||'min') like ('ad'||'min')"]) {
    const d = engine.inspect(getWith('q', payload), ctx());
    assert.ok(ruleIds(d).includes(942110), `${payload}: ${ruleIds(d)}`);
    assert.equal(d.verdict, 'block', payload);
  }
});

test('the hex and concatenation variants are also caught in JSON bodies', () => {
  for (const payload of ['1 OR 0x31=0x31', "' OR ('a'||'b')=('a'||'b')"]) {
    const body = JSON.stringify({ filter: payload });
    const d = engine.inspect({ method: 'POST', url: '/api/echo', headers: { ...UA, 'content-type': 'application/json' }, body, bodyBytes: Buffer.byteLength(body) }, ctx());
    assert.equal(d.verdict, 'block', payload);
  }
});

test('benign hex values and || text do not trigger the extended tautology rules', () => {
  for (const text of ['colour 0xFF or 0x00', 'mask 0x31=0x31', 'rgb 0xff and more', 'cats || dogs', "it's ('a'||'b') nice",
    `"tea" or ("milk" + "sugar")`, "x = 'a' || 'b'", 'pick 0x10 or 16 items', 'error code 0x80070005 and retry']) {
    const d = engine.inspect(getWith('q', text), ctx());
    assert.ok(!ruleIds(d).includes(942100) && !ruleIds(d).includes(942110), `${text}: ${ruleIds(d)}`);
    assert.ok(d.score.total < 3, `${text}: ${d.score.total}`);
    assert.equal(d.verdict, 'allow', text);
  }
});

test('the extended 942100 and 942110 patterns pass the ReDoS guard and stay fast on long input', () => {
  const { rules } = loadDefaultRules();
  for (const id of [942100, 942110]) {
    const src = /matches \/(.*)\/i\s*$/m.exec(rules.find((r) => r.id === id).source)[1];
    assert.equal(checkRegexSafety(src).ok, true, `${id} rejected by the guard`);
  }
  for (const body of [' or 0x1'.repeat(9000), "' or ('a'||".repeat(5000), "'||'".repeat(12000)]) {
    const t = process.hrtime.bigint();
    engine.inspect({ method: 'POST', url: '/p', headers: { ...UA, 'content-type': 'text/plain' }, body, bodyBytes: body.length }, ctx());
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    assert.ok(ms < 500, `${JSON.stringify(body.slice(0, 8))} took ${ms} ms`);
  }
});
