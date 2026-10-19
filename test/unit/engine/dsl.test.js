'use strict';
// FR-2 rule DSL: valid rules, every error class with line/col, ReDoS refusal, file parsing, compiling.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine } = require('./helpers');

const VALID = String.raw`rule 942100 "SQLi boolean tautology" {
  when args matches /\b(or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i
  severity critical
  score 5
  category sqli
  tags sqli, owasp-a03
  description "Tautology used to bypass WHERE clauses"
}`;

function rule(when, extra = 'severity low\n  score 1\n  category test') {
  return `rule 5000 "t" {\n  when ${when}\n  ${extra}\n}`;
}
function firstError(src) {
  const res = engine.validateRuleSource(src);
  assert.equal(res.ok, false, `expected errors for: ${src}`);
  assert.equal(res.rule, null);
  return res.errors[0];
}

test('the contract example rule validates and reports its metadata', () => {
  const res = engine.validateRuleSource(VALID);
  assert.equal(res.ok, true);
  assert.deepEqual(res.errors, []);
  assert.deepEqual(res.rule, {
    id: 942100, name: 'SQLi boolean tautology', severity: 'critical', score: 5, category: 'sqli',
    tags: ['sqli', 'owasp-a03'], description: 'Tautology used to bypass WHERE clauses', targets: ['args'], operators: ['matches'],
  });
});

test('every target and operator is accepted', () => {
  const ok = [
    'path matches /x/', 'path_raw contains "%2e"', 'query startswith "a"', 'args endswith "z"', 'arg_names equals "id"',
    'body contains "x"', 'headers contains "x"', 'header:x-forwarded-for matches /\\d/', 'cookies in ["a", "b"]',
    'method in ["GET", "POST"]', 'user_agent matches /curl/i', 'content_type startswith "text/"', 'body_size gt 10',
    'body_size lt 10', 'body_size ge 1', 'body_size le 1', 'body_size equals 0', 'body_size in [1, 2]', 'args gt 100',
    'not method equals "GET"', 'args contains "a" and (path contains "b" or not cookies contains "c")', 'args, cookies matches /x/',
  ];
  for (const when of ok) {
    const res = engine.validateRuleSource(rule(when));
    assert.equal(res.ok, true, `${when}: ${JSON.stringify(res.errors)}`);
  }
});

test('comments, blank lines and clause order do not matter', () => {
  const src = '# leading comment\nrule 1234 "x" { # trailing\n  category c\n\n  score 0\n  severity medium\n  when args contains "a" # cmt\n}\n';
  assert.equal(engine.validateRuleSource(src).ok, true);
});

test('unknown keyword is reported with line, column and a suggestion', () => {
  const e = firstError('rule 5000 "t" {\n  when args contains "a"\n  severty low\n  score 1\n  category c\n}');
  assert.equal(e.line, 3);
  assert.equal(e.col, 3);
  assert.match(e.message, /Unknown keyword 'severty'.*did you mean 'severity'/);
});

test('unknown target is reported with line and column', () => {
  const e = firstError(rule('argz contains "a"'));
  assert.deepEqual([e.line, e.col], [2, 8]);
  assert.match(e.message, /Unknown target 'argz'.*'args'/);
});

test('unknown operator is reported with line and column', () => {
  const e = firstError(rule('args matchez /a/'));
  assert.deepEqual([e.line, e.col], [2, 13]);
  assert.match(e.message, /Unknown operator 'matchez'/);
});

test('missing required clauses are reported', () => {
  const res = engine.validateRuleSource('rule 5000 "t" {\n  when args contains "a"\n}');
  assert.equal(res.ok, false);
  const msgs = res.errors.map((e) => e.message).join('\n');
  for (const f of ['severity', 'score', 'category']) assert.match(msgs, new RegExp(`Missing required '${f}'`));
  assert.ok(res.errors.every((e) => e.line === 3 && e.col === 1));
});

test('severity enum, score range and id range are enforced', () => {
  const sev = firstError(rule('args contains "a"', 'severity huge\n  score 1\n  category c'));
  assert.match(sev.message, /Unknown severity 'huge'/);
  assert.equal(sev.line, 3);
  assert.match(firstError(rule('args contains "a"', 'severity low\n  score 101\n  category c')).message, /Score must be an integer between 0 and 100/);
  assert.match(firstError(rule('args contains "a"', 'severity low\n  score -1\n  category c')).message, /Score must be/);
  assert.match(firstError('rule 999 "t" { when args contains "a" severity low score 1 category c }').message, /between 1000 and 999999/);
  assert.match(firstError('rule 1000000 "t" { when args contains "a" severity low score 1 category c }').message, /between 1000 and 999999/);
});

test('duplicate clauses, empty strings and malformed lists are rejected', () => {
  assert.match(firstError(rule('args contains "a"', 'severity low\n  severity high\n  score 1\n  category c')).message, /Duplicate 'severity'/);
  assert.match(firstError(rule('args contains ""')).message, /must not be empty/);
  assert.match(firstError(rule('method in []')).message, /must not be empty/);
  assert.match(firstError(rule('method in ["GET" "POST"]')).message, /Expected ',' or ']'/);
});

test('syntax errors: unterminated string, unterminated regex, missing brace, stray characters', () => {
  const s = firstError('rule 5000 "t {\n}');
  assert.deepEqual([s.line, s.col], [1, 11]);
  assert.match(s.message, /Unterminated string/);
  assert.match(firstError(rule('args matches /abc')).message, /Unterminated regular expression/);
  assert.match(firstError('rule 5000 "t" {\n  when args contains "a"\n  severity low score 1 category c\n').message, /Missing '}'/);
  const stray = firstError(rule('args contains "a" ;'));
  assert.match(stray.message, /Unexpected character ';'/);
  assert.match(firstError(rule('args contains "a"') + '\nrule 5001 "u" {}').message, /after the end of the rule/);
});

test('type errors: numeric target with text operator and text target with numbers', () => {
  assert.match(firstError(rule('body_size matches /1/')).message, /numeric target body_size/);
  assert.match(firstError(rule('body_size equals "1"')).message, /needs a number/);
  assert.match(firstError(rule('args equals 1')).message, /needs a numeric target/);
});

test('regex compile errors and disallowed flags are reported at the regex', () => {
  const e = firstError(rule('args matches /(a/'));
  assert.equal(e.line, 2);
  assert.equal(e.col, 21);
  assert.match(e.message, /Invalid regular expression/);
  assert.match(firstError(rule('args matches /a/g')).message, /flag 'g' is not allowed/);
  assert.match(firstError(rule('args matches /a/ii')).message, /must not repeat/);
});

test('ReDoS guard refuses nested quantifiers, overlapping alternation, backreferences in repetition and long patterns', () => {
  const unsafe = ['(a+)+', '(a*)*b', '(\\w+\\s?)*$', '(a|a)*', '(ab|ac)+', '(a|)*', '(a)\\1+', '((a)\\2)*', '.*.*x', '\\w+\\w*', 'x'.repeat(501)];
  for (const p of unsafe) {
    const res = engine.validateRuleSource(rule(`args matches /${p}/`));
    assert.equal(res.ok, false, p);
    assert.match(res.errors[0].message, /Unsafe regular expression|longer than 500/, p);
    assert.equal(res.errors[0].line, 2);
  }
  for (const p of ['(\\d{1,3}\\.){3}\\d{1,3}', '<\\s{0,5}script\\b', '(?:or|and)\\s+\\d', '(a)\\1', '[^>]{0,200}on\\w{1,20}=']) {
    assert.equal(engine.validateRuleSource(rule(`args matches /${p}/`)).ok, true, p);
  }
});

test('non-string or oversized source is rejected', () => {
  assert.match(engine.validateRuleSource(null).errors[0].message, /must be a string/);
  assert.match(engine.validateRuleSource('').errors[0].message, /empty/);
  assert.match(engine.validateRuleSource('#'.repeat(10001)).errors[0].message, /longer than/);
});

test('parseRuleFile splits a multi-rule file and reports file-relative errors', () => {
  const text = `# header comment\n${VALID}\n\n# next\n${rule('args contains "a"').replace('5000', '5001')}\n\nrule 5002 "bad" {\n  when argz contains "x"\n  severity low score 1 category c\n}\n`;
  const res = engine.parseRuleFile(text);
  assert.deepEqual(res.rules.map((r) => r.id), [942100, 5001]);
  assert.equal(engine.validateRuleSource(res.rules[0].source).ok, true);
  assert.ok(!res.rules[0].source.includes('# next'), 'trailing comments belong to the next rule');
  assert.equal(res.errors.length, 1);
  assert.equal(res.errors[0].ruleId, 5002);
  assert.equal(res.errors[0].line, text.split('\n').findIndex((l) => l.includes('argz')) + 1);
  const dup = engine.parseRuleFile(`${VALID}\n${VALID}`);
  assert.equal(dup.rules.length, 1);
  assert.match(dup.errors[0].message, /Duplicate rule id 942100/);
  assert.match(engine.parseRuleFile('hello\n').errors[0].message, /Expected 'rule'/);
});

test('compileRules skips disabled rules, reports id mismatch and duplicates, and versions the ruleset', () => {
  const a = { id: 942100, source: VALID, enabled: true, version: 1 };
  const res = engine.compileRules([a, { ...a }, { id: 5000, source: rule('args contains "x"'), enabled: false, version: 1 },
    { id: 7777, source: rule('args contains "y"'), enabled: true, version: 1 }, { id: 6000, source: 'rule 6000 "x" {', enabled: true }]);
  assert.deepEqual(res.rules.map((r) => r.id), [942100]);
  const msgs = res.errors.map((e) => `${e.ruleId}: ${e.message}`);
  assert.ok(msgs.some((m) => /942100: Duplicate rule id/.test(m)));
  assert.ok(msgs.some((m) => /7777: Rule id 5000 in the source does not match the record id 7777/.test(m)));
  assert.ok(res.errors.some((e) => e.ruleId === 6000 && e.line === 1));
  assert.match(res.rulesetVersion, /^[0-9a-f]{16}$/);
  const r = res.rules[0];
  assert.equal(r.version, 1);
  assert.equal(typeof r.test, 'function');
});

test('rulesetVersion changes with rule version or source and ignores disabled rules and order', () => {
  const a = { id: 942100, source: VALID, enabled: true, version: 1 };
  const b = { id: 5000, source: rule('args contains "x"'), enabled: true, version: 1 };
  const v1 = engine.compileRules([a, b]).rulesetVersion;
  assert.equal(engine.compileRules([b, a]).rulesetVersion, v1);
  assert.notEqual(engine.compileRules([a, { ...b, version: 2 }]).rulesetVersion, v1);
  assert.notEqual(engine.compileRules([a, { ...b, source: rule('args contains "y"') }]).rulesetVersion, v1);
  assert.equal(engine.compileRules([a, b, { id: 5001, source: rule('args contains "z"').replace('5000', '5001'), enabled: false }]).rulesetVersion, v1);
  assert.equal(engine.compileRules([]).rulesetVersion, engine.compileRules(null).rulesetVersion);
});

test('compiled operators behave as documented (case-insensitive strings, length comparison)', () => {
  const mk = (id, when) => ({ id, source: rule(when).replace('5000', String(id)), enabled: true, version: 1 });
  const { rules } = engine.compileRules([
    mk(5001, 'args contains "SeLeCt"'), mk(5002, 'args equals "abc"'), mk(5003, 'args startswith "ab"'), mk(5004, 'args endswith "BC"'),
    mk(5005, 'args in ["x", "ABC"]'), mk(5006, 'args gt 2'), mk(5007, 'args lt 2'), mk(5008, 'method equals "get"'), mk(5009, 'not cookies contains "x"'),
  ]);
  const d = engine.inspect({ method: 'GET', url: '/?a=ABC&b=select', headers: { 'user-agent': 'x' } }, { rules });
  const ids = d.matches.concat(d.suppressed).map((m) => m.ruleId).sort();
  assert.deepEqual(ids, [5001, 5002, 5003, 5004, 5005, 5006, 5008, 5009]);
});
