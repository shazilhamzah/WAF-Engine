'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

const LIB = path.join(__dirname, '..', '..', '..', 'public', 'js', 'lib');
const load = (name) => import(pathToFileURL(path.join(LIB, `${name}.js`)).href);

test('errors: stable codes map to friendly messages; 403 and login failures stay generic', async () => {
  const { messageFor, describeError, ERROR_MESSAGES } = await load('errors');
  const codes = ['VALIDATION_FAILED', 'MALFORMED_JSON', 'AUTH_REQUIRED', 'AUTH_INVALID', 'SESSION_EXPIRED', 'FORBIDDEN',
    'CSRF_INVALID', 'NOT_FOUND', 'CONFLICT', 'PAYLOAD_TOO_LARGE', 'UNSUPPORTED_MEDIA_TYPE', 'CONFIRMATION_REQUIRED',
    'RATE_LIMITED', 'INTERNAL_ERROR'];
  for (const c of codes) assert.ok(ERROR_MESSAGES[c], `message for ${c}`);
  assert.equal(messageFor('AUTH_INVALID'), 'Invalid username or password.');
  assert.equal(messageFor(undefined, 500), ERROR_MESSAGES.INTERNAL_ERROR);
  assert.equal(messageFor('SOMETHING_NEW', 404), ERROR_MESSAGES.NOT_FOUND);
  // a 403 never echoes server text (could reveal record content)
  assert.equal(describeError({ status: 403, code: 'FORBIDDEN', serverMessage: 'secret record 42' }), ERROR_MESSAGES.FORBIDDEN);
  assert.equal(describeError({ status: 429, code: 'RATE_LIMITED', retryAfter: 7.2 }), 'Too many requests. Try again in 8 seconds.');
  assert.match(describeError({ status: 400, code: 'VALIDATION_FAILED', details: [{ field: 'path', message: "must start with '/'" }] }), /path: must start with/);
  assert.match(describeError({ status: 500, code: 'INTERNAL_ERROR', requestId: 'req_1' }), /reference req_1/);
  assert.equal(describeError(null), 'Unknown error.');
});

test('format: timestamps, numbers, badges always carry text + icon', async () => {
  const f = await load('format');
  assert.equal(f.formatTs(null), '—');
  assert.equal(f.formatTs('not a date'), '—');
  assert.match(f.formatTs('2026-10-19T10:00:00.000Z'), /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  assert.equal(f.formatMs(0.5), '0.50 ms');
  assert.equal(f.formatMs(1500), '1.50 s');
  assert.equal(f.formatMs(undefined), '—');
  assert.equal(f.formatBytes(2048), '2.0 KB');
  assert.equal(f.truncate('abcdef', 4), 'abc…');
  assert.equal(f.shortHash('sha256-0123456789abcdef', 8), 'sha256-0…');
  for (const v of ['allow', 'flag', 'block']) {
    const info = f.verdictInfo(v);
    assert.ok(info.icon && info.text === v && info.tone);
  }
  assert.equal(f.verdictInfo('<script>').text, '<script>', 'unknown values pass through as text (rendered with textContent)');
  assert.equal(f.actionInfo('logged').text, 'logged (monitor)');
  assert.equal(f.modeInfo('monitor').text, 'Monitoring only');
  assert.equal(f.modeInfo('block').tone, 'ok', 'normal blocking mode is a healthy state, not an error');
  assert.equal(f.percent(5, 10), 50);
  assert.equal(f.percent(50, 10), 100);
  assert.equal(f.scoreScaleMax({ total: 3, blockThreshold: 5 }), 10);
  assert.equal(f.scoreScaleMax({ total: 40, blockThreshold: 5 }), 40);
  assert.equal(f.dateInputToIso('bad'), '');
  const start = new Date(f.dateInputToIso('2026-10-19'));
  const end = new Date(f.dateInputToIso('2026-10-19', true));
  assert.ok(end > start);
  assert.equal(f.hourLabel(7), '07');
});

test('roles: UI mirrors the contract §2 matrix', async () => {
  const { can, navFor, canOpenRoute, rolesForRoute } = await load('roles');
  assert.deepEqual(navFor('viewer').map((n) => n.route), ['dashboard', 'events']);
  assert.equal(canOpenRoute('viewer', 'account'), true, 'Account remains available in the user header');
  assert.ok(!navFor('operator').some((n) => ['audit', 'users'].includes(n.route)));
  assert.ok(navFor('admin').some((n) => n.route === 'audit'));
  assert.equal(can('viewer', 'events.detail'), false);
  assert.equal(can('operator', 'events.detail'), true);
  assert.equal(can('operator', 'rules.write'), false);
  assert.equal(can('operator', 'rules.validate'), true);
  assert.equal(can('operator', 'exceptions.review'), false);
  assert.equal(can('admin', 'exceptions.review'), true);
  assert.equal(can('operator', 'reports.export'), true);
  assert.equal(can('viewer', 'reports.export'), false);
  assert.equal(can('operator', 'config.write'), false);
  assert.equal(can('nobody', 'dashboard.view'), false);
  assert.equal(canOpenRoute('viewer', 'event'), false);
  assert.equal(canOpenRoute('viewer', 'compare'), false);
  assert.equal(canOpenRoute('admin', 'unknown-route'), false);
  assert.deepEqual(rolesForRoute('audit'), ['admin']);
});

test('dashboard: outcome cards do not double-count flagged inspections', async () => {
  const { summarizeOutcomes } = await load('dashboard');
  const t = summarizeOutcomes({ requests: 20, allowed: 12, blocked: 5, logged: 3, flagged: 4 });
  assert.deepEqual(t, { total: 20, passed: 15, blocked: 5, flagged: 4, monitored: 3 });
  assert.equal(t.passed + t.blocked, t.total, 'flagged is a subset, never an extra traffic bucket');
  assert.equal(summarizeOutcomes().total, 0);
});

test('dashboard: one outcome preserves monitor and soft-flag distinctions', async () => {
  const { eventOutcome } = await load('dashboard');
  assert.equal(eventOutcome({ action: 'blocked', verdict: 'block' }).text, 'Blocked');
  assert.equal(eventOutcome({ action: 'logged', verdict: 'block' }).text, 'Would block · monitor');
  assert.equal(eventOutcome({ action: 'allowed', verdict: 'flag' }).text, 'Flagged · passed');
  assert.equal(eventOutcome({ action: 'allowed', verdict: 'allow' }).text, 'Passed');
  assert.equal(eventOutcome({ action: 'unknown' }).text, 'Unknown outcome');
});

test('navigation: grouped destinations retain role restrictions without duplicating Account', async () => {
  const { navGroupsFor, navFor, canOpenRoute } = await load('roles');
  for (const role of ['admin', 'operator', 'viewer']) {
    const groups = navGroupsFor(role);
    const routes = groups.flatMap((g) => g.items.map((i) => i.route));
    assert.deepEqual(routes, navFor(role).map((i) => i.route));
    assert.equal(routes.length, new Set(routes).size);
    assert.ok(!routes.includes('account'));
    assert.equal(canOpenRoute(role, 'account'), true);
  }
  assert.ok(!navGroupsFor('viewer').some((g) => g.label === 'Policy'));
  assert.ok(!navGroupsFor('operator').some((g) => g.label === 'Administration'));
  assert.ok(navGroupsFor('admin').find((g) => g.label === 'Policy').collapsible);
});

test('query: hash parsing and query building', async () => {
  const q = await load('query');
  assert.deepEqual(q.parseHash('#/events/evt_1?x=2'), { route: 'event', params: { id: 'evt_1' }, query: { x: '2' }, path: '/events/evt_1' });
  assert.equal(q.parseHash('').route, 'dashboard');
  assert.equal(q.parseHash('#/compare?a=1&b=2').query.b, '2');
  assert.equal(q.parseHash('#/events/%E0%A4%A').params.id, '%E0%A4%A', 'malformed escapes do not throw');
  assert.equal(q.buildQuery({ a: 1, b: '', c: null, d: [1, 2], e: [] }), '?a=1&d=1%2C2');
  assert.equal(q.buildQuery({}), '');
  assert.equal(q.hashFor('/compare', { a: 'x y' }), '#/compare?a=x+y');
  assert.deepEqual(q.parseIdList('evt_1, evt_2  evt_1;evt_3'), ['evt_1', 'evt_2', 'evt_3']);
});

test('samples: built-in examples are valid; validation mirrors the server Sample schema', async () => {
  const s = await load('samples');
  for (const ex of s.EXAMPLES) assert.deepEqual(s.validateSample(ex.sample), [], ex.key);
  assert.ok(s.EXAMPLES.some((e) => e.kind === 'benign') && s.EXAMPLES.some((e) => e.kind === 'attack'));
  const ex = s.exampleByKey('sqli');
  ex.path = '/changed';
  assert.notEqual(s.exampleByKey('sqli').path, '/changed', 'examples are copied');
  const fields = (smp) => s.validateSample(smp).map((e) => e.field);
  assert.deepEqual(fields({ method: 'TRACE', path: '/' }), ['method']);
  assert.deepEqual(fields({ method: 'GET', path: 'no-slash' }), ['path']);
  assert.deepEqual(fields({ method: 'GET', path: '/has space' }), ['path']);
  assert.deepEqual(fields({ method: 'GET', path: `/${'a'.repeat(5000)}` }), ['path']);
  assert.deepEqual(fields({ method: 'GET', path: '/', headers: { 'bad name': 'x' } }), ['headers.bad name']);
  assert.deepEqual(fields({ method: 'GET', path: '/', headers: { a: 5 } }), ['headers.a']);
  const many = Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`h${i}`, 'v']));
  assert.ok(fields({ method: 'GET', path: '/', headers: many }).includes('headers'));
  assert.deepEqual(fields({ method: 'POST', path: '/', body: 'x'.repeat(1024 * 1024 + 1) }), ['body']);
  assert.deepEqual(fields(null), ['sample']);
  assert.deepEqual(s.normalizeSample({ method: 'GET', path: '/', headers: { 'User-Agent': 'x' }, body: '', extra: 1 }),
    { method: 'GET', path: '/', headers: { 'user-agent': 'x' }, body: null });
});

test('samples: header editor rows', async () => {
  const s = await load('samples');
  const { headers, errors } = s.rowsToHeaders([{ name: 'Content-Type', value: 'a' }, { name: '', value: '' }, { name: 'content-type', value: 'b' }, { name: '', value: 'orphan' }]);
  assert.deepEqual(headers, { 'content-type': 'a' });
  assert.equal(errors.length, 2);
  assert.deepEqual(s.headersToRows({ a: '1' }), [{ name: 'a', value: '1' }]);
});

test('samples: import file parsing enforces type, size and structure', async () => {
  const s = await load('samples');
  const good = JSON.stringify([{ method: 'GET', path: '/a' }, { label: 'labelled', sample: { method: 'POST', path: '/b', body: 'x=1' } }, { method: 'BAD', path: '/c' }]);
  const r = s.parseImportText(good, good.length, 'samples.json');
  assert.equal(r.ok, true);
  assert.equal(r.total, 3);
  assert.equal(r.samples.length, 2);
  assert.equal(r.invalid.length, 1);
  assert.equal(r.invalid[0].index, 2);
  assert.deepEqual(s.importPayload(r), [
    { method: 'GET', path: '/a', headers: {}, body: null },
    { label: 'labelled', sample: { method: 'POST', path: '/b', headers: {}, body: 'x=1' } },
  ]);
  assert.equal(s.parseImportText(JSON.stringify({ samples: [{ method: 'GET', path: '/' }] }), 10, 'x.json').ok, true);
  assert.match(s.parseImportText('[]', 2, 'evil.exe').error, /\.json/);
  assert.match(s.parseImportText('[]', 2, '../../etc.json').error, /Rename/);
  assert.match(s.parseImportText('[]', 300 * 1024, 'big.json').error, /256 KB/);
  assert.match(s.parseImportText('{not json', 9, 'a.json').error, /not valid JSON/);
  assert.match(s.parseImportText('{"x":1}', 7, 'a.json').error, /array of samples/);
  assert.match(s.parseImportText('[]', 2, 'a.json').error, /no samples/);
  const tooMany = JSON.stringify(Array.from({ length: 101 }, () => ({ method: 'GET', path: '/' })));
  assert.match(s.parseImportText(tooMany, tooMany.length, 'a.json').error, /Too many/);
  const allBad = JSON.stringify([{ method: 'X', path: '/' }]);
  assert.equal(s.parseImportText(allBad, allBad.length, 'a.json').ok, false);
});

test('diff: config diff and event comparison', async () => {
  const d = await load('diff');
  assert.deepEqual(d.flatten({ a: { b: 1, c: [1] }, d: null }), { 'a.b': 1, 'a.c': [1], d: null });
  const changes = d.diffObjects({ mode: 'block', thresholds: { flag: 3, block: 5 } }, { mode: 'monitor', thresholds: { flag: 3, block: 4 } });
  assert.deepEqual(changes, [{ path: 'mode', from: 'block', to: 'monitor' }, { path: 'thresholds.block', from: 5, to: 4 }]);
  assert.deepEqual(d.diffObjects({ a: 1 }, { a: 1 }), []);
  assert.equal(d.displayValue(undefined), '(unset)');
  assert.equal(d.displayValue([1, 2]), '1, 2');

  const normal = { id: 'evt_a', ts: 't1', source: 'console', method: 'GET', path: '/search', verdict: 'allow', action: 'allowed', score: 0, rulesetVersion: 'r1', configVersion: 1,
    decision: { verdict: 'allow', action: 'allowed', score: { total: 0, flagThreshold: 3, blockThreshold: 5 }, matches: [], engine: { engineVersion: '1.0.0' } } };
  const bad = { id: 'evt_b', ts: 't2', source: 'console', method: 'GET', path: '/search', verdict: 'block', action: 'blocked', score: 8, rulesetVersion: 'r1', configVersion: 2,
    decision: { verdict: 'block', action: 'blocked', score: { total: 8, flagThreshold: 3, blockThreshold: 5 }, matches: [{ ruleId: 942100 }, { ruleId: 942100 }], engine: { engineVersion: '1.0.0' } } };
  const rows = d.compareEventRows(normal, bad);
  const changed = rows.filter((r) => r.changed).map((r) => r.field);
  for (const f of ['verdict', 'action', 'score', 'rules', 'configVersion']) assert.ok(changed.includes(f), f);
  for (const f of ['id', 'ts', 'rulesetVersion', 'engineVersion', 'thresholds', 'request']) assert.ok(!changed.includes(f), f);
  assert.deepEqual(rows.find((r) => r.field === 'rules').b, ['942100'], 'rule ids de-duplicated');
  const summary = d.summarizeDiff({ verdictChanged: true, actionChanged: true, scoreDelta: 8, rulesAdded: [942100], rulesRemoved: [], rulesetChanged: false, configChanged: true }, normal, bad);
  assert.ok(summary.includes('Verdict changed: allow → block'));
  assert.ok(summary.includes('Score +8'));
  assert.ok(summary.includes('Configuration version changed'));
  assert.deepEqual(d.summarizeDiff(null), []);
});
