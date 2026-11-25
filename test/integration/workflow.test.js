'use strict';
/**
 * The proposal's "Illustrative working example" (page 3), end to end through the real Studio API:
 *  operator signs in → analyzes a safe sample (completed, evidence, no critical warning) → analyzes a
 *  suspicious variant (specific indicator: rule id + location, not just "unsafe") → history shows both →
 *  compare → export sanitized report → admin changes a threshold (with confirmation) → replay →
 *  new result AND the config change are both traceable (events + audit + config history).
 * Traceability: OBJ-1, OBJ-2, FR-3, FR-6, FR-7, NFR-8.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');
const { analyze, getEvent, audit, matchedIds } = require('../helpers/api');

const BENIGN = { method: 'GET', path: '/search?q=blue%20coffee%20mug&page=2', headers: { 'user-agent': 'workflow-test' }, body: null };
const SUSPICIOUS = { method: 'GET', path: "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", headers: { 'user-agent': 'workflow-test' }, body: null };

describe('proposal illustrative workflow (operator → admin → replay)', { skip: skipUnlessStack() }, () => {
  let stack, operator, admin;
  let benign, suspicious, replayed, newConfigVersion;

  before(async () => {
    stack = await startStack();
    operator = await stack.login('operator');
  });
  after(async () => { if (stack) await stack.stop(); });

  it('operator is signed in with role operator and a CSRF token', () => {
    assert.equal(operator.role, 'operator');
    assert.ok(operator.csrfToken && operator.csrfToken.length >= 16);
  });

  it('benign sample → completed decision, allow, evidence, no critical warning', async () => {
    benign = await analyze(operator, BENIGN, 'workflow benign');
    assert.match(benign.id, /^evt_/);
    assert.equal(benign.source, 'console');
    assert.equal(benign.verdict, 'allow');
    const d = benign.decision;
    assert.ok(d, 'full decision returned to operator');
    assert.ok(Array.isArray(d.explanation) && d.explanation.length > 0, 'explanation present');
    assert.equal(typeof d.score.total, 'number');
    assert.ok(d.score.total < d.score.flagThreshold, 'score below flag threshold');
    assert.ok(!d.matches.some((m) => m.severity === 'critical'), 'no unjustified critical warning');
    assert.ok(d.engine && d.engine.rulesetVersion && d.engine.engineVersion, 'engine/ruleset versions stored');
    assert.equal(typeof d.engine.configVersion, 'number');
    assert.ok(d.timings && typeof d.timings.totalMs === 'number');
  });

  it('suspicious variant → specific indicator (rule id, name, location, excerpt), not just "unsafe"', async () => {
    suspicious = await analyze(operator, SUSPICIOUS, 'workflow suspicious');
    assert.ok(['block', 'flag'].includes(suspicious.verdict), `verdict ${suspicious.verdict}`);
    const d = suspicious.decision;
    assert.ok(d.matches.length > 0, 'at least one rule matched');
    const m = d.matches.find((x) => x.category === 'sqli') || d.matches[0];
    assert.ok(Number.isInteger(Number(m.ruleId)) && Number(m.ruleId) >= 1000, 'numeric rule id');
    assert.ok(m.ruleName && m.ruleName.length > 3, 'rule name');
    assert.match(m.location, /^query\.id$|^query/, 'location points at the query parameter');
    assert.equal(m.category, 'sqli');
    assert.ok(typeof m.excerpt === 'string' && m.excerpt.length <= 120);
    assert.ok(d.explanation.some((line) => line.includes(String(m.ruleId))), 'explanation cites the rule id');
    assert.ok(d.score.contributions.some((c) => String(c.id) === String(m.ruleId)), 'score contribution per rule');
    assert.ok(d.score.byCategory.sqli > 0);
    assert.ok(typeof d.recommendation === 'string' && d.recommendation.length > 0);
  });

  it('history lists both console events', async () => {
    const r = await operator.get('/api/events?source=console&limit=50');
    assert.equal(r.status, 200);
    const ids = r.body.items.map((e) => e.id);
    assert.ok(ids.includes(benign.id) && ids.includes(suspicious.id));
    assert.ok(r.body.total >= 2);
  });

  it('compare shows what changed between the two results', async () => {
    const r = await operator.get(`/api/events/compare?a=${benign.id}&b=${suspicious.id}`);
    assert.equal(r.status, 200);
    assert.equal(r.body.a.id, benign.id);
    assert.equal(r.body.b.id, suspicious.id);
    assert.equal(r.body.diff.verdictChanged, true);
    assert.ok(r.body.diff.scoreDelta > 0);
    assert.ok(r.body.diff.rulesAdded.length > 0);
  });

  it('operator exports a sanitized report containing both events (json + html)', async () => {
    const ids = `${benign.id},${suspicious.id}`;
    const json = await operator.get('/api/reports/export?format=json&ids=' + ids);
    assert.equal(json.status, 200);
    assert.match(json.headers.get('content-disposition') || '', /attachment/);
    assert.ok(json.text.includes(benign.id) && json.text.includes(suspicious.id));
    const html = await operator.get('/api/reports/export?format=html&ids=' + ids);
    assert.equal(html.status, 200);
    assert.match(html.headers.get('content-type') || '', /html/);
    assert.ok(html.text.includes(suspicious.id));
    assert.ok(!html.text.includes('<script'), 'no active script in exported HTML');
  });

  it('admin threshold change requires confirmation (428 without confirm)', async () => {
    admin = await stack.login('admin');
    const cur = await admin.get('/api/config');
    assert.equal(cur.status, 200);
    const config = structuredClone(cur.body.config);
    config.thresholds = { ...config.thresholds, block: 100 };
    const noConfirm = await admin.put('/api/config', { config, reason: 'raise block threshold for demo' });
    assert.equal(noConfirm.status, 428);
    assert.equal(noConfirm.body.error.code, 'CONFIRMATION_REQUIRED');
    const ok = await admin.put('/api/config', { config, reason: 'raise block threshold for demo', confirm: true });
    assert.equal(ok.status, 200, ok.text);
    assert.ok(ok.body.version > cur.body.version, 'config version increments');
    newConfigVersion = ok.body.version;
  });

  it('operator cannot change config (server-side authorization)', async () => {
    const cur = await operator.get('/api/config');
    const r = await operator.put('/api/config', { config: cur.body.config, reason: 'x', confirm: true });
    assert.equal(r.status, 403);
  });

  it('replay of the suspicious sample gives a new, traceable result under the new config', async () => {
    const r = await operator.post(`/api/events/${suspicious.id}/replay`, undefined);
    assert.equal(r.status, 201, r.text);
    replayed = r.body.event;
    assert.equal(r.body.previous.id, suspicious.id);
    assert.equal(replayed.replayOf, suspicious.id);
    assert.equal(replayed.source, 'replay');
    assert.equal(replayed.decision.engine.configVersion, newConfigVersion);
    assert.equal(replayed.decision.score.blockThreshold, 100);
    assert.notEqual(replayed.verdict, 'block', 'higher threshold → no longer blocked');
    assert.deepEqual(matchedIds(replayed).sort(), matchedIds(suspicious).sort(), 'same rules still match (evidence kept)');
    const stored = await getEvent(operator, replayed.id);
    assert.equal(stored.configVersion, newConfigVersion);
  });

  it('config change and replay are traceable in config history and the audit log', async () => {
    const hist = await admin.get('/api/config/history');
    assert.equal(hist.status, 200);
    const entry = hist.body.items.find((i) => i.version === newConfigVersion);
    assert.ok(entry, 'new version in history');
    assert.equal(entry.reason, 'raise block threshold for demo');
    assert.ok(entry.changedBy, 'changedBy recorded');

    const items = await audit(admin);
    const byAction = (a) => items.filter((i) => i.action === a);
    const cfg = byAction('config.update').find((i) => String(i.targetId) === String(newConfigVersion));
    assert.ok(cfg, 'config.update audited with the new version');
    assert.equal(cfg.actorName, 'admin');
    assert.equal(cfg.outcome, 'success');
    assert.ok(byAction('analysis.submit').length >= 2, 'analysis submissions audited');
    assert.ok(byAction('event.replay').some((i) => String(i.targetId) === suspicious.id || String(i.targetId) === replayed.id));
    assert.ok(byAction('report.export').length >= 1, 'export audited');
    assert.ok(byAction('auth.login.success').length >= 2, 'logins audited');

    const verify = await admin.get('/api/audit/verify');
    assert.equal(verify.status, 200);
    assert.equal(verify.body.ok, true);
    assert.ok(verify.body.checked >= items.length);
  });
});
