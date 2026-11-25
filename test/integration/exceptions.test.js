'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');
const { analyze, createUser, audit, matchedIds } = require('../helpers/api');

const SAMPLE = { method: 'GET', path: "/search?q=%27%20OR%201%3D1%20--", headers: {}, body: null };

describe('exception workflow with separation of duties', { skip: skipUnlessStack() }, () => {
  let stack, operator, admin, admin2;
  let original, ruleId, location, exc, ownExc;

  before(async () => {
    stack = await startStack();
    operator = await stack.login('operator');
    admin = await stack.login('admin');
    const u = await createUser(admin, 'admin2', 'admin');
    admin2 = await stack.login('admin', { username: 'admin2', password: u.password });
  });
  after(async () => { if (stack) await stack.stop(); });

  it('operator analyzes a sample that a rule matches', async () => {
    original = await analyze(operator, SAMPLE, 'exception baseline');
    assert.ok(original.decision.matches.length > 0, 'at least one rule matched');
    ruleId = Number(original.decision.matches[0].ruleId);
    location = original.decision.matches[0].location;
  });

  it('operator previews the impact of a scoped exception', async () => {
    const r = await operator.post('/api/exceptions/preview', { ruleId, scope: { pathPrefix: '/search', location, method: 'GET' } });
    assert.equal(r.status, 200, r.text);
    assert.ok(r.body.affectedEvents >= 1, 'preview finds the baseline event');
    assert.ok(Array.isArray(r.body.sample));
  });

  it('operator requests the exception (status pending)', async () => {
    const r = await operator.post('/api/exceptions', {
      ruleId, scope: { pathPrefix: '/search', location, method: 'GET' },
      reason: 'Search box legitimately receives SQL-like text in the lab', sourceEventId: original.id
    });
    assert.equal(r.status, 201, r.text);
    exc = r.body.exception;
    assert.match(exc.id, /^exc_/);
    assert.equal(exc.status, 'pending');
  });

  it('pending exception does not change decisions yet', async () => {
    const r = await operator.post(`/api/events/${original.id}/replay`, undefined);
    assert.equal(r.status, 201);
    assert.ok(matchedIds(r.body.event).includes(ruleId));
  });

  it('operator cannot approve (role) — generic 403', async () => {
    const r = await operator.post(`/api/exceptions/${exc.id}/approve`, { confirm: true });
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, 'FORBIDDEN');
  });

  it('an admin cannot approve an exception they requested themselves', async () => {
    const r = await admin.post('/api/exceptions', { ruleId, scope: { pathPrefix: '/nowhere', location: null, method: null }, reason: 'self-approval check' });
    assert.equal(r.status, 201, r.text);
    ownExc = r.body.exception;
    const self = await admin.post(`/api/exceptions/${ownExc.id}/approve`, { confirm: true });
    assert.equal(self.status, 403, 'separation of duties enforced');
    const still = await admin.get('/api/exceptions?status=pending');
    assert.ok(still.body.items.some((e) => e.id === ownExc.id));
  });

  it('approval without confirm → 428', async () => {
    const r = await admin2.post(`/api/exceptions/${exc.id}/approve`, { note: 'looks fine' });
    assert.equal(r.status, 428);
  });

  it('second admin approves with confirmation', async () => {
    const r = await admin2.post(`/api/exceptions/${exc.id}/approve`, { confirm: true, note: 'approved for lab search box' });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.body.exception.status, 'approved');
  });

  it('replay shows the match suppressed (kept as evidence) and a changed decision', async () => {
    const r = await operator.post(`/api/events/${original.id}/replay`, undefined);
    assert.equal(r.status, 201, r.text);
    const d = r.body.event.decision;
    assert.ok(!d.matches.some((m) => Number(m.ruleId) === ruleId && m.location === location), 'active matches no longer include the rule');
    const sup = d.suppressed.find((m) => Number(m.ruleId) === ruleId);
    assert.ok(sup, 'suppressed match kept as evidence');
    assert.equal(sup.suppressedBy, exc.id);
    assert.ok(d.score.total < original.decision.score.total, 'score dropped');
  });

  it('exception only applies within its scope (other path still matches)', async () => {
    const other = await analyze(operator, { ...SAMPLE, path: SAMPLE.path.replace('/search', '/products') }, 'out of scope');
    assert.ok(matchedIds(other).includes(ruleId));
  });

  it('revoke (with confirm) restores the original decision', async () => {
    const r = await admin2.post(`/api/exceptions/${exc.id}/revoke`, { confirm: true, note: 'demo over' });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.body.exception.status, 'revoked');
    const rep = await operator.post(`/api/events/${original.id}/replay`, undefined);
    assert.equal(rep.status, 201);
    assert.ok(matchedIds(rep.body.event).includes(ruleId));
    assert.equal(rep.body.event.verdict, original.verdict);
  });

  it('admin can reject a pending request', async () => {
    const r = await admin2.post(`/api/exceptions/${ownExc.id}/reject`, { note: 'not needed' });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.body.exception.status, 'rejected');
  });

  it('every exception step is in the audit log with the right actor', async () => {
    const items = await audit(admin);
    const find = (action, id) => items.find((i) => i.action === action && String(i.targetId) === id);
    assert.equal(find('exception.request', exc.id).actorName, 'operator');
    assert.equal(find('exception.approve', exc.id).actorName, 'admin2');
    assert.equal(find('exception.revoke', exc.id).actorName, 'admin2');
    assert.ok(find('exception.reject', ownExc.id));
    assert.ok(items.some((i) => i.action === 'auth.denied' || (i.action === 'exception.approve' && i.outcome !== 'success')),
      'denied approval attempts are audited');
    const v = await admin.get('/api/audit/verify');
    assert.equal(v.body.ok, true);
  });
});
