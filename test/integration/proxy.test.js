'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack, waitFor } = require('../helpers/stack');
const { getEvent, updateConfig, audit } = require('../helpers/api');

describe('WAF reverse proxy end to end', { skip: skipUnlessStack() }, () => {
  let stack, admin;
  before(async () => {
    stack = await startStack();
    admin = await stack.login('admin');
  });
  after(async () => { if (stack) await stack.stop(); });

  it('benign request passes to the target with X-WAF-Action: allowed', async () => {
    const r = await stack.proxy({ path: '/search?q=mug' });
    assert.equal(r.status, 200);
    assert.equal(r.headers['x-waf-action'], 'allowed');
    assert.match(r.headers['x-waf-event-id'] || '', /^evt_/);
    assert.match(r.text, /Packet Sniffer Mug/);
    assert.equal(r.headers['x-lab-target'], 'vulnerable-shop', 'response really came from the target');
    const ev = await waitFor(async () => { const x = await admin.get('/api/events/' + r.headers['x-waf-event-id']); return x.status === 200 && x.body.event; });
    assert.equal(ev.source, 'proxy');
    assert.equal(ev.action, 'allowed');
  });

  it('benign POST body is forwarded intact (buffered body re-streamed)', async () => {
    const body = 'author=tester&text=' + encodeURIComponent('Lovely hoodie, fits well');
    const r = await stack.proxy({ method: 'POST', path: '/comments', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body });
    assert.equal(r.status, 201, r.text);
    assert.equal(JSON.parse(r.text).comment.text, 'Lovely hoodie, fits well');
    const echo = await stack.proxy({ method: 'POST', path: '/api/echo', headers: { 'content-type': 'text/plain' }, body: 'x'.repeat(5000) });
    assert.equal(echo.status, 200);
    assert.equal(JSON.parse(echo.text).bytes, 5000);
  });

  let blockedEventId;
  it('SQLi is blocked with 403, event id, and NO rule details in the body', async () => {
    const r = await stack.proxy({ path: '/products?id=1%20OR%201%3D1', headers: { accept: 'text/html' } });
    assert.equal(r.status, 403);
    assert.equal(r.headers['x-waf-action'], 'blocked');
    blockedEventId = r.headers['x-waf-event-id'];
    assert.match(blockedEventId || '', /^evt_/);
    assert.ok(r.text.includes(blockedEventId), 'block page shows the event id');
    assert.doesNotMatch(r.text, /Packet Sniffer Mug|FAKE-LAB/, 'target content not leaked');
    const ev = await getEvent(admin, blockedEventId);
    assert.equal(ev.verdict, 'block');
    assert.ok(ev.decision.matches.length > 0);
    for (const m of ev.decision.matches) {
      assert.ok(!r.text.includes(m.ruleName), `rule name "${m.ruleName}" must not be revealed`);
      assert.ok(!new RegExp(`\\b${m.ruleId}\\b`).test(r.text), `rule id ${m.ruleId} must not be revealed`);
    }
    assert.doesNotMatch(r.text, /OR 1=1|anomaly score|threshold/i);
  });

  it('block response honours Accept: application/json and still hides rule details', async () => {
    const r = await stack.proxy({ path: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', headers: { accept: 'application/json' } });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.text);
    assert.ok(JSON.stringify(body).includes(r.headers['x-waf-event-id']));
    assert.ok(!('matches' in body) && !('score' in body) && !('decision' in body));
  });

  it('path traversal to the fake secret is blocked', async () => {
    const r = await stack.proxy({ path: '/files?name=../secret/flag.txt' });
    assert.equal(r.status, 403);
    assert.doesNotMatch(r.text, /FAKE-LAB-FLAG/);
  });

  it('monitor mode lets the same attack through with X-WAF-Action: logged and wouldBlock', async () => {
    await updateConfig(admin, (c) => { c.mode = 'monitor'; }, 'monitor mode test');
    const r = await stack.proxy({ path: '/products?id=1%20OR%201%3D1', headers: { accept: 'application/json' } });
    assert.equal(r.status, 200, 'request reaches the target in monitor mode');
    assert.equal(r.headers['x-waf-action'], 'logged');
    const ev = await getEvent(admin, r.headers['x-waf-event-id']);
    assert.equal(ev.mode, 'monitor');
    assert.equal(ev.verdict, 'block');
    assert.equal(ev.action, 'logged');
    assert.equal(ev.decision.wouldBlock, true);
    await updateConfig(admin, (c) => { c.mode = 'block'; }, 'back to block mode');
    const again = await stack.proxy({ path: '/products?id=1%20OR%201%3D1' });
    assert.equal(again.status, 403, 'block mode restored immediately (engine state reloaded)');
  });

  it('rate limit breach returns 429 with evidence, then recovers after reconfiguration', async () => {
    await updateConfig(admin, (c) => { c.mode = 'block'; c.rateLimit = { enabled: true, windowMs: 60000, maxRequests: 5 }; }, 'tight rate limit test');
    const statuses = [];
    let limited;
    for (let i = 0; i < 9; i++) {
      const r = await stack.proxy({ path: '/search?q=ratelimit' + i });
      statuses.push(r.status);
      if (r.status === 429) limited = r;
    }
    assert.ok(statuses.slice(0, 5).every((s) => s === 200), `first 5 allowed: ${statuses}`);
    assert.ok(limited, `a 429 was returned: ${statuses}`);
    assert.equal(limited.headers['x-waf-action'], 'blocked');
    const ev = await getEvent(admin, limited.headers['x-waf-event-id']);
    assert.equal(ev.decision.blockReason, 'RATE_LIMITED');
    assert.equal(ev.decision.rateLimit.limited, true);
    assert.equal(ev.decision.rateLimit.limit, 5);
    await updateConfig(admin, (c) => { c.rateLimit = { enabled: true, windowMs: 60000, maxRequests: 100000 }; }, 'relax rate limit');
    const ok = await stack.proxy({ path: '/search?q=after' });
    assert.equal(ok.status, 200);
  });

  it('oversized body is rejected with 413 before reaching the target', async () => {
    const cfg = (await admin.get('/api/config')).body.config;
    const big = Buffer.alloc(cfg.limits.maxBodyBytes + 1024, 0x61);
    const r = await stack.proxy({ method: 'POST', path: '/api/echo', headers: { 'content-type': 'text/plain' }, body: big });
    assert.ok(r.status === 413 || r.status === 0, `413 expected, got ${r.status} ${r.error || ''}`);
    if (r.status === 413) assert.equal(r.headers['x-waf-action'], 'blocked');
  });

  it('proxy decisions are visible in the event list with filters', async () => {
    const r = await admin.get('/api/events?source=proxy&action=blocked&limit=100');
    assert.equal(r.status, 200);
    assert.ok(r.body.items.some((e) => e.id === blockedEventId));
    assert.ok(r.body.items.every((e) => e.action === 'blocked' && e.source === 'proxy'));
  });

  it('target down → safe 502 page, no internals, system.error audited', async () => {
    await stack.stopTarget();
    const r = await stack.proxy({ path: '/search?q=mug' });
    assert.equal(r.status, 502);
    assert.doesNotMatch(r.text, /ECONNREFUSED|127\.0\.0\.1:\d+|\bat \w+ \(|node:/);
    const items = await waitFor(async () => (await audit(admin, { action: 'system.error' })).filter((i) => i.action === 'system.error'));
    assert.ok(items && items.length >= 1, 'system.error audit event recorded');
    const health = await stack.client().get('/api/health');
    assert.equal(health.status, 200, 'studio keeps working while the target is down');
  });
});
