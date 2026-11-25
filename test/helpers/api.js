'use strict';
const assert = require('node:assert/strict');

async function analyze(client, sample, label) {
  const r = await client.post('/api/analyze', { label, sample: { headers: {}, body: null, method: 'GET', ...sample } });
  assert.equal(r.status, 201, `analyze ${sample.path}: HTTP ${r.status} ${r.text.slice(0, 300)}`);
  assert.ok(r.body && r.body.event && r.body.event.id, 'analyze returns { event }');
  return r.body.event;
}

async function getEvent(client, id) {
  const r = await client.get('/api/events/' + encodeURIComponent(id));
  assert.equal(r.status, 200, `get event ${id}: HTTP ${r.status}`);
  return r.body.event;
}

async function updateConfig(admin, mutate, reason = 'test change') {
  const cur = await admin.get('/api/config');
  assert.equal(cur.status, 200, `GET /api/config: HTTP ${cur.status}`);
  const config = structuredClone(cur.body.config);
  mutate(config);
  const r = await admin.put('/api/config', { config, reason, confirm: true });
  assert.equal(r.status, 200, `PUT /api/config: HTTP ${r.status} ${r.text.slice(0, 300)}`);
  return r.body;
}

async function createUser(admin, username, role, password = `Test-${role}-${username}-Pw1!`) {
  const r = await admin.post('/api/users', { username, password, role });
  assert.equal(r.status, 201, `create user ${username}: HTTP ${r.status} ${r.text.slice(0, 200)}`);
  return { ...r.body.user, password };
}

async function audit(admin, filter = {}) {
  const qs = new URLSearchParams({ limit: '500', ...filter }).toString();
  const r = await admin.get('/api/audit?' + qs);
  assert.equal(r.status, 200, `GET /api/audit: HTTP ${r.status}`);
  return r.body.items;
}

function matchedIds(event) {
  if (Array.isArray(event.matchedRuleIds)) return event.matchedRuleIds.map(Number);
  return ((event.decision && event.decision.matches) || []).map((m) => Number(m.ruleId));
}

module.exports = { analyze, getEvent, updateConfig, createUser, audit, matchedIds };
