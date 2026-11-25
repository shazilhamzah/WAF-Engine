'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { sanitize } = require('./stats');
const { waitFor } = require('../helpers/stack');

const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURES = path.join(ROOT, 'fixtures');

function loadFixture(name) {
  const f = path.join(FIXTURES, name);
  if (!fs.existsSync(f)) return null;
  const data = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (Array.isArray(data)) return { case: name, title: name, samples: data };
  if (!Array.isArray(data.samples)) throw new Error(`${name}: "samples" array missing`);
  return data;
}

function toRaw(request) {
  const headers = {};
  for (const [k, v] of Object.entries(request.headers || {})) headers[k.toLowerCase()] = String(v);
  let body = request.body;
  if (body !== null && body !== undefined && typeof body === 'object' && !Buffer.isBuffer(body)) {
    body = JSON.stringify(body);
    if (!headers['content-type']) headers['content-type'] = 'application/json';
  }
  if (typeof body === 'string' && !headers['content-type']) headers['content-type'] = 'application/x-www-form-urlencoded';
  if (body === undefined) body = null;
  return { method: (request.method || 'GET').toUpperCase(), path: request.path || request.url || '/', headers, body };
}

function describeInput(raw) {
  const bodyBytes = raw.body == null ? 0 : Buffer.byteLength(raw.body);
  return {
    method: raw.method,
    path: sanitize(raw.path, 160),
    headers: Object.keys(raw.headers),
    bodyBytes,
    bodyExcerpt: bodyBytes ? sanitize(Buffer.isBuffer(raw.body) ? raw.body.subarray(0, 200) : String(raw.body).slice(0, 200), 120) : ''
  };
}

async function fetchEvent(admin, eventId) {
  if (!eventId) return null;
  return waitFor(async () => {
    const r = await admin.get('/api/events/' + encodeURIComponent(eventId));
    return r.status === 200 && r.body && r.body.event ? r.body.event : null;
  }, { timeoutMs: 2000 });
}

function evidenceOf(event) {
  if (!event) return { eventId: null, ruleIds: [], categories: [], score: null, explanation: '', anomalies: [], decisionMs: null };
  const d = event.decision || {};
  const matches = d.matches || [];
  return {
    eventId: event.id,
    ruleIds: matches.map((m) => Number(m.ruleId)),
    ruleNames: matches.map((m) => m.ruleName).slice(0, 5),
    locations: [...new Set(matches.map((m) => m.location))].slice(0, 5),
    categories: [...new Set(matches.map((m) => m.category).filter(Boolean))],
    suppressed: (d.suppressed || []).map((m) => Number(m.ruleId)),
    score: d.score ? d.score.total : event.score,
    thresholds: d.score ? { flag: d.score.flagThreshold, block: d.score.blockThreshold } : null,
    anomalies: (d.anomalies || []).map((a) => a.code),
    blockReason: d.blockReason || null,
    decodedVia: [...new Set(matches.flatMap((m) => m.decodedVia || []))],
    explanation: sanitize((d.explanation || []).join(' · '), 240),
    decisionMs: d.timings ? d.timings.totalMs : null,
    proxyLatencyMs: event.latencyMs ?? null
  };
}

function judge(expected, actual, evidence) {
  const exp = (expected && expected.verdict) || 'allow';
  const notes = [];
  let pass;
  if (exp === 'block') {
    pass = actual.action === 'blocked';
    if (pass && actual.status !== 403) notes.push(`blocked with HTTP ${actual.status} (${evidence.blockReason || 'n/a'})`);
  } else if (exp === 'allow') {
    pass = actual.action === 'allowed' && actual.verdict === 'allow';
    if (actual.action === 'allowed' && actual.verdict === 'flag') notes.push('flagged (soft false positive)');
  } else if (exp === 'flag') {
    pass = actual.action !== 'blocked' && actual.verdict === 'flag';
  } else {
    pass = false;
    notes.push(`unknown expected verdict ${exp}`);
  }
  const wanted = (expected && expected.categories) || [];
  const categoryHit = wanted.length === 0 ? null : wanted.some((c) => evidence.categories.includes(c));
  if (exp !== 'allow' && wanted.length && !categoryHit && actual.action === 'blocked') notes.push(`blocked via ${evidence.categories.join(',') || evidence.blockReason || 'anomaly'} not ${wanted.join(',')}`);
  return { pass, categoryHit, notes };
}

async function runSample(stack, admin, sample) {
  const raw = toRaw(sample.request || sample);
  const res = await stack.proxy({ ...raw, headers: { 'user-agent': 'waf-studio-evaluate/1.0', ...raw.headers } });
  const eventId = res.headers['x-waf-event-id'] || null;
  const event = await fetchEvent(admin, eventId);
  const evidence = evidenceOf(event);
  const actual = {
    status: res.status,
    action: res.headers['x-waf-action'] || (res.status === 0 ? 'error' : 'unknown'),
    verdict: event ? event.verdict : null,
    roundTripMs: Math.round(res.ms * 1000) / 1000,
    error: res.error || null
  };
  const { pass, categoryHit, notes } = judge(sample.expected, actual, evidence);
  if (sample.knownLimitation) notes.push(`Known limitation: ${sample.knownLimitation}`);
  return {
    id: sample.id,
    description: sample.description || '',
    input: describeInput(raw),
    expected: { verdict: (sample.expected && sample.expected.verdict) || 'allow', categories: (sample.expected && sample.expected.categories) || [] },
    actual,
    evidence,
    categoryHit,
    pass,
    notes
  };
}

function caseSummary(records) {
  const passed = records.filter((r) => r.pass).length;
  return { total: records.length, passed, failed: records.length - passed, passRate: records.length ? Math.round((passed / records.length) * 1000) / 10 : null };
}

module.exports = { loadFixture, toRaw, runSample, fetchEvent, evidenceOf, judge, caseSummary, describeInput, FIXTURES };
