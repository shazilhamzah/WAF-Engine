'use strict';
/** Shared helpers for engine unit tests (not a test file itself). */

const path = require('node:path');
const engine = require('../../../src/engine');
const { loadDefaultRules } = require('../../../src/rules');

const ROOT = path.join(__dirname, '..', '..', '..');
const UA = { 'user-agent': 'Mozilla/5.0 (unit test)' };

let cached = null;
/** Compiled default rule set (cached across tests in one file). */
function defaultRules() {
  if (!cached) {
    const { rules } = loadDefaultRules();
    cached = engine.compileRules(rules.map((r) => ({ id: r.id, source: r.source, enabled: true, version: 1 })));
  }
  return cached;
}

/** Inspect context with the default rules and no rate limiter, overridable. */
function ctx(overrides = {}) {
  const compiled = defaultRules();
  return { rules: compiled.rules, rulesetVersion: compiled.rulesetVersion, config: engine.DEFAULT_CONFIG, configVersion: 1, exceptions: [], rateLimiter: null, clientKey: 'c_test', now: 1_700_000_000_000, ...overrides };
}

/** Raw GET request with one query parameter. */
function getWith(name, value, headers = UA) {
  return { method: 'GET', url: `/search?${encodeURIComponent(name)}=${encodeURIComponent(value)}`, headers, body: null, bodyBytes: 0, remoteAddress: '127.0.0.1' };
}

/** Raw request from a fixture Sample { method, path, headers, body }. */
function fromSample(s) {
  return { method: s.method, url: s.path, headers: s.headers || {}, body: s.body, bodyBytes: s.body ? Buffer.byteLength(s.body) : 0, remoteAddress: '127.0.0.1' };
}

module.exports = { engine, ROOT, UA, defaultRules, ctx, getWith, fromSample };
