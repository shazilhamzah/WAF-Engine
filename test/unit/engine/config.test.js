'use strict';
// EngineConfig defaults and validation (contract §3.2).
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine } = require('./helpers');

test('DEFAULT_CONFIG matches the contract and is frozen', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(engine.DEFAULT_CONFIG)), {
    mode: 'block',
    thresholds: { flag: 3, block: 5 },
    limits: { maxBodyBytes: 1048576, inspectBodyBytes: 65536, maxUrlLength: 4096, maxHeaderCount: 100, maxArgs: 200, decodeRounds: 3 },
    rateLimit: { enabled: true, windowMs: 60000, maxRequests: 300 },
  });
  assert.ok(Object.isFrozen(engine.DEFAULT_CONFIG));
  assert.ok(Object.isFrozen(engine.DEFAULT_CONFIG.limits));
  assert.equal(engine.ENGINE_VERSION, '1.0.0');
});

test('validateConfig accepts defaults, partial configs and returns a normalized copy', () => {
  const res = engine.validateConfig(engine.DEFAULT_CONFIG);
  assert.equal(res.ok, true);
  assert.notEqual(res.config, engine.DEFAULT_CONFIG);
  const partial = engine.validateConfig({ mode: 'monitor', thresholds: { block: 8 } });
  assert.equal(partial.ok, true);
  assert.equal(partial.config.mode, 'monitor');
  assert.deepEqual(partial.config.thresholds, { flag: 3, block: 8 });
  assert.equal(partial.config.limits.maxArgs, 200);
});

test('validateConfig rejects unknown fields, wrong types and out-of-range values with field paths', () => {
  const res = engine.validateConfig({ mode: 'off', extra: 1, thresholds: { flag: 0, block: 'x' }, limits: { decodeRounds: 9, foo: 1 }, rateLimit: { enabled: 'yes', windowMs: 1.5 } });
  assert.equal(res.ok, false);
  assert.equal(res.config, null);
  const fields = res.errors.map((e) => e.field).sort();
  assert.deepEqual(fields, ['extra', 'limits.decodeRounds', 'limits.foo', 'mode', 'rateLimit.enabled', 'rateLimit.windowMs', 'thresholds.block', 'thresholds.flag']);
  assert.ok(res.errors.every((e) => typeof e.message === 'string' && e.message.length > 0));
});

test('validateConfig enforces flag <= block and inspectBodyBytes <= maxBodyBytes', () => {
  assert.deepEqual(engine.validateConfig({ thresholds: { flag: 6, block: 5 } }).errors.map((e) => e.field), ['thresholds.flag']);
  assert.deepEqual(engine.validateConfig({ limits: { maxBodyBytes: 2048, inspectBodyBytes: 4096 } }).errors.map((e) => e.field), ['limits.inspectBodyBytes']);
  assert.equal(engine.validateConfig({ thresholds: { flag: 5, block: 5 } }).ok, true);
});

test('validateConfig rejects non-objects', () => {
  for (const v of ['x', 5, [], true]) assert.equal(engine.validateConfig(v).ok, false);
  assert.equal(engine.validateConfig(undefined).ok, true);
});
