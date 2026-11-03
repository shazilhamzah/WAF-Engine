'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, ctx, getWith } = require('./helpers');

test('allows maxRequests per window and limits the next one', () => {
  const rl = engine.createRateLimiter({ windowMs: 1000, maxRequests: 3 });
  const t = 10_000;
  assert.deepEqual([0, 100, 200].map((dt) => rl.check('c1', t + dt).limited), [false, false, false]);
  const fourth = rl.check('c1', t + 300);
  assert.equal(fourth.limited, true);
  assert.equal(fourth.count, 4);
  assert.equal(fourth.limit, 3);
  assert.equal(fourth.windowMs, 1000);
  assert.equal(fourth.checked, true);
  assert.ok(fourth.retryAfterSeconds >= 1);
});

test('the window slides: old requests expire individually', () => {
  const rl = engine.createRateLimiter({ windowMs: 1000, maxRequests: 2 });
  rl.check('c', 0);
  rl.check('c', 600);
  assert.equal(rl.check('c', 900).limited, true, '3 requests within 1 s');
  // at 1001 the request at 0 has left the window but 600 and 900 are still inside
  assert.equal(rl.check('c', 1001).limited, true);
  // at 1950 only 1001 is inside (600 and 900 expired) so it is allowed
  const later = rl.check('c', 1950);
  assert.equal(later.limited, false);
  assert.equal(later.count, 2);
});

test('keys are independent', () => {
  const rl = engine.createRateLimiter({ windowMs: 1000, maxRequests: 1 });
  assert.equal(rl.check('a', 0).limited, false);
  assert.equal(rl.check('a', 1).limited, true);
  assert.equal(rl.check('b', 2).limited, false);
});

test('memory is bounded: per-key log capped and stale keys evicted', () => {
  const rl = engine.createRateLimiter({ windowMs: 1000, maxRequests: 5, maxKeys: 100 });
  for (let i = 0; i < 1000; i++) rl.check('flood', i * 0.1);
  assert.equal(rl.check('flood', 100).count, 6, 'count saturates at maxRequests + 1');
  for (let i = 0; i < 100; i++) rl.check(`k${i}`, 10);
  assert.ok(rl.size() <= 100);
  rl.check('fresh', 5000);
  assert.equal(rl.size(), 1);
});

test('LRU eviction when the key table is full of active keys', () => {
  const rl = engine.createRateLimiter({ windowMs: 60_000, maxRequests: 10, maxKeys: 3 });
  rl.check('a', 0);
  rl.check('b', 1);
  rl.check('c', 2);
  rl.check('a', 3);
  rl.check('d', 4); // this evicts b as the least recently seen
  assert.equal(rl.size(), 3);
  assert.equal(rl.check('b', 5).count, 1, 'b started fresh after eviction');
});

test('configure() changes limits and reset() clears state', () => {
  const rl = engine.createRateLimiter({ windowMs: 1000, maxRequests: 1 });
  rl.check('x', 0);
  assert.equal(rl.check('x', 1).limited, true);
  rl.configure({ maxRequests: 10 });
  assert.equal(rl.options.maxRequests, 10);
  assert.equal(rl.check('x', 2).limited, false);
  rl.reset();
  assert.equal(rl.size(), 0);
  rl.configure({ windowMs: -5, maxRequests: 'x' });
  assert.equal(rl.options.windowMs, 1000, 'invalid values are ignored');
});

test('inspect: rateLimiter null -> not checked; breach -> 429 in block mode, logged in monitor mode', () => {
  const none = engine.inspect(getWith('q', 'a'), ctx({ rateLimiter: null }));
  assert.equal(none.rateLimit.checked, false);
  const config = { ...engine.DEFAULT_CONFIG, rateLimit: { enabled: true, windowMs: 1000, maxRequests: 2 } };
  const rl = engine.createRateLimiter({});
  const c = (now, extra = {}) => ctx({ rateLimiter: rl, clientKey: 'c_abc', config, now, ...extra });
  assert.equal(engine.inspect(getWith('q', 'a'), c(0)).rateLimit.count, 1);
  assert.equal(rl.options.maxRequests, 2, 'limiter synced to config');
  engine.inspect(getWith('q', 'a'), c(10));
  const d = engine.inspect(getWith('q', 'a'), c(20));
  assert.equal(d.rateLimit.limited, true);
  assert.equal(d.verdict, 'block');
  assert.equal(d.blockReason, 'RATE_LIMITED');
  assert.equal(d.statusCode, 429);
  assert.equal(d.action, 'blocked');
  assert.ok(d.explanation.some((l) => /Rate limit exceeded/.test(l)));
  const m = engine.inspect(getWith('q', 'a'), c(30, { config: { ...config, mode: 'monitor' } }));
  assert.equal(m.action, 'logged');
  assert.equal(m.blockReason, 'RATE_LIMITED');
  assert.equal(m.statusCode, null);
  const other = engine.inspect(getWith('q', 'a'), c(40, { clientKey: 'c_other' }));
  assert.equal(other.rateLimit.limited, false);
});

test('inspect: disabled rate limiting in config skips the stage', () => {
  const rl = engine.createRateLimiter({});
  const config = { ...engine.DEFAULT_CONFIG, rateLimit: { enabled: false, windowMs: 1000, maxRequests: 1 } };
  const d = engine.inspect(getWith('q', 'a'), ctx({ rateLimiter: rl, config }));
  assert.equal(d.rateLimit.checked, false);
  assert.equal(rl.size(), 0);
});
