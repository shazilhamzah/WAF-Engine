'use strict';
/**
 * Per-client sliding-window rate limiter (FR-5, pipeline step 5).
 *
 * Algorithm: a sliding *log* per client key. Each check prunes timestamps older than `windowMs`,
 * appends the current time and compares the count with `maxRequests` (the current request counts,
 * so request number maxRequests + 1 inside any window is limited). Limited requests are also
 * recorded, so a client that keeps flooding stays limited.
 *
 * Memory is bounded:
 *  - per key at most maxRequests + 1 timestamps are kept (older ones cannot change the outcome);
 *  - at most `maxKeys` keys are tracked; stale keys (no request inside the window) are swept at most
 *    once per window and whenever the table is full; if it is still full the least-recently-seen key
 *    is evicted (Map insertion order is refreshed on every access).
 *
 * The clock is injectable: check(key, now) uses `now` when it is a finite number.
 */

const LIMITS = Object.freeze({ windowMs: [1000, 3600000], maxRequests: [1, 100000], maxKeys: [1, 1000000] });
const DEFAULTS = Object.freeze({ windowMs: 60000, maxRequests: 300, maxKeys: 10000 });

function pick(value, [min, max], fallback) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
}

function createRateLimiter(opts = {}) {
  let windowMs = DEFAULTS.windowMs;
  let maxRequests = DEFAULTS.maxRequests;
  let maxKeys = DEFAULTS.maxKeys;
  const buckets = new Map();
  let lastSweep = -Infinity;

  function prune(b, now) {
    const cutoff = now - windowMs;
    while (b.head < b.ts.length && b.ts[b.head] <= cutoff) b.head++;
    if (b.head > 32 && b.head * 2 > b.ts.length) {
      b.ts = b.ts.slice(b.head);
      b.head = 0;
    }
  }

  function sweep(now) {
    for (const [k, b] of buckets) {
      prune(b, now);
      if (b.head >= b.ts.length) buckets.delete(k);
    }
    lastSweep = now;
  }

  function configure(o = {}) {
    const src = o && typeof o === 'object' ? o : {};
    windowMs = pick(src.windowMs, LIMITS.windowMs, windowMs);
    maxRequests = pick(src.maxRequests, LIMITS.maxRequests, maxRequests);
    maxKeys = pick(src.maxKeys, LIMITS.maxKeys, maxKeys);
    while (buckets.size > maxKeys) buckets.delete(buckets.keys().next().value);
    return { windowMs, maxRequests, maxKeys };
  }

  /**
   * @returns {{ checked: true, limited: boolean, count: number, limit: number, windowMs: number, retryAfterSeconds: number }}
   */
  function check(key, now) {
    const t = Number.isFinite(now) ? now : Date.now();
    const k = String(key === undefined || key === null || key === '' ? 'anonymous' : key).slice(0, 256);
    if (t - lastSweep >= windowMs || t < lastSweep) sweep(t);
    let b = buckets.get(k);
    if (b) {
      buckets.delete(k); // refresh LRU position
    } else {
      b = { ts: [], head: 0 };
      if (buckets.size >= maxKeys) {
        sweep(t);
        while (buckets.size >= maxKeys) buckets.delete(buckets.keys().next().value);
      }
    }
    buckets.set(k, b);
    prune(b, t);
    b.ts.push(t);
    let count = b.ts.length - b.head;
    if (count > maxRequests + 1) {
      b.head += count - (maxRequests + 1);
      count = maxRequests + 1;
    }
    const limited = count > maxRequests;
    let retryAfterSeconds = 0;
    if (limited) {
      const pivot = b.ts[b.head + count - maxRequests];
      retryAfterSeconds = Math.max(1, Math.ceil((pivot + windowMs - t) / 1000));
    }
    return { checked: true, limited, count, limit: maxRequests, windowMs, retryAfterSeconds };
  }

  function reset() {
    buckets.clear();
    lastSweep = -Infinity;
  }

  configure(opts);
  return {
    check,
    configure,
    reset,
    size: () => buckets.size,
    get options() {
      return { windowMs, maxRequests, maxKeys };
    },
  };
}

module.exports = { createRateLimiter, DEFAULTS };
