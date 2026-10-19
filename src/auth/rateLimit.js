'use strict';
/**
 * In-memory sliding-window limiter used for API-side abuse controls (login attempts per client, analysis
 * submissions per user). The proxy uses the engine's own limiter (contract §3); this one is for the console.
 */

function createSlidingWindowLimiter({ windowMs, max, clock = () => Date.now(), maxKeys = 10000 }) {
  const hits = new Map(); // key -> number[] (timestamps, ascending)

  function prune(list, now) {
    while (list.length && list[0] <= now - windowMs) list.shift();
  }

  return {
    windowMs, max,
    /** Records a hit for key. Returns { limited, count, retryAfterSeconds }. A limited hit is not recorded. */
    hit(key) {
      const now = clock();
      let list = hits.get(key);
      if (!list) {
        if (hits.size >= maxKeys) {
          // Bounded memory: drop entries whose windows have fully elapsed, then the oldest key.
          for (const [k, l] of hits) { prune(l, now); if (!l.length) hits.delete(k); }
          if (hits.size >= maxKeys) hits.delete(hits.keys().next().value);
        }
        list = [];
        hits.set(key, list);
      }
      prune(list, now);
      if (list.length >= max) {
        return { limited: true, count: list.length, retryAfterSeconds: Math.max(1, Math.ceil((list[0] + windowMs - now) / 1000)) };
      }
      list.push(now);
      return { limited: false, count: list.length, retryAfterSeconds: 0 };
    },
    reset(key) { if (key === undefined) hits.clear(); else hits.delete(key); },
  };
}

/**
 * Login throttle (FR-5, NFR-7):
 *  - per username: `maxFailures` failures within `windowMs` -> locked for `lockMs` (applies identically to
 *    unknown usernames, so lockout behaviour does not reveal which accounts exist)
 *  - per client: `perClientMax` attempts per `perClientWindowMs`
 */
function createLoginThrottle({
  clock = () => Date.now(), maxFailures = 5, windowMs = 15 * 60 * 1000, lockMs = 15 * 60 * 1000,
  perClientMax = 20, perClientWindowMs = 60 * 1000,
} = {}) {
  const failures = new Map(); // usernameKey -> number[]
  const locks = new Map(); // usernameKey -> lockedUntil ms
  const clientLimiter = createSlidingWindowLimiter({ windowMs: perClientWindowMs, max: perClientMax, clock });
  const keyOf = (username) => String(username || '').trim().toLowerCase().slice(0, 64);

  return {
    maxFailures, windowMs, lockMs,
    checkClient(clientId) { return clientLimiter.hit(clientId || 'unknown'); },
    /** @param {string|null} persistedLockedUntil ISO from the users table (survives restarts) */
    lockStatus(username, persistedLockedUntil = null) {
      const now = clock();
      const key = keyOf(username);
      let until = locks.get(key) || 0;
      const persisted = persistedLockedUntil ? Date.parse(persistedLockedUntil) : 0;
      if (persisted > until) until = persisted;
      if (until > now) return { locked: true, lockedUntil: new Date(until).toISOString(), retryAfterSeconds: Math.ceil((until - now) / 1000) };
      if (locks.has(key)) locks.delete(key);
      return { locked: false, lockedUntil: null, retryAfterSeconds: 0 };
    },
    /** Returns { failures, lockedNow, lockedUntil } */
    recordFailure(username) {
      const now = clock();
      const key = keyOf(username);
      const list = (failures.get(key) || []).filter((t) => t > now - windowMs);
      list.push(now);
      if (failures.size > 10000 && !failures.has(key)) failures.delete(failures.keys().next().value);
      if (list.length >= maxFailures) {
        const lockedUntil = now + lockMs;
        locks.set(key, lockedUntil);
        failures.delete(key);
        return { failures: list.length, lockedNow: true, lockedUntil: new Date(lockedUntil).toISOString() };
      }
      failures.set(key, list);
      return { failures: list.length, lockedNow: false, lockedUntil: null };
    },
    recordSuccess(username) {
      const key = keyOf(username);
      failures.delete(key);
      locks.delete(key);
    },
    unlock(username) { this.recordSuccess(username); },
  };
}

module.exports = { createSlidingWindowLimiter, createLoginThrottle };
