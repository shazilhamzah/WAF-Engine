'use strict';
/**
 * Pseudonymous client identifier (contract §4.2): raw IPs are never stored.
 * clientId = 'c_' + HMAC-SHA256(secret, ip).hex.slice(0, 16)
 */
const crypto = require('node:crypto');

function normalizeIp(ip) {
  if (!ip) return 'unknown';
  const s = String(ip);
  // Treat IPv4-mapped IPv6 addresses (::ffff:127.0.0.1) as their IPv4 form.
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

function clientIdFor(secret, ip) {
  if (!secret) throw new Error('clientIdFor requires a secret');
  return 'c_' + crypto.createHmac('sha256', String(secret)).update(normalizeIp(ip)).digest('hex').slice(0, 16);
}

/** Returns a memoising function ip -> clientId (bounded cache). */
function createClientIdentifier(secret) {
  const cache = new Map();
  return function identify(ip) {
    const key = normalizeIp(ip);
    let id = cache.get(key);
    if (!id) {
      id = clientIdFor(secret, key);
      if (cache.size > 5000) cache.clear();
      cache.set(key, id);
    }
    return id;
  };
}

module.exports = { clientIdFor, createClientIdentifier, normalizeIp };
