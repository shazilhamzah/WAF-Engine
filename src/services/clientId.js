'use strict';
const crypto = require('node:crypto');

function normalizeIp(ip) {
  if (!ip) return 'unknown';
  const s = String(ip);
  // treat ipv4 mapped ipv6 addresses as plain ipv4
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

function clientIdFor(secret, ip) {
  if (!secret) throw new Error('clientIdFor requires a secret');
  return 'c_' + crypto.createHmac('sha256', String(secret)).update(normalizeIp(ip)).digest('hex').slice(0, 16);
}

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
