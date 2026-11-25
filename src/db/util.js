'use strict';
const crypto = require('node:crypto');

const ID_PREFIXES = Object.freeze({ user: 'usr_', event: 'evt_', exception: 'exc_', audit: 'aud_', request: 'req_' });
const ID_RE = /^(usr|evt|exc|aud|req)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Server-generated identifier, e.g. newId('evt_') -> 'evt_1b9d6bcd-…'. */
function newId(prefix) {
  if (!Object.values(ID_PREFIXES).includes(prefix)) throw new Error(`Unknown id prefix ${prefix}`);
  return prefix + crypto.randomUUID();
}

function isId(value, prefix) {
  return typeof value === 'string' && value.startsWith(prefix) && ID_RE.test(value);
}

/**
 * Canonical JSON: object keys sorted recursively, no whitespace, `undefined` dropped (like JSON.stringify).
 * Used for the audit hash chain so the hash is independent of property insertion order.
 */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) return 'null';
    return JSON.stringify(value === undefined ? null : value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => (v === undefined || typeof v === 'function' ? 'null' : canonicalJson(v))).join(',') + ']';
  }
  if (typeof value.toJSON === 'function') return canonicalJson(value.toJSON());
  const keys = Object.keys(value).filter((k) => value[k] !== undefined && typeof value[k] !== 'function').sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/** Escapes LIKE wildcards; use with `LIKE ? ESCAPE '\\'`. */
function escapeLike(text) {
  return String(text).replace(/[\\%_]/g, (c) => '\\' + c);
}

function parseJson(text, fallback = null) {
  if (text === null || text === undefined) return fallback;
  try { return JSON.parse(text); } catch { return fallback; }
}

function nowIso(clock) {
  return new Date(clock ? clock() : Date.now()).toISOString();
}

function toBool(v) { return v === 1 || v === true || v === 1n; }

module.exports = { ID_PREFIXES, newId, isId, canonicalJson, sha256Hex, escapeLike, parseJson, nowIso, toBool };
