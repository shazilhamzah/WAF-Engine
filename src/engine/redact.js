'use strict';
/**
 * Redaction and evidence excerpts (data minimization, contract §4.2).
 *
 * - redact(value): deep copy with secrets masked. Keys that are sensitive header names or look like
 *   secrets (password, token, api key, session, card number ...) are replaced by MASK, and secret
 *   parameters embedded in strings (query strings, form bodies, JSON text, Authorization schemes)
 *   have their values masked.
 * - excerpt(str, index, len): ≤ 120 characters around [index, index+len), control / bidi / invisible
 *   characters escaped so the excerpt is safe to show and log.
 * - maskSecretsInString(str, preserveLength): masks secret values inside a string; with
 *   preserveLength the result keeps the same length so match indices remain valid.
 */

const MASK = '[REDACTED]';
const MAX_EXCERPT = 120;

const SENSITIVE_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token',
  'x-csrf-token', 'x-xsrf-token', 'x-access-token',
]);
const SENSITIVE_NAME_RE = /pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|session|credit|card|cvv|ssn|csrf|credential|authori[sz]ation|cookie|private[_-]?key|jwt/i;
const SENSITIVE_COOKIE_RE = /sid|sess|auth|jwt|remember|token|login/i;

function isSensitiveName(name) {
  return typeof name === 'string' && name.length > 0 && SENSITIVE_NAME_RE.test(name);
}

function isSensitiveHeader(name) {
  if (typeof name !== 'string') return false;
  const n = name.toLowerCase();
  return SENSITIVE_HEADERS.has(n) || SENSITIVE_NAME_RE.test(n);
}

/**
 * Whether evidence at a match location must not reveal its value (contract §3.5 locations).
 * `query.user.password` -> true; `header.authorization` -> true; `cookie.sid` -> true.
 */
function isSensitiveLocation(location) {
  if (typeof location !== 'string') return false;
  const dot = location.indexOf('.');
  if (dot === -1) return false;
  const kind = location.slice(0, dot);
  const name = location.slice(dot + 1);
  if (kind === 'header') return isSensitiveHeader(name);
  if (kind === 'cookie') return isSensitiveName(name) || SENSITIVE_COOKIE_RE.test(name);
  if (kind === 'query' || kind === 'body') {
    if (isSensitiveName(name)) return true;
    return name.split('.').some(isSensitiveName);
  }
  return false;
}

function safeDecodeName(name) {
  try {
    return decodeURIComponent(name.replace(/\+/g, ' '));
  } catch {
    return name;
  }
}

const PAIR_RE = /(^|[?&;\s])([^=&;\s?]{1,64})=([^&;\s]*)/g;
const JSON_PAIR_RE = /"((?:[^"\\]|\\.){1,64})"(\s*:\s*)"((?:[^"\\]|\\.)*)"/g;
const AUTH_SCHEME_RE = /\b(Bearer|Basic|Digest|Token)(\s+)([A-Za-z0-9._~+/=-]{4,})/g;

/** Masks secret values embedded in a string (query strings, form bodies, JSON text, auth schemes). */
function maskSecretsInString(str, preserveLength = false) {
  if (typeof str !== 'string' || str === '') return str;
  const mask = (v) => (preserveLength ? '*'.repeat(v.length) : MASK);
  let out = str;
  if (out.indexOf('=') !== -1) {
    out = out.replace(PAIR_RE, (m, pre, name, value) => (
      value && isSensitiveName(safeDecodeName(name)) ? `${pre}${name}=${mask(value)}` : m));
  }
  if (out.indexOf('"') !== -1 && out.indexOf(':') !== -1) {
    out = out.replace(JSON_PAIR_RE, (m, name, sep, value) => (
      value && isSensitiveName(name) ? `"${name}"${sep}"${mask(value)}"` : m));
  }
  out = out.replace(AUTH_SCHEME_RE, (m, scheme, ws, token) => `${scheme}${ws}${mask(token)}`);
  return out;
}

/**
 * Deep copy with secrets masked. Never throws; cycles and excessive depth are replaced by markers.
 */
function redact(value) {
  const seen = new WeakSet();
  const walk = (v, depth, key) => {
    if (v === null || v === undefined) return v;
    const t = typeof v;
    if (t === 'string') return maskSecretsInString(v, false);
    if (t === 'number' || t === 'boolean') return v;
    if (t === 'bigint') return v.toString();
    if (t === 'function' || t === 'symbol') return undefined;
    if (depth > 20) return '[TRUNCATED]';
    if (Buffer.isBuffer(v) || v instanceof Uint8Array) {
      if (key === 'body' && v.length <= 1048576) return maskSecretsInString(Buffer.from(v).toString('utf8'), false);
      return `[${v.length} bytes]`;
    }
    if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.toISOString();
    if (seen.has(v)) return '[CIRCULAR]';
    seen.add(v);
    let out;
    if (Array.isArray(v)) {
      out = v.map((item) => walk(item, depth + 1, key));
    } else {
      out = {};
      for (const k of Object.keys(v)) {
        let item;
        try {
          item = v[k];
        } catch {
          item = undefined;
        }
        const masked = (isSensitiveHeader(k) || isSensitiveName(k)) && item !== null && item !== undefined && item !== '';
        const res = masked ? MASK : walk(item, depth + 1, k);
        if (res !== undefined) Object.defineProperty(out, k, { value: res, enumerable: true, writable: true, configurable: true });
      }
    }
    seen.delete(v);
    return out;
  };
  try {
    return walk(value, 0, null);
  } catch {
    return MASK;
  }
}

function escapeChar(ch) {
  const cp = ch.codePointAt(0);
  if (ch === '\n') return '\\n';
  if (ch === '\r') return '\\r';
  if (ch === '\t') return '\\t';
  if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return '\\x' + cp.toString(16).padStart(2, '0');
  if ((cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2069)
    || cp === 0xfeff || cp === 0x2028 || cp === 0x2029 || cp === 0x00ad || (cp >= 0xd800 && cp <= 0xdfff)) {
    return '\\u' + cp.toString(16).padStart(4, '0');
  }
  return ch;
}

/**
 * Safe excerpt of `str` around the region [index, index + len). Result is at most 120 characters,
 * starts/ends with '…' when truncated, and has control, bidi and invisible characters escaped.
 */
function excerpt(str, index = 0, len = 0) {
  let s;
  try {
    s = typeof str === 'string' ? str : (str === null || str === undefined ? '' : String(str));
  } catch {
    return '';
  }
  if (s === '') return '';
  const idx = Math.max(0, Math.min(s.length, Number.isFinite(Number(index)) ? Math.floor(Number(index)) : 0));
  const regionLen = Math.max(0, Number.isFinite(Number(len)) ? Math.floor(Number(len)) : 0);
  const context = regionLen >= MAX_EXCERPT ? 0 : Math.min(30, Math.floor((MAX_EXCERPT - regionLen) / 2));
  const start = Math.max(0, idx - context);
  let out = start > 0 ? '…' : '';
  let i = start;
  while (i < s.length) {
    const cp = s.codePointAt(i);
    const ch = String.fromCodePoint(cp);
    const piece = escapeChar(ch);
    const remainingAfter = i + ch.length < s.length;
    const budget = MAX_EXCERPT - (remainingAfter ? 1 : 0);
    if (out.length + piece.length > budget) {
      out += '…';
      return out.slice(0, MAX_EXCERPT);
    }
    out += piece;
    i += ch.length;
  }
  return out;
}

module.exports = {
  MASK,
  MAX_EXCERPT,
  SENSITIVE_HEADERS,
  SENSITIVE_NAME_RE,
  isSensitiveName,
  isSensitiveHeader,
  isSensitiveLocation,
  maskSecretsInString,
  redact,
  excerpt,
};
