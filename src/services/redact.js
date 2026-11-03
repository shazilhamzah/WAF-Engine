'use strict';

const MASK = '[REDACTED]';
const SECRET_KEY_RE = /passw(or)?d|passphrase|^pass$|pwd|secret|token|cookie|authori[sz]ation|api[-_]?key|^session$|session[-_]?(id|token|key)|csrf|credential|private[-_]?key|^sid$|^waf_sid$/i;
const SECRET_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token',
  'x-csrf-token', 'x-xsrf-token',
]);

function isSecretKey(key) {
  return typeof key === 'string' && SECRET_KEY_RE.test(key);
}

function redact(value, depth = 0, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object') return value;
  if (depth > 12) return '[TRUNCATED]';
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);
  if (Buffer.isBuffer(value)) return `[${value.length} bytes]`;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1, seen));
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    out[k] = isSecretKey(k) && v !== null && v !== undefined ? MASK : redact(v, depth + 1, seen);
  }
  return out;
}

function redactHeaders(headers) {
  const out = {};
  for (const [name, value] of Object.entries(headers || {})) {
    out[name] = SECRET_HEADERS.has(name.toLowerCase()) || isSecretKey(name) ? MASK : value;
  }
  return out;
}

function redactBody(body, contentType) {
  if (typeof body !== 'string' || body === '') return body;
  const ct = String(contentType || '').toLowerCase();
  const trimmed = body.trim();
  if (ct.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.stringify(redact(JSON.parse(trimmed)));
    } catch { /* not json so fall through */ }
  }
  if (ct.includes('x-www-form-urlencoded') || (/^[^\s=&]+=[^\s]*(&[^\s=&]+=[^\s]*)*$/.test(trimmed) && !ct.includes('json'))) {
    let changed = false;
    const parts = body.split('&').map((pair) => {
      const eq = pair.indexOf('=');
      if (eq <= 0) return pair;
      let name;
      try { name = decodeURIComponent(pair.slice(0, eq).replace(/\+/g, ' ')); } catch { name = pair.slice(0, eq); }
      if (isSecretKey(name)) { changed = true; return `${pair.slice(0, eq)}=${encodeURIComponent(MASK)}`; }
      return pair;
    });
    return changed ? parts.join('&') : body;
  }
  return body;
}

function redactPathQuery(p) {
  if (typeof p !== 'string') return p;
  const q = p.indexOf('?');
  if (q < 0) return p;
  const hashAt = p.indexOf('#', q);
  const query = hashAt < 0 ? p.slice(q + 1) : p.slice(q + 1, hashAt);
  const masked = query.split('&').map((pair) => {
    const eq = pair.indexOf('=');
    if (eq <= 0) return pair;
    let name;
    try { name = decodeURIComponent(pair.slice(0, eq).replace(/\+/g, ' ')); } catch { name = pair.slice(0, eq); }
    return isSecretKey(name) ? `${pair.slice(0, eq)}=${encodeURIComponent(MASK)}` : pair;
  }).join('&');
  return p.slice(0, q + 1) + masked + (hashAt < 0 ? '' : p.slice(hashAt));
}

function redactSample(sample) {
  if (!sample) return null;
  const headers = redactHeaders(sample.headers || {});
  const ct = Object.entries(sample.headers || {}).find(([k]) => k.toLowerCase() === 'content-type');
  return {
    method: sample.method,
    path: redactPathQuery(sample.path),
    headers,
    body: sample.body === undefined ? null : redactBody(sample.body, ct ? ct[1] : ''),
  };
}

module.exports = { MASK, redact, redactHeaders, redactBody, redactSample, redactPathQuery, isSecretKey };
