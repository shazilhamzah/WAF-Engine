'use strict';
/**
 * HTTP helpers shared by integration tests, security tests and the evaluation harness.
 *
 *  - ApiClient  : JSON client for the Studio API (global fetch) that keeps the `waf_sid` cookie and the
 *                 CSRF token, and sends `X-CSRF-Token` on every state-changing request (contract §5).
 *  - rawRequest : low-level client (node:http) for the WAF proxy. Unlike fetch/URL it does NOT normalise
 *                 the path, so `../`, `%2e%2e`, double encoding and odd methods reach the WAF byte-for-byte.
 */
const http = require('node:http');

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

class ApiClient {
  /** @param {string} baseUrl e.g. http://127.0.0.1:53211 */
  constructor(baseUrl, { username = null, role = null } = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.sid = null;          // value of the waf_sid cookie
    this.csrfToken = null;
    this.user = null;
    this.username = username;
    this.role = role;
    this.lastSetCookie = [];
  }

  _absorbCookies(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    this.lastSetCookie = list;
    for (const c of list) {
      const m = /^waf_sid=([^;]*)/i.exec(c);
      if (!m) continue;
      const expired = /max-age=0/i.test(c) || /expires=Thu, 01 Jan 1970/i.test(c) || m[1] === '';
      this.sid = expired ? null : m[1];
    }
  }

  /**
   * Generic request. Returns { status, headers, body (parsed JSON or null), text }.
   * opts: { body (object → JSON), rawBody (string|Buffer), headers, csrf (false|string to override) }
   */
  async request(method, path, opts = {}) {
    method = method.toUpperCase();
    const headers = { accept: 'application/json', ...(opts.headers || {}) };
    if (this.sid && opts.cookie !== false) headers.cookie = `waf_sid=${this.sid}`;
    if (STATE_CHANGING.has(method)) {
      if (opts.csrf === undefined) { if (this.csrfToken) headers['x-csrf-token'] = this.csrfToken; } else if (opts.csrf) headers['x-csrf-token'] = opts.csrf;
    }
    let body;
    if (opts.rawBody !== undefined) body = opts.rawBody;
    else if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      if (!Object.keys(headers).some((h) => h.toLowerCase() === 'content-type')) headers['content-type'] = 'application/json';
    }
    const res = await fetch(this.baseUrl + path, { method, headers, body, redirect: 'manual' });
    this._absorbCookies(res);
    const text = await res.text();
    let json = null;
    if ((res.headers.get('content-type') || '').includes('json') && text) {
      try { json = JSON.parse(text); } catch { json = null; }
    }
    return { status: res.status, headers: res.headers, body: json, text };
  }

  get(p, o) { return this.request('GET', p, o); }
  post(p, body, o = {}) { return this.request('POST', p, { ...o, body }); }
  put(p, body, o = {}) { return this.request('PUT', p, { ...o, body }); }
  del(p, body, o = {}) { return this.request('DELETE', p, { ...o, body }); }

  async login(username, password) {
    const r = await this.post('/api/auth/login', { username, password });
    if (r.status === 200 && r.body) {
      this.csrfToken = r.body.csrfToken || null;
      this.user = r.body.user || null;
      this.username = username;
      this.role = r.body.user && r.body.user.role;
    }
    return r;
  }

  async logout() { return this.post('/api/auth/logout', undefined); }

  /** Re-reads the CSRF token from /api/auth/me (e.g. after a session refresh). */
  async refreshCsrf() {
    const r = await this.get('/api/auth/me');
    if (r.status === 200 && r.body && r.body.csrfToken) this.csrfToken = r.body.csrfToken;
    return r;
  }
}

/** Makes an arbitrary path acceptable to node:http (only chars outside 0x21–0x7E are %-encoded). */
function wireSafePath(p) {
  let out = '';
  for (const ch of String(p)) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x21 && cp <= 0x7e) out += ch;
    else out += Array.from(Buffer.from(ch, 'utf8')).map((b) => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
  }
  return out;
}

/**
 * Sends one request without any path normalisation.
 * Resolves { status, headers (lower-cased object), body: Buffer, text, ms, error? }.
 * Never rejects: network errors resolve with status 0 and `error` set (useful for "target down" cases).
 */
function rawRequest(baseUrl, { method = 'GET', path = '/', headers = {}, body = null, agent, timeoutMs = 15000 } = {}) {
  const u = new URL(baseUrl);
  const payload = body == null ? null : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  const h = { ...headers };
  if (payload && !Object.keys(h).some((k) => k.toLowerCase() === 'content-length')) h['content-length'] = String(payload.length);
  const started = process.hrtime.bigint();
  return new Promise((resolve) => {
    let req;
    try {
      req = http.request({
        host: u.hostname, port: u.port, method, path: wireSafePath(path), headers: h,
        agent: agent === undefined ? false : agent
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({ status: res.statusCode, headers: res.headers, body: buf, text: buf.toString('utf8'),
            ms: Number(process.hrtime.bigint() - started) / 1e6 });
        });
        res.on('error', (e) => resolve({ status: res.statusCode || 0, headers: res.headers || {}, body: Buffer.alloc(0), text: '', error: e.code || e.message, ms: 0 }));
      });
    } catch (e) {
      resolve({ status: 0, headers: {}, body: Buffer.alloc(0), text: '', error: e.code || e.message, ms: 0 });
      return;
    }
    req.setTimeout(timeoutMs, () => req.destroy(new Error('TIMEOUT')));
    req.on('error', (e) => resolve({ status: 0, headers: {}, body: Buffer.alloc(0), text: '', error: e.code || e.message,
      ms: Number(process.hrtime.bigint() - started) / 1e6 }));
    if (payload) {
      // Large bodies: the server may answer (413) and close before we finish writing — that is fine.
      req.on('error', () => {});
      req.end(payload);
    } else req.end();
  });
}

module.exports = { ApiClient, rawRequest, wireSafePath };
