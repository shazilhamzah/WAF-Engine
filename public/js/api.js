import { describeError } from './lib/errors.js';
import { buildQuery } from './lib/query.js';

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

let csrfToken = null;
let unauthorizedHandler = null;
let lastRequestAt = Date.now();

export class ApiError extends Error {
  constructor({ status, code, serverMessage, details, requestId, retryAfter }) {
    super(code || `HTTP_${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || null;
    this.serverMessage = serverMessage || null;
    this.details = Array.isArray(details) ? details : [];
    this.requestId = requestId || null;
    this.retryAfter = Number.isFinite(retryAfter) ? retryAfter : null;
    this.friendly = describeError(this);
  }
}

export function setCsrfToken(token) { csrfToken = token || null; }
export function getCsrfToken() { return csrfToken; }
export function onUnauthorized(fn) { unauthorizedHandler = fn; }
export function lastActivity() { return lastRequestAt; }

async function readError(res) {
  let payload = null;
  try { payload = await res.json(); } catch { payload = null; }
  const err = (payload && payload.error) || {};
  let retryAfter = Number(payload && (payload.retryAfterSeconds ?? err.retryAfterSeconds));
  if (!Number.isFinite(retryAfter)) retryAfter = Number(res.headers.get('Retry-After'));
  return new ApiError({
    status: res.status,
    code: typeof err.code === 'string' ? err.code : null,
    serverMessage: typeof err.message === 'string' ? err.message : null,
    details: err.details,
    requestId: err.requestId,
    retryAfter: Number.isFinite(retryAfter) ? retryAfter : null,
  });
}

// crypto.randomUUID only exists in secure contexts, so plain-http access (e.g. over a VPN IP) falls back
export function uuid() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * One key per user intent: made when the action starts, reused by every retry of it, and dropped
 * once it succeeds. A different payload is a different intent, so it gets a fresh key too.
 */
export function actionKey() {
  let key = null;
  let payload = null;
  return {
    for(body) {
      if (!key || body !== payload) { key = uuid(); payload = body; }
      return key;
    },
    reset() { key = null; payload = null; },
  };
}

const RETRY_DELAYS_MS = [400, 1200];
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

export async function request(method, path, { body, query, raw = false, signal, idempotencyKey } = {}) {
  const m = method.toUpperCase();
  const headers = { Accept: 'application/json' };
  const init = { method: m, credentials: 'same-origin', headers, cache: 'no-store', signal };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  if (STATE_CHANGING.has(m) && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  if (idempotencyKey) {
    headers['Idempotency-Key'] = typeof idempotencyKey === 'string' ? idempotencyKey : idempotencyKey.for(init.body || '');
  }
  const url = `${path}${buildQuery(query)}`;
  let res;
  // only keyed requests retry on their own: the key makes a repeat safe even if the first one landed
  for (let attempt = 0; ; attempt += 1) {
    try {
      res = await fetch(url, init);
    } catch (e) {
      if (e && e.name === 'AbortError') throw e;
      if (idempotencyKey && attempt < RETRY_DELAYS_MS.length) { await wait(RETRY_DELAYS_MS[attempt]); continue; }
      throw new ApiError({ status: 0, code: 'NETWORK_ERROR' });
    }
    if (idempotencyKey && res.status === 409 && attempt < RETRY_DELAYS_MS.length) {
      const peek = await res.clone().json().catch(() => null);
      if (peek && peek.error && peek.error.code === 'IDEMPOTENCY_IN_PROGRESS') { await wait(RETRY_DELAYS_MS[attempt]); continue; }
    }
    break;
  }
  lastRequestAt = Date.now();
  if (!res.ok) {
    const err = await readError(res);
    const isAuthCall = path === '/api/auth/login' || path === '/api/auth/me';
    if (res.status === 401 && !isAuthCall && unauthorizedHandler) unauthorizedHandler(err.code);
    throw err;
  }
  if (raw) return res;
  if (res.status === 204) return null;
  const type = res.headers.get('Content-Type') || '';
  if (!type.includes('application/json')) {
    throw new ApiError({ status: res.status, code: 'BAD_RESPONSE' });
  }
  try {
    return await res.json();
  } catch {
    throw new ApiError({ status: res.status, code: 'BAD_RESPONSE' });
  }
}

export const get = (path, query) => request('GET', path, { query });
export const post = (path, body, idempotencyKey) => request('POST', path, { body: body === undefined ? {} : body, idempotencyKey });
export const put = (path, body) => request('PUT', path, { body: body === undefined ? {} : body });
export const del = (path, body) => request('DELETE', path, { body });

export function filenameFromDisposition(header, fallback) {
  const m = /filename="?([A-Za-z0-9._-]+)"?/.exec(header || '');
  return m ? m[1] : fallback;
}

export async function download(path, query, fallbackName) {
  const res = await request('GET', path, { query, raw: true });
  const blob = await res.blob();
  const name = filenameFromDisposition(res.headers.get('Content-Disposition'), fallbackName);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.setAttribute('href', url);
  a.setAttribute('download', name);
  a.hidden = true;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  return { name, size: blob.size };
}

const enc = encodeURIComponent;

export const api = {
  health: () => get('/api/health'),
  login: (username, password) => request('POST', '/api/auth/login', { body: { username, password } }),
  logout: () => post('/api/auth/logout'),
  me: () => get('/api/auth/me'),
  changePassword: (currentPassword, newPassword) => post('/api/auth/password', { currentPassword, newPassword }),

  stats: (hours) => get('/api/stats', { hours }),
  events: (filters) => get('/api/events', filters),
  event: (id) => get(`/api/events/${enc(id)}`),
  compare: (a, b) => get('/api/events/compare', { a, b }),
  analyze: (sample, label, key) => post('/api/analyze', label ? { label, sample } : { sample }, key),
  importSamples: (filename, samples, key) => post('/api/import', { filename, samples }, key),
  replay: (id, key) => post(`/api/events/${enc(id)}/replay`, undefined, key),

  rules: () => get('/api/rules'),
  ruleHistory: (id) => get(`/api/rules/${enc(id)}/history`),
  validateRule: (source) => post('/api/rules/validate', { source }),
  createRule: (source, enabled, key) => post('/api/rules', { source, enabled }, key),
  updateRule: (id, body) => put(`/api/rules/${enc(id)}`, body),
  deleteRule: (id) => del(`/api/rules/${enc(id)}`, { confirm: true }),

  config: () => get('/api/config'),
  configHistory: () => get('/api/config/history'),
  updateConfig: (config, reason) => put('/api/config', { config, reason, confirm: true }),

  exceptions: (status) => get('/api/exceptions', { status }),
  previewException: (ruleId, scope) => post('/api/exceptions/preview', { ruleId, scope }),
  requestException: (body, key) => post('/api/exceptions', body, key),
  approveException: (id, note) => post(`/api/exceptions/${enc(id)}/approve`, note ? { confirm: true, note } : { confirm: true }),
  rejectException: (id, note) => post(`/api/exceptions/${enc(id)}/reject`, note ? { note } : {}),
  revokeException: (id, note) => post(`/api/exceptions/${enc(id)}/revoke`, note ? { confirm: true, note } : { confirm: true }),

  audit: (filters) => get('/api/audit', filters),
  verifyAudit: () => get('/api/audit/verify'),

  exportReport: (query) => download('/api/reports/export', query, `waf-studio-report.${query.format || 'html'}`),

  users: () => get('/api/users'),
  createUser: (username, password, role, key) => post('/api/users', { username, password, role }, key),
  updateUser: (id, body) => put(`/api/users/${enc(id)}`, body),
};
