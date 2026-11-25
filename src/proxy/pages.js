'use strict';
// pages show only the event id and nothing about rules or inputs

const REASONS = Object.freeze({
  400: 'Bad Request', 403: 'Forbidden', 413: 'Payload Too Large', 429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
});

const MESSAGES = Object.freeze({
  400: 'The request was rejected because it is malformed.',
  403: 'The request was blocked by the web application firewall.',
  413: 'The request body is larger than the firewall allows.',
  429: 'Too many requests. Please slow down and try again later.',
  500: 'The firewall could not process the request.',
  502: 'The protected application is currently unavailable.',
  503: 'The firewall is temporarily unable to inspect requests.',
});

const BASE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
});

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function prefersJson(accept) {
  const a = String(accept || '').toLowerCase();
  const j = a.indexOf('application/json');
  if (j < 0) return false;
  const h = a.indexOf('text/html');
  return h < 0 || j < h;
}

function render(status, eventId, json, code) {
  const reason = REASONS[status] || 'Error';
  const message = MESSAGES[status] || 'The request could not be completed.';
  if (json) {
    const body = JSON.stringify({ error: { code, status, message, eventId: eventId || null } });
    return { headers: { ...BASE_HEADERS, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }, body };
  }
  const ref = eventId ? `<p>Reference: <code>${escapeHtml(eventId)}</code></p>` : '';
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${status} ${reason}</title></head>`
    + `<body><h1>${status} ${reason}</h1><p>${message}</p>${ref}<p>If you believe this is a mistake, contact the administrator and quote the reference.</p></body></html>`;
  return { headers: { ...BASE_HEADERS, 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': Buffer.byteLength(body) }, body };
}

const blockPage = (status, eventId, json) => render(status, eventId, json, 'WAF_BLOCKED');
const errorPage = (status, eventId, json) => render(status, eventId, json, status === 502 ? 'TARGET_UNAVAILABLE' : 'WAF_ERROR');

module.exports = { blockPage, errorPage, prefersJson, escapeHtml };
