'use strict';
const http = require('node:http');
const { Readable } = require('node:stream');
require('./silenceDep0060').installDep0060Filter(); // see file: hides only http-proxy's DEP0060
const httpProxy = require('http-proxy');
const { normalizeLogger } = require('../services/logger');
const { createAuditor } = require('../services/audit');
const { createClientIdentifier } = require('../services/clientId');
const { blockPage, errorPage, prefersJson } = require('./pages');

const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'proxy-authorization', 'proxy-authenticate'];
const PRUNE_EVERY = 1000;
const DEFAULT_RETENTION = 100000;

function flattenHeaders(headers) {
  const out = {};
  for (const [k, val] of Object.entries(headers || {})) {
    out[k.toLowerCase()] = Array.isArray(val) ? val.join(', ') : String(val);
  }
  return out;
}

function stripHopByHop(headers) {
  const listed = String(headers.connection || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  for (const h of [...HOP_BY_HOP, ...listed]) delete headers[h];
}

function readBody(req, cap) {
  return new Promise((resolve) => {
    const declared = Number.parseInt(req.headers['content-length'], 10);
    if (Number.isFinite(declared) && declared > cap - 1) {
      resolve({ body: Buffer.alloc(0), received: declared, overflow: true });
      return;
    }
    const chunks = [];
    let received = 0;
    let done = false;
    const finish = (overflow) => {
      if (done) return;
      done = true;
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      resolve({ body: Buffer.concat(chunks), received, overflow });
    };
    const onData = (chunk) => {
      received += chunk.length;
      const room = cap - (received - chunk.length);
      if (room > 0) chunks.push(room >= chunk.length ? chunk : chunk.subarray(0, room));
      if (received >= cap) { req.pause(); finish(true); }
    };
    const onEnd = () => finish(false);
    const onError = () => finish(false);
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
  });
}

function createProxyServer({ db, engineState, targetUrl, secret, logger, audit, retention = DEFAULT_RETENTION } = {}) {
  if (!db || !engineState || !targetUrl || !secret) throw new Error('createProxyServer requires db, engineState, targetUrl and secret');
  const log = normalizeLogger(logger);
  const auditor = audit || createAuditor({ db, logger: log });
  const identify = createClientIdentifier(secret);
  const engine = engineState.engine;
  let stored = 0;
  let lastTargetErrorAudit = 0;

  const proxy = httpProxy.createProxyServer({
    target: targetUrl, xfwd: true, changeOrigin: false, ws: false, proxyTimeout: 30000, timeout: 30000,
  });
  proxy.on('proxyRes', (proxyRes) => {
    delete proxyRes.headers['x-powered-by'];
  });
  // last resort so a proxy error cannot crash the process
  proxy.on('error', (err, req, res) => onTargetError(err, req, res));

  function onTargetError(err, req, res) {
    log.warn('proxy target error', { code: err && err.code, path: req && req.url ? String(req.url).split('?')[0].slice(0, 200) : null });
    const now = Date.now();
    if (now - lastTargetErrorAudit > 1000) {
      lastTargetErrorAudit = now;
      auditor.system('system.error', {
        outcome: 'failure', targetType: 'proxy', targetId: 'target',
        details: { reason: 'target_unavailable', code: (err && err.code) || 'UNKNOWN', eventId: (req && req.wafEventId) || null },
        clientId: (req && req.wafClientId) || null,
      });
    }
    if (res && typeof res.writeHead === 'function' && !res.headersSent) {
      const page = errorPage(502, req && req.wafEventId, prefersJson(req && req.headers && req.headers.accept));
      res.writeHead(502, page.headers);
      res.end(page.body);
    } else if (res && typeof res.destroy === 'function') {
      res.destroy();
    }
  }

  function storeEvent(decision, clientKey, latencyMs, raw, ctx) {
    try {
      const event = db.events.record({
        source: 'proxy', decision, clientId: clientKey, latencyMs,
        fallback: { method: raw.method, url: raw.url, rulesetVersion: ctx.rulesetVersion, configVersion: ctx.configVersion },
      });
      stored += 1;
      if (stored % PRUNE_EVERY === 0) db.events.prune(retention);
      return event.id;
    } catch (err) {
      log.error('failed to store proxy event', { err });
      return null;
    }
  }

  async function handle(req, res) {
    const config = engineState.getConfig();
    const maxBody = (config && config.limits && config.limits.maxBodyBytes) || 1048576;
    const { body, received, overflow } = await readBody(req, maxBody + 1);
    const headers = flattenHeaders(req.headers);
    const remoteAddress = req.socket && req.socket.remoteAddress;
    const clientKey = identify(remoteAddress);
    req.wafClientId = clientKey;
    const raw = { method: req.method, url: req.url, headers, body: body.length ? body : null, bodyBytes: received, remoteAddress };
    const ctx = engineState.getContext({ clientKey, withRateLimit: true });

    let decision;
    const started = process.hrtime.bigint();
    try {
      decision = engine.inspect(raw, ctx);
    } catch (err) {
      // fail closed so nothing is forwarded if the engine cannot decide
      log.error('engine.inspect threw', { err });
      auditor.system('system.error', { outcome: 'failure', targetType: 'engine', targetId: 'inspect', details: { reason: 'inspect_failed' }, clientId: clientKey });
      const page = errorPage(503, null, prefersJson(headers.accept));
      res.writeHead(503, { ...page.headers, Connection: 'close' });
      res.end(page.body);
      return;
    }
    const measured = Number(process.hrtime.bigint() - started) / 1e6;

    if (overflow && decision.action !== 'blocked') {
      // never buffer or forward more than the body limit
      decision = {
        ...decision,
        verdict: 'block', action: 'blocked', wouldBlock: true, statusCode: 413, blockReason: 'BODY_TOO_LARGE',
        explanation: [...(decision.explanation || []), `Proxy safety limit: bodies larger than ${maxBody} bytes are never forwarded, even in monitor mode.`],
      };
    }
    const latencyMs = decision.timings && Number.isFinite(decision.timings.totalMs) ? decision.timings.totalMs : measured;
    const eventId = storeEvent(decision, clientKey, latencyMs, raw, ctx);
    req.wafEventId = eventId;
    if (eventId) res.setHeader('X-WAF-Event-Id', eventId);

    if (decision.action === 'blocked') {
      const status = [400, 403, 413, 429].includes(decision.statusCode) ? decision.statusCode : 403;
      const page = blockPage(status, eventId, prefersJson(headers.accept));
      const extra = { 'X-WAF-Action': 'blocked' };
      if (status === 429) {
        const windowMs = (decision.rateLimit && decision.rateLimit.windowMs) || (config.rateLimit && config.rateLimit.windowMs) || 60000;
        extra['Retry-After'] = String(Math.max(1, Math.ceil(windowMs / 1000)));
      }
      if (overflow || status === 413) extra.Connection = 'close';
      res.writeHead(status, { ...page.headers, ...extra });
      res.end(page.body);
      return;
    }

    res.setHeader('X-WAF-Action', decision.action === 'logged' ? 'logged' : 'allowed');
    stripHopByHop(req.headers);
    if (body.length || req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      req.headers['content-length'] = String(body.length);
    } else {
      delete req.headers['content-length'];
    }
    proxy.web(req, res, { buffer: Readable.from(body.length ? [body] : []) }, (err) => onTargetError(err, req, res));
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log.error('proxy handler failed', { err });
      if (!res.headersSent) {
        const page = errorPage(500, req.wafEventId, prefersJson(req.headers.accept));
        res.writeHead(500, page.headers);
        res.end(page.body);
      } else {
        res.destroy();
      }
    });
  });
  // upgrade requests are not inspected so they are refused
  server.on('upgrade', (req, socket) => { socket.end('HTTP/1.1 501 Not Implemented\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'); });
  server.on('clientError', (err, socket) => {
    if (socket.writable && !socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    else socket.destroy();
  });
  server.on('close', () => { try { proxy.close(); } catch { /* ignore */ } });
  server.wafProxy = proxy;
  return server;
}

module.exports = { createProxyServer, readBody, flattenHeaders, stripHopByHop, HOP_BY_HOP };
