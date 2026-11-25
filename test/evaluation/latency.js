'use strict';
/**
 * T6 latency overhead: the same benign requests sent (a) directly to the vulnerable target and
 * (b) through the WAF proxy, interleaved one-by-one so both sides see the same machine load.
 * Each side uses its own keep-alive agent with one socket so connection setup is not measured.
 * Overhead = proxy statistic − direct statistic (ms).
 */
const http = require('node:http');
const { rawRequest } = require('../helpers/http');
const { summarize, round } = require('./stats');

const DEFAULT_THRESHOLD_P95_MS = 25;

const SCENARIOS = {
  'GET /search?q=mug': { method: 'GET', path: '/search?q=mug', headers: { 'user-agent': 'Mozilla/5.0 (WAF Studio evaluation)' }, body: null },
  'POST /api/echo (2 KB form)': {
    method: 'POST', path: '/api/echo', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'Mozilla/5.0 (WAF Studio evaluation)' },
    body: 'comment=' + 'lorem ipsum dolor sit amet '.repeat(76).slice(0, 2040)
  }
};

/**
 * @param {{ directUrl: string, proxyUrl: string, n?: number, warmup?: number, thresholdMs?: number, scenarios?: string[], onProgress?: Function }} o
 */
async function measureOverhead(o) {
  const n = o.n || 300;
  const warmup = o.warmup ?? 30;
  const thresholdMs = o.thresholdMs || DEFAULT_THRESHOLD_P95_MS;
  const names = o.scenarios || Object.keys(SCENARIOS);
  const results = [];
  for (const name of names) {
    const sc = SCENARIOS[name];
    const directAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const proxyAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const direct = [];
    const proxied = [];
    const errors = { direct: 0, proxy: 0, nonSuccess: 0 };
    try {
      for (let i = 0; i < warmup; i++) {
        await rawRequest(o.directUrl, { ...sc, agent: directAgent });
        await rawRequest(o.proxyUrl, { ...sc, agent: proxyAgent });
      }
      for (let i = 0; i < n; i++) {
        // alternate which side goes first to cancel ordering effects
        const order = i % 2 === 0 ? ['d', 'p'] : ['p', 'd'];
        for (const side of order) {
          const r = await rawRequest(side === 'd' ? o.directUrl : o.proxyUrl, { ...sc, agent: side === 'd' ? directAgent : proxyAgent });
          if (r.status === 0) { errors[side === 'd' ? 'direct' : 'proxy']++; continue; }
          if (r.status >= 300) errors.nonSuccess++;
          (side === 'd' ? direct : proxied).push(r.ms);
        }
        if (o.onProgress && i % 50 === 0) o.onProgress(name, i, n);
      }
    } finally {
      directAgent.destroy();
      proxyAgent.destroy();
    }
    const d = summarize(direct);
    const p = summarize(proxied);
    const overhead = {};
    for (const k of ['mean', 'p50', 'p95', 'p99']) overhead[k] = d[k] === null || p[k] === null ? null : round(p[k] - d[k]);
    results.push({
      scenario: name, request: { method: sc.method, path: sc.path, bodyBytes: sc.body ? Buffer.byteLength(sc.body) : 0 },
      n, warmup, direct: d, proxy: p, overheadMs: overhead, errors,
      thresholdMs, pass: overhead.p95 !== null && overhead.p95 < thresholdMs && errors.proxy === 0 && errors.nonSuccess === 0
    });
  }
  return { thresholdMs, criterion: `p95 overhead (proxy − direct) < ${thresholdMs} ms on localhost`, results, pass: results.every((r) => r.pass) };
}

module.exports = { measureOverhead, SCENARIOS, DEFAULT_THRESHOLD_P95_MS };
