#!/usr/bin/env node
'use strict';
/**
 * Standalone T6 latency benchmark (owner: Nufil).
 *
 *   npm run bench                    N = 300 interleaved pairs per scenario
 *   node scripts/bench-latency.js --n 1000 --warmup 50 --threshold 25
 *
 * Starts the full stack on ephemeral 127.0.0.1 ports (temp DB), raises the proxy rate limit so the
 * benchmark is not throttled, then compares direct-to-target vs. via-WAF latency.
 * Prints a table and writes docs/evaluation/latency.json. Exit 0 always (measurement), 1 if it cannot run.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { startStack, stackAvailable } = require('../test/helpers/stack');
const { measureOverhead, DEFAULT_THRESHOLD_P95_MS } = require('../test/evaluation/latency');

const ROOT = path.resolve(__dirname, '..');

function args(argv) {
  const a = { n: 300, warmup: 30, threshold: DEFAULT_THRESHOLD_P95_MS, out: path.join(ROOT, 'docs', 'evaluation', 'latency.json') };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--n') a.n = Math.max(10, Number(argv[++i]) || a.n);
    else if (argv[i] === '--warmup') a.warmup = Math.max(0, Number(argv[++i]) || 0);
    else if (argv[i] === '--threshold') a.threshold = Number(argv[++i]) || a.threshold;
    else if (argv[i] === '--out') a.out = path.resolve(argv[++i]);
  }
  return a;
}

function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

async function main() {
  const a = args(process.argv.slice(2));
  if (!stackAvailable()) { console.error('[bench] backend not available (src/index.js missing)'); process.exit(1); }
  const stack = await startStack();
  try {
    const admin = await stack.login('admin');
    const cur = await admin.get('/api/config');
    const config = structuredClone(cur.body.config);
    config.rateLimit = { enabled: true, windowMs: 60000, maxRequests: 100000 };
    const put = await admin.put('/api/config', { config, reason: 'latency benchmark', confirm: true });
    if (put.status !== 200) throw new Error('could not relax the rate limit: HTTP ' + put.status);
    console.log(`[bench] N=${a.n} pairs per scenario, warm-up ${a.warmup}, threshold p95 overhead < ${a.threshold} ms`);
    const res = await measureOverhead({ directUrl: stack.targetUrl, proxyUrl: stack.proxyUrl, n: a.n, warmup: a.warmup, thresholdMs: a.threshold,
      onProgress: (name, i, n) => process.stdout.write(`\r[bench] ${name}: ${i}/${n}   `) });
    process.stdout.write('\r' + ' '.repeat(70) + '\r');
    const head = ['scenario', 'side', 'mean', 'p50', 'p95', 'p99', 'max'];
    const w = [30, 10, 9, 9, 9, 9, 9];
    console.log(head.map((h, i) => pad(h, w[i])).join(''));
    for (const r of res.results) {
      for (const [side, s] of [['direct', r.direct], ['via WAF', r.proxy], ['overhead', r.overheadMs]]) {
        console.log([r.scenario, side, s.mean, s.p50, s.p95, s.p99, s.max ?? ''].map((v, i) => pad(v, w[i])).join(''));
      }
      console.log(`${pad('', 30)}→ ${r.pass ? 'PASS' : 'FAIL'} (p95 overhead ${r.overheadMs.p95} ms; errors ${JSON.stringify(r.errors)})`);
    }
    const out = { generatedAt: new Date().toISOString(), environment: { node: process.version, os: `${os.type()} ${os.release()}`, cpu: (os.cpus()[0] || {}).model, cpus: os.cpus().length }, ...res };
    fs.mkdirSync(path.dirname(a.out), { recursive: true });
    fs.writeFileSync(a.out, JSON.stringify(out, null, 2) + '\n');
    console.log(`[bench] ${res.pass ? 'PASS' : 'FAIL'} — ${res.criterion}. Written ${path.relative(ROOT, a.out)}`);
  } finally {
    await stack.stop();
  }
}

main().catch((e) => { console.error('[bench] failed:', e.message); process.exit(1); });
