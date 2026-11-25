#!/usr/bin/env node
'use strict';
/**
 * Acceptance check (owner: Nufil) — proposal: "At least 80% of automated tests must pass".
 *
 *   npm run check                run every test (unit + integration + security + evaluation helpers)
 *   node scripts/check.js --lenient   allow tests to SKIP when a module is missing (phase-1 development)
 *   node scripts/check.js --no-audit  skip `npm audit`
 *
 * 1. Runs `node --test --test-concurrency=1 "test/**\/*.test.js"` with the spec reporter on screen and the
 *    TAP reporter captured to .tmp/check.tap; counts pass / fail / skipped / cancelled / todo.
 *    WAF_STRICT=1 is set so integration/security suites FAIL (rather than skip) if the backend is missing.
 * 2. Computes the pass percentage = pass / (pass + fail + cancelled) and asserts ≥ 80 %.
 * 3. Runs `npm audit --omit=dev --json` (production dependencies) and reports vulnerability counts.
 * 4. Writes docs/evaluation/check-summary.json.
 * Exit code 0 when the threshold is met and there are no high/critical production vulnerabilities.
 */
const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const TMP = path.join(ROOT, '.tmp');
const OUT = path.join(ROOT, 'docs', 'evaluation', 'check-summary.json');
const THRESHOLD = 80;

const argv = process.argv.slice(2);
const lenient = argv.includes('--lenient');
const runAudit = !argv.includes('--no-audit');
const pattern = (argv.find((a) => a.startsWith('--pattern=')) || '--pattern=test/**/*.test.js').split('=')[1];

function parseTap(text) {
  const counts = { tests: 0, suites: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0, duration_ms: 0 };
  for (const line of text.split(/\r?\n/)) {
    const m = /^# (tests|suites|pass|fail|cancelled|skipped|todo|duration_ms) ([\d.]+)/.exec(line);
    if (m) counts[m[1]] = Number(m[2]);
  }
  // Failing leaf tests: "not ok N - name" lines that are not just a failing parent/file.
  const failing = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)not ok \d+ - (.*?)(?: # .*)?$/.exec(lines[i]);
    if (!m) continue;
    const block = lines.slice(i + 1, i + 12).join('\n');
    if (/failureType: '(subtestsFailed|cancelledByParent)'/.test(block)) continue;
    const loc = /location: '([^']+)'/.exec(block);
    const err = /error: \|-?\s*\n\s*(.+)|error: '([^']*)'/.exec(block);
    failing.push({ name: m[2].trim(), location: loc ? path.relative(ROOT, loc[1].replace(/:\d+:\d+$/, '')) : null, error: err ? (err[1] || err[2] || '').trim().slice(0, 200) : null });
  }
  return { counts, failing };
}

function runTests() {
  fs.mkdirSync(TMP, { recursive: true });
  const tapFile = path.join(TMP, 'check.tap');
  const args = ['--test', '--test-concurrency=1', '--test-reporter=spec', '--test-reporter-destination=stdout',
    '--test-reporter=tap', `--test-reporter-destination=${tapFile}`, pattern];
  const env = { ...process.env };
  if (!lenient) env.WAF_STRICT = '1';
  console.log(`[check] node ${args.join(' ')}${lenient ? '' : '   (WAF_STRICT=1)'}`);
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, env, stdio: ['ignore', 'inherit', 'inherit'] });
    child.on('close', (code) => {
      const tap = fs.existsSync(tapFile) ? fs.readFileSync(tapFile, 'utf8') : '';
      resolve({ exitCode: code, ...parseTap(tap) });
    });
  });
}

function npmAudit() {
  const r = spawnSync('npm', ['audit', '--omit=dev', '--json'], { cwd: ROOT, encoding: 'utf8', shell: process.platform === 'win32', timeout: 120000 });
  try {
    const j = JSON.parse(r.stdout || '{}');
    if (j.error) return { ok: false, available: false, message: String(j.error.summary || j.error.code || 'npm audit error').slice(0, 200) };
    const v = (j.metadata && j.metadata.vulnerabilities) || {};
    const total = ['info', 'low', 'moderate', 'high', 'critical'].reduce((a, k) => a + (v[k] || 0), 0);
    return { ok: !(v.high || v.critical), available: true, vulnerabilities: v, total, dependencies: j.metadata && j.metadata.dependencies };
  } catch {
    return { ok: true, available: false, message: 'npm audit unavailable (offline?) — not counted as a failure' };
  }
}

(async () => {
  const started = Date.now();
  const t = await runTests();
  const c = t.counts;
  const denom = c.pass + c.fail + c.cancelled;
  const passRate = denom ? Math.round((c.pass / denom) * 1000) / 10 : 0;
  const meets = denom > 0 && passRate >= THRESHOLD;
  const audit = runAudit ? npmAudit() : { available: false, ok: true, message: 'skipped (--no-audit)' };
  const summary = {
    generatedAt: new Date().toISOString(),
    command: `node --test --test-concurrency=1 "${pattern}"`,
    mode: lenient ? 'lenient (missing modules skip)' : 'strict (WAF_STRICT=1)',
    node: process.version,
    tests: { ...c, passRate, threshold: THRESHOLD, meetsThreshold: meets },
    failing: t.failing,
    npmAudit: audit,
    durationSec: Math.round((Date.now() - started) / 100) / 10,
    result: meets && audit.ok ? 'PASS' : 'FAIL'
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(summary, null, 2) + '\n');

  console.log('\n──────────── check summary ────────────');
  console.log(`tests     ${c.tests} (suites ${c.suites})  pass ${c.pass}  fail ${c.fail}  cancelled ${c.cancelled}  skipped ${c.skipped}  todo ${c.todo}`);
  console.log(`pass rate ${passRate} %  (threshold ≥ ${THRESHOLD} %) → ${meets ? 'MET' : 'NOT MET'}`);
  if (t.failing.length) {
    console.log(`failing   ${t.failing.length} test(s):`);
    for (const f of t.failing.slice(0, 40)) console.log(`  ✖ ${f.name}${f.location ? `  (${f.location})` : ''}`);
    if (t.failing.length > 40) console.log(`  … and ${t.failing.length - 40} more (see ${path.relative(ROOT, OUT)})`);
  }
  if (audit.available) {
    const v = audit.vulnerabilities;
    console.log(`npm audit ${audit.total} production vulnerabilities (critical ${v.critical || 0}, high ${v.high || 0}, moderate ${v.moderate || 0}, low ${v.low || 0})`);
  } else console.log(`npm audit ${audit.message}`);
  console.log(`result    ${summary.result}   → ${path.relative(ROOT, OUT)}`);
  process.exit(summary.result === 'PASS' ? 0 : 1);
})();
