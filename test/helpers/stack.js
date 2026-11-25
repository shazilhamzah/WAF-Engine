'use strict';
/**
 * startStack(): boots the WHOLE WAF Studio stack (studio API + WAF proxy + vulnerable target) on
 * ephemeral ports with a throw-away database, seeds it with known test passwords and returns helpers.
 *
 * Contract assumptions (docs/02-architecture.md) — if one of these changes, only this file needs fixing:
 *   A1  require('src/index.js').startAll(opts) → Promise<{ studio, proxy, target, close() }>
 *       opts: { studioPort, proxyPort, targetPort, dbPath, dataDir, quiet }
 *       studio/proxy/target are http.Server instances OR objects exposing `.server`, `.port` or `.url`.
 *   A2  require('src/services/seed.js').seedDatabase(db, engine, { passwords }) seeds users
 *       admin/operator/viewer (usernames = role names) + default rules + default config. It may return
 *       { passwords } — returned passwords win over the ones we pass.
 *   A3  The seed needs a DB handle. We prefer `stack.db` (if startAll exposes it); otherwise we open the
 *       DB file ourselves with require('src/db').openDatabase(dbPath) BEFORE starting, seed, close it,
 *       then start the stack on the same file (so the running engine state loads the seeded rules).
 *   A4  Tables/columns follow §4 (sessions.expires_at/last_seen_at, audit_log triggers) — used by the
 *       session-expiry and tamper tests through `stack.openRawDb()`.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ApiClient, rawRequest } = require('./http');

const ROOT = path.resolve(__dirname, '..', '..');
const SRC_INDEX = path.join(ROOT, 'src', 'index.js');
const SRC_SEED = path.join(ROOT, 'src', 'services', 'seed.js');
const SRC_DB = path.join(ROOT, 'src', 'db', 'index.js');
const SRC_ENGINE = path.join(ROOT, 'src', 'engine', 'index.js');

/** Known, test-only passwords (≥ 12 chars, as the password policy requires). */
const TEST_PASSWORDS = Object.freeze({
  admin: 'Test-Admin-Passw0rd!',
  operator: 'Test-Operator-Passw0rd!',
  viewer: 'Test-Viewer-Passw0rd!'
});

/** Whether the backend modules exist yet (phase-1 tests skip cleanly when they do not). */
function stackAvailable() {
  return fs.existsSync(SRC_INDEX) && fs.existsSync(SRC_SEED);
}

/**
 * For node:test — returns a `skip` option: tests are skipped (with a reason) while the backend does
 * not exist yet, unless WAF_STRICT=1 (set by scripts/check.js) in which case they run and fail loudly.
 */
function skipUnlessStack() {
  if (stackAvailable() || process.env.WAF_STRICT === '1') return false;
  return 'backend not available yet (src/index.js or src/services/seed.js missing)';
}

function portOf(x) {
  if (!x) return null;
  if (typeof x === 'number') return x;
  if (typeof x.address === 'function') { const a = x.address(); return a && typeof a === 'object' ? a.port : null; }
  if (x.server) return portOf(x.server);
  if (typeof x.port === 'number') return x.port;
  if (typeof x.url === 'string') return Number(new URL(x.url).port);
  return null;
}

function rmrf(dir) {
  for (let i = 0; i < 10; i++) {
    try { fs.rmSync(dir, { recursive: true, force: true }); return; } catch { /* Windows file locks: retry */ }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100); // short synchronous sleep
  }
}

async function seedFile(dbPath, passwords) {
  const { seedDatabase } = require(SRC_SEED);
  const engine = fs.existsSync(SRC_ENGINE) ? require(SRC_ENGINE) : undefined;
  const { openDatabase } = require(SRC_DB);
  const db = await openDatabase(dbPath);
  try {
    const out = await seedDatabase(db, engine, { passwords });
    return (out && out.passwords) || passwords;
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
}

/**
 * @param {object} [opts]
 * @param {string} [opts.dataDir]   reuse an existing data dir (restart/recovery tests)
 * @param {boolean} [opts.seed=true] seed users/rules/config (false on restart)
 * @param {object} [opts.passwords] override test passwords
 * @param {object} [opts.startOptions] extra options for startAll
 */
async function startStack(opts = {}) {
  const dataDir = opts.dataDir || fs.mkdtempSync(path.join(os.tmpdir(), 'waf-studio-test-'));
  const dbPath = opts.dbPath || path.join(dataDir, 'waf-studio.db');
  let passwords = { ...TEST_PASSWORDS, ...(opts.passwords || {}) };
  const seed = opts.seed !== false;

  // Seed before start when we can open the DB ourselves (A3).
  let seeded = false;
  if (seed && fs.existsSync(SRC_DB)) {
    passwords = await seedFile(dbPath, passwords);
    seeded = true;
  }

  const { startAll } = require(SRC_INDEX);
  const stack = await startAll({
    studioPort: 0, proxyPort: 0, targetPort: 0, dbPath, dataDir, quiet: true, ...(opts.startOptions || {})
  });

  if (seed && !seeded) {
    const { seedDatabase } = require(SRC_SEED);
    const engine = fs.existsSync(SRC_ENGINE) ? require(SRC_ENGINE) : undefined;
    if (!stack.db) throw new Error('startStack: cannot seed — neither src/db/index.js openDatabase nor stack.db available');
    const out = await seedDatabase(stack.db, engine, { passwords });
    if (out && out.passwords) passwords = out.passwords;
    // Make the running engine pick up seeded rules/config if it exposes a reload.
    const es = stack.engineState;
    if (es && typeof es.reload === 'function') await es.reload();
  }

  const studioPort = portOf(stack.studio);
  const proxyPort = portOf(stack.proxy);
  const targetPort = portOf(stack.target);
  if (!studioPort || !proxyPort) throw new Error('startStack: could not determine studio/proxy ports from startAll() result');

  const studioUrl = `http://127.0.0.1:${studioPort}`;
  const proxyUrl = `http://127.0.0.1:${proxyPort}`;
  const targetUrl = targetPort ? `http://127.0.0.1:${targetPort}` : null;
  let stopped = false;

  const api = {
    raw: stack, dataDir, dbPath, passwords, studioUrl, proxyUrl, targetUrl,

    /** New unauthenticated API client. */
    client() { return new ApiClient(studioUrl); },

    /** Logged-in client for a role (username defaults to the role name). Throws on failure. */
    async login(role, { username = role, password = passwords[role] } = {}) {
      const c = new ApiClient(studioUrl);
      const r = await c.login(username, password);
      if (r.status !== 200) throw new Error(`login(${username}) failed: HTTP ${r.status} ${r.text.slice(0, 200)}`);
      return c;
    },

    /** Raw request through the WAF proxy (no path normalisation). */
    proxy(req) { return rawRequest(proxyUrl, req); },
    /** Raw request straight to the target (bypasses the WAF — baseline for T6). */
    direct(req) { return rawRequest(targetUrl, req); },

    /** Stops the target only (for "target down → 502" tests). */
    async stopTarget() {
      const t = stack.target;
      const srv = t && (typeof t.close === 'function' ? t : t.server);
      if (srv && typeof srv.close === 'function') {
        if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
        await new Promise((r) => srv.close(() => r()));
      }
    },

    /** Opens the DB file directly (node:sqlite) for white-box checks. Caller must close(). */
    openRawDb() {
      const { DatabaseSync } = require('node:sqlite');
      const db = new DatabaseSync(dbPath);
      db.exec('PRAGMA busy_timeout = 5000');
      return db;
    },

    /** Stops everything; removes the temp data dir unless keepData. */
    async stop({ keepData = false } = {}) {
      if (stopped) return;
      stopped = true;
      try { await stack.close(); } catch { /* ignore */ }
      if (!keepData && !opts.dataDir) rmrf(dataDir);
    }
  };
  return api;
}

/** Waits for `fn` to return truthy (polling), e.g. for an async event write. */
async function waitFor(fn, { timeoutMs = 3000, intervalMs = 25 } = {}) {
  const until = Date.now() + timeoutMs;
  let last;
  while (Date.now() < until) {
    last = await fn();
    if (last) return last;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return last;
}

/** Strings that must never appear in an error body (stack traces, internal paths, engine internals). */
const LEAK_PATTERNS = [
  /\bat [\w.<>$]+ \(/,            // stack frame "at fn ("
  /\bat (?:node:|file:|[A-Za-z]:\\)/,
  /node:internal/,
  /node_modules/,
  /[A-Za-z]:\\(?:Users|Windows|Program)/i,
  /\/(?:home|Users|usr|var)\/[\w.-]+\//,
  /SqliteError|SQLITE_|ERR_[A-Z_]{4,}/,
  /TypeError|ReferenceError|SyntaxError: Unexpected/
];

function findLeak(text) {
  for (const re of LEAK_PATTERNS) if (re.test(text)) return re.source;
  return null;
}

module.exports = { startStack, stackAvailable, skipUnlessStack, waitFor, findLeak, rmrf, TEST_PASSWORDS, portOf, ROOT };
