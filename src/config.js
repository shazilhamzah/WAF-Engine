'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const HOST = '127.0.0.1';
const PROJECT_ROOT = path.resolve(__dirname, '..');

function parsePort(value, fallback, name) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Invalid ${name}: must be an integer between 0 and 65535`);
  }
  return n;
}

function loadConfig(env = process.env) {
  const studioPort = parsePort(env.STUDIO_PORT, 3000, 'STUDIO_PORT');
  const proxyPort = parsePort(env.PROXY_PORT, 8080, 'PROXY_PORT');
  const targetPort = parsePort(env.TARGET_PORT, 3001, 'TARGET_PORT');
  const dataDir = path.resolve(PROJECT_ROOT, env.WAF_DATA_DIR || 'data');
  const dbPath = env.WAF_DB_PATH
    ? (env.WAF_DB_PATH === ':memory:' ? ':memory:' : path.resolve(PROJECT_ROOT, env.WAF_DB_PATH))
    : path.join(dataDir, 'waf-studio.db');
  const targetUrl = env.TARGET_URL || `http://${HOST}:${targetPort}`;
  try {
    // fail early so a typo shows at startup and not at the first request
    const u = new URL(targetUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('protocol');
  } catch {
    throw new Error('Invalid TARGET_URL: must be an absolute http(s) URL');
  }
  return { host: HOST, studioPort, proxyPort, targetPort, targetUrl, dataDir, dbPath, projectRoot: PROJECT_ROOT };
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

function loadSecret(dataDir, env = process.env) {
  if (env.WAF_SECRET) {
    if (String(env.WAF_SECRET).length < 16) throw new Error('WAF_SECRET must be at least 16 characters');
    return { secret: String(env.WAF_SECRET), source: 'env' };
  }
  ensureDir(dataDir);
  const keyPath = path.join(dataDir, 'secret.key');
  try {
    const existing = fs.readFileSync(keyPath, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(existing)) return { secret: existing, source: 'file' };
    throw new Error('secret.key is corrupt (expected 64 hex characters); delete it to regenerate');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  const secret = crypto.randomBytes(32).toString('hex');
  // exclusive create so two processes cannot both write the key
  try {
    fs.writeFileSync(keyPath, secret + '\n', { mode: 0o600, flag: 'wx' });
  } catch (err) {
    if (err.code === 'EEXIST') return loadSecret(dataDir, env);
    throw err;
  }
  try { fs.chmodSync(keyPath, 0o600); } catch { /* best effort */ }
  return { secret, source: 'generated' };
}

module.exports = { HOST, PROJECT_ROOT, loadConfig, loadSecret, ensureDir, parsePort };
