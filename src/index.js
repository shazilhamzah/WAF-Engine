'use strict';
/**
 * WAF Studio bootstrap (contract §1, §10).
 *
 *   const { startAll } = require('./src');
 *   const stack = await startAll({ studioPort: 0, proxyPort: 0, targetPort: 0, dbPath, dataDir, quiet: true });
 *   // stack.studio / stack.proxy / stack.target are listening http.Server instances (port 0 → ephemeral)
 *   await stack.close();
 *
 * `npm start` runs this file directly: it starts the Studio console, the WAF reverse proxy and the
 * deliberately vulnerable lab target, all bound to 127.0.0.1, and prints the three URLs.
 */
const http = require('node:http');
const path = require('node:path');
const { loadConfig, loadSecret, HOST } = require('./config');
const { openDatabase } = require('./db');
const { createEngineState } = require('./services/engineState');
const { createAuditor } = require('./services/audit');
const { createConsoleLogger, silentLogger, normalizeLogger } = require('./services/logger');
const { createStudioApp } = require('./api/app');
const { createProxyServer } = require('./proxy/server');

const EVENT_RETENTION = 100000;

function loadEngine() {
  try {
    return require('./engine');
  } catch (err) {
    if (err && err.code === 'MODULE_NOT_FOUND' && String(err.message).includes(path.join(__dirname, 'engine'))) {
      throw new Error('Security engine not found (src/engine/index.js). The engine module is required to start WAF Studio.');
    }
    throw err;
  }
}

function loadTargetApp() {
  const p = path.resolve(__dirname, '..', 'target', 'app.js');
  try {
    return require(p).createTargetApp();
  } catch (err) {
    if (err && err.code === 'MODULE_NOT_FOUND' && String(err.message).includes(p)) {
      throw new Error('Vulnerable target not found (target/app.js). Start with { startTarget: false } and set TARGET_URL instead.');
    }
    throw err;
  }
}

function hardenServer(server) {
  server.headersTimeout = 20000;   // slow-header (slowloris) protection
  server.requestTimeout = 60000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 200;
  return server;
}

function listen(server, port, name) {
  return new Promise((resolve, reject) => {
    const onError = (err) => {
      server.off('listening', onListening);
      reject(new Error(`${name} could not listen on ${HOST}:${port} (${err.code || err.message})`));
    };
    const onListening = () => { server.off('error', onError); resolve(server.address().port); };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, HOST);
  });
}

function closeServer(server) {
  if (!server || !server.listening) return Promise.resolve();
  return new Promise((resolve) => {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    server.close(() => resolve());
  });
}

/**
 * Starts the Studio console, the WAF proxy and (optionally) the vulnerable target.
 * @param {{ studioPort?: number, proxyPort?: number, targetPort?: number, dbPath?: string, dataDir?: string,
 *           startTarget?: boolean, targetUrl?: string, quiet?: boolean, logger?: object, engine?: object,
 *           env?: NodeJS.ProcessEnv, studioOptions?: object }} [options]
 * @returns {Promise<{ studio: http.Server, proxy: http.Server, target: http.Server|null, db, engineState,
 *                     ports: {studio:number, proxy:number, target:number|null}, urls: object, close(): Promise<void> }>}
 */
async function startAll(options = {}) {
  const env = options.env || process.env;
  const cfg = loadConfig(env);
  const pick = (v, d) => (v === undefined || v === null ? d : v);
  const studioPort = pick(options.studioPort, cfg.studioPort);
  const proxyPort = pick(options.proxyPort, cfg.proxyPort);
  const targetPort = pick(options.targetPort, cfg.targetPort);
  const dataDir = options.dataDir ? path.resolve(options.dataDir) : cfg.dataDir;
  const dbPath = options.dbPath || (options.dataDir ? path.join(dataDir, 'waf-studio.db') : cfg.dbPath);
  const startTarget = options.startTarget !== false;
  const log = options.logger ? normalizeLogger(options.logger) : (options.quiet ? silentLogger : createConsoleLogger());

  const { secret } = loadSecret(dataDir, env);
  const engine = options.engine || loadEngine();
  const db = openDatabase(dbPath);
  const servers = { studio: null, proxy: null, target: null };
  let closed = false;

  async function close() {
    if (closed) return;
    closed = true;
    await Promise.all([closeServer(servers.proxy), closeServer(servers.studio), closeServer(servers.target)]);
    db.close();
  }

  try {
    const engineState = createEngineState({ db, engine, logger: log });
    const audit = createAuditor({ db, logger: log });
    db.events.prune(EVENT_RETENTION);

    let targetUrl = options.targetUrl || null;
    let actualTargetPort = null;
    if (startTarget) {
      servers.target = hardenServer(http.createServer(loadTargetApp()));
      actualTargetPort = await listen(servers.target, targetPort, 'Vulnerable target');
      if (!targetUrl) targetUrl = `http://${HOST}:${actualTargetPort}`;
    }
    if (!targetUrl) targetUrl = cfg.targetUrl;

    servers.studio = hardenServer(http.createServer(createStudioApp({ db, engineState, secret, logger: log, options: options.studioOptions || {} })));
    const actualStudioPort = await listen(servers.studio, studioPort, 'Studio console');
    servers.proxy = hardenServer(createProxyServer({ db, engineState, targetUrl, secret, logger: log, audit, retention: EVENT_RETENTION }));
    const actualProxyPort = await listen(servers.proxy, proxyPort, 'WAF proxy');

    const st = engineState.status();
    const urls = {
      studio: `http://${HOST}:${actualStudioPort}`,
      proxy: `http://${HOST}:${actualProxyPort}`,
      target: targetUrl,
    };
    audit.system('system.start', {
      targetType: 'system', targetId: 'waf-studio',
      details: {
        studioPort: actualStudioPort, proxyPort: actualProxyPort, targetPort: actualTargetPort,
        rulesetVersion: st.rulesetVersion, ruleCount: st.ruleCount, configVersion: st.configVersion, mode: st.mode,
        engineVersion: engine.ENGINE_VERSION || null, schemaVersion: db.schemaVersion,
      },
    });
    if (db.users.count() === 0) log.warn('no users exist yet; run `npm run setup` to create the admin/operator/viewer accounts');
    if (st.ruleCount === 0) log.warn('no rules are loaded; run `npm run setup` to load src/rules/default.rules');

    return {
      studio: servers.studio, proxy: servers.proxy, target: servers.target, db, engineState,
      ports: { studio: actualStudioPort, proxy: actualProxyPort, target: actualTargetPort },
      urls,
      close,
    };
  } catch (err) {
    await close();
    throw err;
  }
}

module.exports = { startAll };

if (require.main === module) {
  startAll().then((stack) => {
    const out = process.stdout;
    out.write('\nWAF Studio is running (bound to 127.0.0.1 only):\n');
    out.write(`  Studio console : ${stack.urls.studio}\n`);
    out.write(`  WAF proxy      : ${stack.urls.proxy}   <- send test traffic here\n`);
    out.write(`  Lab target     : ${stack.urls.target}   (deliberately vulnerable; do not expose)\n\n`);
    out.write('Press Ctrl+C to stop.\n');
    let stopping = false;
    const stop = (signal) => {
      if (stopping) return;
      stopping = true;
      out.write(`\nReceived ${signal}, shutting down...\n`);
      const timer = setTimeout(() => process.exit(1), 5000);
      timer.unref();
      stack.close().then(() => process.exit(0), () => process.exit(1));
    };
    process.on('SIGINT', () => stop('SIGINT'));
    process.on('SIGTERM', () => stop('SIGTERM'));
  }).catch((err) => {
    process.stderr.write(`WAF Studio failed to start: ${err.message}\n`);
    process.exit(1);
  });
}
