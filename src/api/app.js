'use strict';
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const { normalizeLogger } = require('../services/logger');
const { createAuditor } = require('../services/audit');
const { createClientIdentifier } = require('../services/clientId');
const { createSessionManager } = require('../auth/sessions');
const { createLoginThrottle, createSlidingWindowLimiter } = require('../auth/rateLimit');
const { createAuthMiddleware } = require('../auth/middleware');
const { ApiError } = require('./errors');
const mw = require('./middleware');
const { createAuthRouter } = require('./routes/auth');
const { createUsersRouter } = require('./routes/users');
const { createEventsRouter } = require('./routes/events');
const { createRulesRouter } = require('./routes/rules');
const { createConfigRouter } = require('./routes/config');
const { createExceptionsRouter } = require('./routes/exceptions');
const { createAuditRouter } = require('./routes/audit');

const PUBLIC_DIR = path.resolve(__dirname, '..', '..', 'public');
const REPORTS_ROUTER_PATH = path.resolve(__dirname, 'routes', 'reports.js');
const PKG_VERSION = (() => { try { return require('../../package.json').version; } catch { return '0.0.0'; } })();

function loadReportsRouterFactory(log) {
  try {
    const mod = require(REPORTS_ROUTER_PATH);
    const factory = mod && (mod.createReportsRouter || (typeof mod === 'function' ? mod : null));
    if (typeof factory !== 'function') {
      log.warn('src/api/routes/reports.js does not export createReportsRouter; report export disabled');
      return null;
    }
    return factory;
  } catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND' && String(e.message).includes(REPORTS_ROUTER_PATH)) {
      log.warn('src/api/routes/reports.js not found; report export disabled');
      return null;
    }
    throw e;
  }
}

function createStudioApp({ db, engineState, secret, logger, clock, publicDir = PUBLIC_DIR, options = {} } = {}) {
  if (!db) throw new Error('createStudioApp requires db');
  if (!engineState) throw new Error('createStudioApp requires engineState');
  if (!secret) throw new Error('createStudioApp requires secret');
  const log = normalizeLogger(logger);
  const now = typeof clock === 'function' ? clock : () => Date.now();

  const audit = createAuditor({ db, logger: log });
  const identifyClient = createClientIdentifier(secret);
  const sessions = createSessionManager({ db, clock: now, idleMs: options.idleMs, absoluteMs: options.absoluteMs });
  const throttle = createLoginThrottle({ clock: now, ...(options.loginThrottle || {}) });
  const analysisLimiter = createSlidingWindowLimiter({ windowMs: 60_000, max: options.analysisPerMinute || 60, clock: now });
  const auth = createAuthMiddleware({ sessions, audit });
  const deps = { db, engineState, audit, auth, sessions, throttle, analysisLimiter, logger: log, clock: now, version: PKG_VERSION };

  const app = express();
  app.disable('x-powered-by');
  app.disable('etag');
  app.set('trust proxy', false);
  app.set('query parser', 'simple');
  app.set('json spaces', 0);

  app.use(mw.requestContext({ identifyClient }));
  app.use(mw.hostAndOriginGuard());

  app.use('/api', mw.apiNoStore, mw.requireJsonBody);
  app.use(['/api/analyze', '/api/import'], express.json({ limit: '2mb', strict: true, type: 'application/json' }));
  app.use('/api', express.json({ limit: '256kb', strict: true, type: 'application/json' }), mw.ensureObjectBody);
  app.use('/api', auth.loadSession, auth.requireCsrf);

  app.use('/api', createAuthRouter(deps));
  app.use('/api', createEventsRouter(deps));
  app.use('/api/users', createUsersRouter(deps));
  app.use('/api/rules', createRulesRouter(deps));
  app.use('/api/config', createConfigRouter(deps));
  app.use('/api/exceptions', createExceptionsRouter(deps));
  app.use('/api/audit', createAuditRouter(deps));

  const reportsFactory = loadReportsRouterFactory(log);
  if (reportsFactory) {
    app.use('/api/reports', auth.requireAuth, auth.requireRole('admin', 'operator'), reportsFactory({ db, engineState, audit, logger: log }));
  } else {
    app.use('/api/reports', auth.requireAuth, auth.requireRole('admin', 'operator'), (req, res, next) => next(new ApiError('NOT_FOUND', 'Report export is not available.')));
  }

  app.use('/api', (req, res, next) => next(new ApiError('NOT_FOUND')));

  // anything without a file extension falls back to the single page app
  const indexFile = path.join(publicDir, 'index.html');
  app.use(express.static(publicDir, { index: 'index.html', dotfiles: 'ignore', redirect: false, fallthrough: true }));
  app.use((req, res, next) => {
    if ((req.method === 'GET' || req.method === 'HEAD') && !path.extname(req.path) && fs.existsSync(indexFile)) {
      res.setHeader('Cache-Control', 'no-cache');
      return res.sendFile(indexFile);
    }
    return next(new ApiError('NOT_FOUND'));
  });

  app.use(mw.errorHandler({ logger: log, audit }));

  app.locals.waf = { audit, sessions, throttle, analysisLimiter, auth };
  return app;
}

module.exports = { createStudioApp, PUBLIC_DIR };
