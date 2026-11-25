'use strict';
const { normalizeLogger } = require('./logger');
const { canonicalJson } = require('../db/util');

function createEngineState({ db, engine, logger, clock } = {}) {
  if (!db) throw new Error('createEngineState requires db');
  if (!engine || typeof engine.inspect !== 'function' || typeof engine.compileRules !== 'function') {
    throw new Error('createEngineState requires the security engine (src/engine) with inspect() and compileRules()');
  }
  const log = normalizeLogger(logger);
  const now = typeof clock === 'function' ? clock : (db.clock || (() => Date.now()));

  let compiled = { rules: [], errors: [], rulesetVersion: 'empty' };
  let configRecord = null;
  let exceptions = [];
  let rateLimiter = null;
  let rateLimitKey = null;
  let loadedAt = null;

  function loadConfig() {
    let latest = db.configs.latest();
    if (!latest) {
      const base = engine.DEFAULT_CONFIG ? structuredClone(engine.DEFAULT_CONFIG) : {};
      const validated = typeof engine.validateConfig === 'function' ? engine.validateConfig(base) : { ok: true, config: base };
      latest = db.configs.append(validated.ok ? validated.config : base, null, 'default configuration');
    }
    if (typeof engine.validateConfig === 'function') {
      const v = engine.validateConfig(latest.config);
      if (v && v.ok) latest = { ...latest, config: v.config };
      else log.warn('stored configuration failed validation; using it unnormalized', { version: latest.version });
    }
    return latest;
  }

  function configureRateLimiter(config) {
    const rl = (config && config.rateLimit) || {};
    const key = canonicalJson(rl);
    if (typeof engine.createRateLimiter !== 'function') return;
    if (!rateLimiter) {
      rateLimiter = engine.createRateLimiter(rl);
    } else if (key !== rateLimitKey) {
      if (typeof rateLimiter.configure === 'function') rateLimiter.configure(rl);
      // a changed limit starts from a clean window
      if (typeof rateLimiter.reset === 'function') rateLimiter.reset();
    }
    rateLimitKey = key;
  }

  function reload() {
    const records = db.rules.listForCompile().filter((r) => r.enabled);
    const result = engine.compileRules(records) || {};
    compiled = {
      rules: Array.isArray(result.rules) ? result.rules : [],
      errors: Array.isArray(result.errors) ? result.errors : [],
      rulesetVersion: result.rulesetVersion || 'empty',
    };
    if (compiled.errors.length) log.warn('rule compilation reported errors', { count: compiled.errors.length });
    configRecord = loadConfig();
    exceptions = db.exceptions.listActive(now());
    configureRateLimiter(configRecord.config);
    loadedAt = new Date(now()).toISOString();
    return status();
  }

  function status() {
    return {
      rulesetVersion: compiled.rulesetVersion,
      ruleCount: compiled.rules.length,
      compileErrors: compiled.errors,
      configVersion: configRecord ? configRecord.version : null,
      mode: configRecord && configRecord.config ? configRecord.config.mode : null,
      activeExceptions: exceptions.length,
      loadedAt,
    };
  }

  reload();

  return {
    engine,
    reload,
    status,
    getContext({ clientKey = null, withRateLimit = false } = {}) {
      const t = now();
      const iso = new Date(t).toISOString();
      return {
        rules: compiled.rules,
        rulesetVersion: compiled.rulesetVersion,
        config: configRecord.config,
        configVersion: configRecord.version,
        exceptions: exceptions.filter((x) => !x.expiresAt || x.expiresAt > iso),
        rateLimiter: withRateLimit ? rateLimiter : null,
        clientKey,
        now: t,
      };
    },
    getRulesetVersion() { return compiled.rulesetVersion; },
    getCompileErrors() { return compiled.errors; },
    getConfig() { return configRecord.config; },
    getConfigVersion() { return configRecord.version; },
    getConfigRecord() { return configRecord; },
    getRateLimiter() { return rateLimiter; },
  };
}

module.exports = { createEngineState };
