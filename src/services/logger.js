'use strict';
const { redact } = require('./redact');

const silentLogger = Object.freeze({ debug() {}, info() {}, warn() {}, error() {} });

function serializeError(err) {
  if (!err || typeof err !== 'object') return err;
  return { name: err.name, code: err.code, message: String(err.message || '').slice(0, 500), stack: err.stack };
}

function createConsoleLogger({ level = 'info', stream = process.stderr } = {}) {
  const levels = { debug: 10, info: 20, warn: 30, error: 40 };
  const min = levels[level] || 20;
  const write = (lvl) => (msg, meta) => {
    if (levels[lvl] < min) return;
    const entry = { ts: new Date().toISOString(), level: lvl, msg: String(msg) };
    if (meta !== undefined) {
      const m = { ...meta };
      if (m.err) m.err = serializeError(m.err);
      entry.meta = redact(m);
    }
    stream.write(JSON.stringify(entry) + '\n');
  };
  return { debug: write('debug'), info: write('info'), warn: write('warn'), error: write('error') };
}

function normalizeLogger(logger) {
  if (!logger) return silentLogger;
  const noop = () => {};
  return {
    debug: typeof logger.debug === 'function' ? logger.debug.bind(logger) : noop,
    info: typeof logger.info === 'function' ? logger.info.bind(logger) : noop,
    warn: typeof logger.warn === 'function' ? logger.warn.bind(logger) : noop,
    error: typeof logger.error === 'function' ? logger.error.bind(logger) : noop,
  };
}

module.exports = { silentLogger, createConsoleLogger, normalizeLogger, serializeError };
