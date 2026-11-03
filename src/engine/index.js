'use strict';

const { DEFAULT_CONFIG, validateConfig } = require('./config');
const { parseRequest } = require('./parser');
const { validateRuleSource, parseRuleFile, compileRules } = require('./dsl');
const { createRateLimiter } = require('./ratelimit');
const { ENGINE_VERSION, inspect } = require('./pipeline');
const { redact, excerpt } = require('./redact');

module.exports = {
  ENGINE_VERSION,
  DEFAULT_CONFIG,
  validateConfig,
  parseRequest,
  validateRuleSource,
  parseRuleFile,
  compileRules,
  createRateLimiter,
  inspect,
  redact,
  excerpt,
};
