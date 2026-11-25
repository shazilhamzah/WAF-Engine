'use strict';
/**
 * EngineConfig defaults and strict validation (contract §3.2).
 *
 * validateConfig(cfg) merges `cfg` over DEFAULT_CONFIG (missing fields take their default), rejects
 * unknown fields, wrong types and out-of-range values, and returns a normalized frozen-free copy.
 */

const DEFAULT_CONFIG = deepFreeze({
  mode: 'block',
  thresholds: { flag: 3, block: 5 },
  limits: {
    maxBodyBytes: 1048576,
    inspectBodyBytes: 65536,
    maxUrlLength: 4096,
    maxHeaderCount: 100,
    maxArgs: 200,
    decodeRounds: 3,
  },
  rateLimit: { enabled: true, windowMs: 60000, maxRequests: 300 },
});

/** Integer ranges for every numeric field. */
const RANGES = Object.freeze({
  'thresholds.flag': [1, 100],
  'thresholds.block': [1, 100],
  'limits.maxBodyBytes': [1024, 104857600],
  'limits.inspectBodyBytes': [256, 4194304],
  'limits.maxUrlLength': [64, 65536],
  'limits.maxHeaderCount': [1, 1000],
  'limits.maxArgs': [1, 10000],
  'limits.decodeRounds': [1, 5],
  'rateLimit.windowMs': [1000, 3600000],
  'rateLimit.maxRequests': [1, 100000],
});

function deepFreeze(obj) {
  for (const v of Object.values(obj)) if (v && typeof v === 'object') deepFreeze(v);
  return Object.freeze(obj);
}

function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * @param {object} cfg candidate EngineConfig (partial allowed; defaults fill gaps)
 * @returns {{ ok: boolean, config: object|null, errors: {field: string, message: string}[] }}
 */
function validateConfig(cfg) {
  const errors = [];
  const out = clone(DEFAULT_CONFIG);
  if (cfg === undefined || cfg === null) return { ok: true, config: out, errors };
  if (!isPlainObject(cfg)) {
    return { ok: false, config: null, errors: [{ field: 'config', message: 'must be an object' }] };
  }
  const sections = { mode: null, thresholds: ['flag', 'block'], limits: Object.keys(DEFAULT_CONFIG.limits), rateLimit: ['enabled', 'windowMs', 'maxRequests'] };
  let keys;
  try {
    keys = Object.keys(cfg);
  } catch {
    return { ok: false, config: null, errors: [{ field: 'config', message: 'must be an object' }] };
  }
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(sections, key)) {
      errors.push({ field: key, message: 'unknown field' });
      continue;
    }
    const value = cfg[key];
    if (key === 'mode') {
      if (value !== 'block' && value !== 'monitor') errors.push({ field: 'mode', message: "must be 'block' or 'monitor'" });
      else out.mode = value;
      continue;
    }
    if (!isPlainObject(value)) {
      errors.push({ field: key, message: 'must be an object' });
      continue;
    }
    for (const sub of Object.keys(value)) {
      const field = `${key}.${sub}`;
      if (!sections[key].includes(sub)) {
        errors.push({ field, message: 'unknown field' });
        continue;
      }
      const v = value[sub];
      if (field === 'rateLimit.enabled') {
        if (typeof v !== 'boolean') errors.push({ field, message: 'must be a boolean' });
        else out.rateLimit.enabled = v;
        continue;
      }
      const [min, max] = RANGES[field];
      if (typeof v !== 'number' || !Number.isInteger(v)) {
        errors.push({ field, message: 'must be an integer' });
      } else if (v < min || v > max) {
        errors.push({ field, message: `must be between ${min} and ${max}` });
      } else {
        out[key][sub] = v;
      }
    }
  }
  if (!errors.length) {
    if (out.thresholds.flag > out.thresholds.block) {
      errors.push({ field: 'thresholds.flag', message: 'must be less than or equal to thresholds.block' });
    }
    if (out.limits.inspectBodyBytes > out.limits.maxBodyBytes) {
      errors.push({ field: 'limits.inspectBodyBytes', message: 'must be less than or equal to limits.maxBodyBytes' });
    }
  }
  return errors.length ? { ok: false, config: null, errors } : { ok: true, config: out, errors };
}

/** Lenient merge used inside inspect(): invalid input falls back to defaults field by field. */
function resolveConfig(cfg) {
  const res = validateConfig(cfg);
  if (res.ok) return res.config;
  const out = clone(DEFAULT_CONFIG);
  if (!isPlainObject(cfg)) return out;
  if (cfg.mode === 'monitor' || cfg.mode === 'block') out.mode = cfg.mode;
  for (const section of ['thresholds', 'limits', 'rateLimit']) {
    const src = cfg[section];
    if (!isPlainObject(src)) continue;
    for (const sub of Object.keys(out[section])) {
      const v = src[sub];
      const field = `${section}.${sub}`;
      if (field === 'rateLimit.enabled') {
        if (typeof v === 'boolean') out.rateLimit.enabled = v;
      } else if (Number.isInteger(v) && v >= RANGES[field][0] && v <= RANGES[field][1]) {
        out[section][sub] = v;
      }
    }
  }
  if (out.thresholds.flag > out.thresholds.block) out.thresholds.flag = out.thresholds.block;
  if (out.limits.inspectBodyBytes > out.limits.maxBodyBytes) out.limits.inspectBodyBytes = out.limits.maxBodyBytes;
  return out;
}

module.exports = { DEFAULT_CONFIG, RANGES, validateConfig, resolveConfig };
