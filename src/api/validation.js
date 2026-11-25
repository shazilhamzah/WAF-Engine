'use strict';
const { ApiError } = require('./errors');

const ISO_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
const SKIP = Symbol('skip');

function make(check, opts = {}) {
  return {
    optional: Boolean(opts.optional),
    nullable: Boolean(opts.nullable),
    default: opts.default,
    check,
    run(value, path, errors) {
      if (value === undefined) {
        if (this.default !== undefined) return typeof this.default === 'function' ? this.default() : this.default;
        if (this.optional) return SKIP;
        errors.push({ field: path, message: 'is required' });
        return SKIP;
      }
      if (value === null) {
        if (this.nullable) return null;
        errors.push({ field: path, message: 'must not be null' });
        return SKIP;
      }
      return this.check(value, path, errors);
    },
  };
}

function typeName(value) {
  if (Array.isArray(value)) return 'array';
  return value === null ? 'null' : typeof value;
}

const v = {
  string({ min = 0, max = 10000, pattern, patternMessage, trim = false, oneOf, ...opts } = {}) {
    return make((value, path, errors) => {
      if (typeof value !== 'string') { errors.push({ field: path, message: `must be a string (got ${typeName(value)})` }); return SKIP; }
      const s = trim ? value.trim() : value;
      if (s.length < min) { errors.push({ field: path, message: min === 1 ? 'must not be empty' : `must be at least ${min} characters` }); return SKIP; }
      if (s.length > max) { errors.push({ field: path, message: `must be at most ${max} characters` }); return SKIP; }
      if (pattern && !pattern.test(s)) { errors.push({ field: path, message: patternMessage || 'has an invalid format' }); return SKIP; }
      if (oneOf && !oneOf.includes(s)) { errors.push({ field: path, message: `must be one of: ${oneOf.join(', ')}` }); return SKIP; }
      return s;
    }, opts);
  },
  enumOf(values, opts = {}) {
    return make((value, path, errors) => {
      if (typeof value !== 'string' || !values.includes(value)) {
        errors.push({ field: path, message: `must be one of: ${values.join(', ')}` });
        return SKIP;
      }
      return value;
    }, opts);
  },
  integer({ min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER, coerce = false, clamp = false, ...opts } = {}) {
    return make((value, path, errors) => {
      let n = value;
      if (coerce && typeof value === 'string' && /^-?\d{1,15}$/.test(value.trim())) n = Number(value.trim());
      if (typeof n !== 'number' || !Number.isInteger(n)) { errors.push({ field: path, message: 'must be an integer' }); return SKIP; }
      if (clamp) return Math.min(Math.max(n, min), max);
      if (n < min || n > max) { errors.push({ field: path, message: `must be between ${min} and ${max}` }); return SKIP; }
      return n;
    }, opts);
  },
  boolean({ coerce = false, ...opts } = {}) {
    return make((value, path, errors) => {
      if (coerce && (value === 'true' || value === 'false')) return value === 'true';
      if (typeof value !== 'boolean') { errors.push({ field: path, message: 'must be true or false' }); return SKIP; }
      return value;
    }, opts);
  },
  isoDate({ future = false, ...opts } = {}) {
    return make((value, path, errors) => {
      if (typeof value !== 'string' || value.length > 40 || !ISO_RE.test(value) || Number.isNaN(Date.parse(value))) {
        errors.push({ field: path, message: 'must be an ISO-8601 date/time' });
        return SKIP;
      }
      const iso = new Date(Date.parse(value)).toISOString();
      if (future && Date.parse(iso) <= Date.now()) { errors.push({ field: path, message: 'must be in the future' }); return SKIP; }
      return iso;
    }, opts);
  },
  object(shape, { allowUnknown = false, ...opts } = {}) {
    return make((value, path, errors) => {
      if (typeof value !== 'object' || Array.isArray(value)) { errors.push({ field: path, message: `must be an object (got ${typeName(value)})` }); return SKIP; }
      const out = {};
      for (const key of Object.keys(value)) {
        if (Object.prototype.hasOwnProperty.call(shape, key)) continue;
        if (allowUnknown) {
          // passed through untouched but prototype keys are blocked
          if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') out[key] = value[key];
        } else {
          errors.push({ field: path ? `${path}.${key}` : key, message: 'is not an allowed field' });
        }
      }
      for (const [key, schema] of Object.entries(shape)) {
        const r = schema.run(Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined, path ? `${path}.${key}` : key, errors);
        if (r !== SKIP) out[key] = r;
      }
      return out;
    }, opts);
  },
  array(item, { min = 0, max = 1000, ...opts } = {}) {
    return make((value, path, errors) => {
      if (!Array.isArray(value)) { errors.push({ field: path, message: `must be an array (got ${typeName(value)})` }); return SKIP; }
      if (value.length < min) { errors.push({ field: path, message: `must contain at least ${min} item(s)` }); return SKIP; }
      if (value.length > max) { errors.push({ field: path, message: `must contain at most ${max} items` }); return SKIP; }
      const out = [];
      value.forEach((x, i) => { const r = item.run(x, `${path}[${i}]`, errors); if (r !== SKIP) out.push(r); });
      return out;
    }, opts);
  },
  record(valueSchema, { maxKeys = 50, keyPattern, keyMessage, lowerCaseKeys = false, ...opts } = {}) {
    return make((value, path, errors) => {
      if (typeof value !== 'object' || Array.isArray(value)) { errors.push({ field: path, message: `must be an object (got ${typeName(value)})` }); return SKIP; }
      const keys = Object.keys(value);
      if (keys.length > maxKeys) { errors.push({ field: path, message: `must have at most ${maxKeys} entries` }); return SKIP; }
      const out = {};
      for (const k of keys) {
        if (keyPattern && !keyPattern.test(k)) { errors.push({ field: `${path}.${k.slice(0, 64)}`, message: keyMessage || 'invalid name' }); continue; }
        const r = valueSchema.run(value[k], `${path}.${k}`, errors);
        if (r !== SKIP) out[lowerCaseKeys ? k.toLowerCase() : k] = r;
      }
      return out;
    }, opts);
  },
  any(opts = {}) { return make((value) => value, opts); },
};

function validate(schema, input, root = '') {
  const errors = [];
  const out = schema.run(input === undefined ? undefined : input, root, errors);
  if (errors.length) {
    throw new ApiError('VALIDATION_FAILED', undefined, { details: errors.slice(0, 50).map((e) => ({ field: e.field || '(body)', message: e.message })) });
  }
  return out === SKIP ? undefined : out;
}

const METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const ROLES = Object.freeze(['admin', 'operator', 'viewer']);
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9-]{1,64}$/;
// eslint-disable-next-line no-control-regex
const SAFE_PATH_RE = /^\/[^\u0000-\u001f\u007f\s]*$/;
const SAMPLE_BODY_MAX = 1024 * 1024;

const sampleSchema = v.object({
  method: v.enumOf(METHODS),
  path: v.string({ min: 1, max: 4096, pattern: SAFE_PATH_RE, patternMessage: "must start with '/' and contain no spaces or control characters (URL-encode them, e.g. %20)" }),
  headers: v.record(v.string({ max: 4096 }), { maxKeys: 50, keyPattern: HEADER_NAME_RE, keyMessage: 'header names may only contain letters, digits and -', default: () => ({}) }),
  body: v.string({ max: SAMPLE_BODY_MAX, nullable: true, default: null }),
});

function sampleSizeProblems(sample, prefix = 'sample') {
  if (typeof sample.body === 'string' && Buffer.byteLength(sample.body, 'utf8') > SAMPLE_BODY_MAX) {
    return [{ field: `${prefix}.body`, message: 'must be at most 1 MiB' }];
  }
  return [];
}

const scopeSchema = v.object({
  pathPrefix: v.string({ min: 1, max: 512, pattern: SAFE_PATH_RE, patternMessage: "must start with '/' and contain no spaces or control characters", nullable: true, optional: true }),
  location: v.string({
    min: 1, max: 200, nullable: true, optional: true,
    pattern: /^(path|method|body|query_names|body_names|(query|body|header|cookie)\.[^\s]{1,190})$/,
    patternMessage: 'must be a match location such as query.q, body.name, header.user-agent, path',
  }),
  method: v.enumOf(METHODS, { nullable: true, optional: true }),
});

const ruleIdSchema = v.integer({ min: 1000, max: 999999 });

module.exports = {
  v, validate, SKIP, METHODS, ROLES, USERNAME_RE, HEADER_NAME_RE, SAMPLE_BODY_MAX,
  sampleSchema, sampleSizeProblems, scopeSchema, ruleIdSchema,
};
