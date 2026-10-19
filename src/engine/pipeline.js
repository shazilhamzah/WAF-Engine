'use strict';
/**
 * inspect(raw, ctx): the full decision pipeline (contract §1.2), executed in the proposal's order:
 *   1 parser      -> parseRequest (malformed / oversized input rejected before any rule runs)
 *   2 rule DSL    -> evaluateRules over normalized variants; approved exceptions applied here
 *   3 scoring     -> computeScore (rule points + anomaly points vs thresholds)
 *   4 modes       -> applyMode (block enforces, monitor logs with wouldBlock)
 *   5 rate limit  -> per-client sliding window (outcome mapped through the same mode policy)
 *   6 audit       -> the returned Decision is what the caller stores (no I/O here)
 *   7 tuning      -> exceptions come from ctx.exceptions; explanation + evidence are in the Decision
 *
 * inspect never throws: any internal failure returns a fail-safe MALFORMED_REQUEST decision.
 */

const { performance } = require('node:perf_hooks');
const { resolveConfig } = require('./config');
const { parseRequest } = require('./parser');
const { evaluateRules } = require('./evaluate');
const { prepareExceptions } = require('./exceptions');
const { computeScore } = require('./scoring');
const { applyMode } = require('./modes');
const { buildExplanation } = require('./explain');
const { excerpt } = require('./redact');

const ENGINE_VERSION = '1.0.0';
const configCache = new WeakMap();

function getConfig(cfg) {
  if (cfg && typeof cfg === 'object') {
    const hit = configCache.get(cfg);
    if (hit) return hit;
    const resolved = resolveConfig(cfg);
    configCache.set(cfg, resolved);
    return resolved;
  }
  return resolveConfig(undefined);
}

function round3(n) {
  return Math.round(n * 1000) / 1000;
}

/** Truncated, control-character-free copy for the request summary. */
function clip(s, n) {
  if (typeof s !== 'string') return null;
  return excerpt(s, 0, n).slice(0, n);
}

function summarize(parsed) {
  if (parsed.ok) {
    const r = parsed.request;
    return {
      method: r.method,
      path: clip(r.path, 200),
      normalizedPath: clip(r.canonicalPath, 200),
      queryNames: r.queryNames.slice(0, 50).map((n) => clip(n, 64)),
      bodyNames: r.bodyNames.slice(0, 50).map((n) => clip(n, 64)),
      contentType: r.contentType ? clip(r.contentType.split(';')[0].trim(), 100) : null,
      bodyBytes: r.bodyBytes,
      inspectedBytes: r.inspectedBytes,
      truncated: r.truncated,
      userAgent: r.userAgent ? clip(r.userAgent, 80) : null,
    };
  }
  const p = parsed.partial || {};
  return {
    method: p.method ? clip(p.method, 24) : null,
    path: p.path ? clip(p.path, 200) : null,
    normalizedPath: null,
    queryNames: [],
    bodyNames: [],
    contentType: p.contentType ? clip(p.contentType.split(';')[0].trim(), 100) : null,
    bodyBytes: Number.isFinite(p.bodyBytes) ? p.bodyBytes : 0,
    inspectedBytes: 0,
    truncated: false,
    userAgent: p.userAgent ? clip(p.userAgent, 80) : null,
  };
}

function checkRateLimit(ctx, config, now) {
  const notChecked = { checked: false, limited: false, count: 0, limit: config.rateLimit.maxRequests, windowMs: config.rateLimit.windowMs };
  const limiter = ctx.rateLimiter;
  if (!limiter || typeof limiter.check !== 'function' || !config.rateLimit.enabled) return notChecked;
  try {
    const opts = limiter.options;
    if (opts && typeof limiter.configure === 'function'
      && (opts.windowMs !== config.rateLimit.windowMs || opts.maxRequests !== config.rateLimit.maxRequests)) {
      limiter.configure({ windowMs: config.rateLimit.windowMs, maxRequests: config.rateLimit.maxRequests });
    }
    const r = limiter.check(ctx.clientKey, now);
    if (!r || typeof r !== 'object') return notChecked;
    return {
      checked: true,
      limited: Boolean(r.limited),
      count: Number.isFinite(r.count) ? r.count : 0,
      limit: Number.isFinite(r.limit) ? r.limit : config.rateLimit.maxRequests,
      windowMs: Number.isFinite(r.windowMs) ? r.windowMs : config.rateLimit.windowMs,
      retryAfterSeconds: Number.isFinite(r.retryAfterSeconds) ? r.retryAfterSeconds : 0,
    };
  } catch {
    return notChecked;
  }
}

/**
 * @param {object} raw contract §3.1 raw request
 * @param {object} ctx contract §3.3 inspect context
 * @returns {object} Decision (contract §3.6)
 */
function inspect(raw, ctx) {
  const t0 = performance.now();
  let mode = 'block';
  let c = {};
  try {
    c = ctx && typeof ctx === 'object' ? ctx : {};
    const config = getConfig(c.config);
    mode = config.mode;
    const now = Number.isFinite(c.now) ? c.now : Date.now();

    // 1. parser
    const parsed = parseRequest(raw, config.limits);
    const t1 = performance.now();

    // 2. rules + exceptions (only for requests that passed the parser)
    let matches = [];
    let suppressed = [];
    if (parsed.ok) {
      const exceptions = prepareExceptions(c.exceptions, now);
      ({ matches, suppressed } = evaluateRules(c.rules, parsed.request, exceptions));
    }
    const t2 = performance.now();

    // 3. scoring
    const anomalies = parsed.anomalies.map((a) => ({ code: a.code, message: a.message, points: a.points }));
    const { score, verdict: scoreVerdict } = computeScore(matches, anomalies, config.thresholds);

    // 5. rate limit (every request counts, including rejected ones)
    const rateLimit = checkRateLimit(c, config, now);

    let verdict = scoreVerdict;
    let blockReason = null;
    let status = null;
    if (!parsed.ok) {
      verdict = 'block';
      blockReason = parsed.error.code;
      status = parsed.statusCode;
    } else if (scoreVerdict === 'block') {
      blockReason = 'SCORE_THRESHOLD';
      status = 403;
    } else if (rateLimit.limited) {
      verdict = 'block';
      blockReason = 'RATE_LIMITED';
      status = 429;
    }

    // 4. mode (applied to the final would-block outcome)
    const m = applyMode(mode, blockReason !== null, status);

    const ex = buildExplanation({
      parsedOk: parsed.ok, anomalies, matches, suppressed, score, scoreVerdict, verdict,
      blockReason, mode, action: m.action, wouldBlock: m.wouldBlock, statusCode: m.statusCode, rateLimit,
    });
    const t3 = performance.now();
    return {
      verdict,
      action: m.action,
      wouldBlock: m.wouldBlock,
      statusCode: m.statusCode,
      blockReason,
      mode,
      score,
      matches,
      suppressed,
      anomalies,
      rateLimit,
      request: summarize(parsed),
      explanation: ex.explanation,
      recommendation: ex.recommendation,
      engine: {
        engineVersion: ENGINE_VERSION,
        rulesetVersion: typeof c.rulesetVersion === 'string' ? c.rulesetVersion : null,
        configVersion: c.configVersion === undefined ? null : c.configVersion,
      },
      timings: { parseMs: round3(t1 - t0), rulesMs: round3(t2 - t1), totalMs: round3(t3 - t0) },
    };
  } catch {
    return failSafeDecision(mode, c, t0);
  }
}

/** Decision returned when inspection itself failed: fail closed in block mode, log in monitor mode. */
function failSafeDecision(mode, ctx, t0) {
  const monitor = mode === 'monitor';
  let cfgVersion = null;
  let rsVersion = null;
  try {
    cfgVersion = ctx && ctx.configVersion !== undefined ? ctx.configVersion : null;
    rsVersion = ctx && typeof ctx.rulesetVersion === 'string' ? ctx.rulesetVersion : null;
  } catch { /* ignore hostile getters */ }
  return {
    verdict: 'block',
    action: monitor ? 'logged' : 'blocked',
    wouldBlock: true,
    statusCode: monitor ? null : 400,
    blockReason: 'MALFORMED_REQUEST',
    mode: monitor ? 'monitor' : 'block',
    score: { total: 0, flagThreshold: 3, blockThreshold: 5, byCategory: {}, contributions: [] },
    matches: [],
    suppressed: [],
    anomalies: [{ code: 'INSPECTION_ERROR', message: 'The request could not be inspected safely; failing closed', points: 0 }],
    rateLimit: { checked: false, limited: false, count: 0, limit: 0, windowMs: 0 },
    request: {
      method: null, path: null, normalizedPath: null, queryNames: [], bodyNames: [], contentType: null,
      bodyBytes: 0, inspectedBytes: 0, truncated: false, userAgent: null,
    },
    explanation: ['The engine could not inspect this request safely and treated it as malformed (fail-safe)'],
    recommendation: monitor
      ? 'Investigate: inspection failed (monitor mode: logged, not blocked).'
      : 'Reject: inspection failed; the request was blocked as a precaution.',
    engine: { engineVersion: ENGINE_VERSION, rulesetVersion: rsVersion, configVersion: cfgVersion },
    timings: { parseMs: 0, rulesMs: 0, totalMs: round3(performance.now() - t0) },
  };
}

module.exports = { ENGINE_VERSION, inspect, failSafeDecision };
