'use strict';
const crypto = require('node:crypto');

const DEFAULT_CONFIG = Object.freeze({
  mode: 'block',
  thresholds: { flag: 3, block: 5 },
  limits: { maxBodyBytes: 1048576, inspectBodyBytes: 65536, maxUrlLength: 4096, maxHeaderCount: 100, maxArgs: 200, decodeRounds: 3 },
  rateLimit: { enabled: true, windowMs: 60000, maxRequests: 300 },
});

function validateConfig(cfg) {
  const errors = [];
  if (!cfg || typeof cfg !== 'object') return { ok: false, config: null, errors: [{ field: '', message: 'must be an object' }] };
  const c = structuredClone({ ...DEFAULT_CONFIG, ...cfg });
  if (!['block', 'monitor'].includes(c.mode)) errors.push({ field: 'mode', message: 'must be block or monitor' });
  const t = c.thresholds || {};
  if (!Number.isInteger(t.flag) || !Number.isInteger(t.block) || t.flag < 1 || t.flag > t.block || t.block > 100) {
    errors.push({ field: 'thresholds', message: '1 <= flag <= block <= 100' });
  }
  const r = c.rateLimit || {};
  if (typeof r.enabled !== 'boolean' || !Number.isInteger(r.windowMs) || !Number.isInteger(r.maxRequests) || r.maxRequests < 1) {
    errors.push({ field: 'rateLimit', message: 'invalid' });
  }
  if (!c.limits || !Number.isInteger(c.limits.maxBodyBytes)) errors.push({ field: 'limits.maxBodyBytes', message: 'invalid' });
  return { ok: errors.length === 0, config: errors.length ? null : c, errors };
}

const RULE_RE = /^\s*rule\s+(\d+)\s+"([^"]+)"\s*\{([\s\S]*)\}\s*$/;

function validateRuleSource(src) {
  const m = RULE_RE.exec(String(src || ''));
  if (!m) return { ok: false, rule: null, errors: [{ line: 1, col: 1, message: 'expected: rule <id> "<name>" { ... }' }] };
  const id = Number(m[1]);
  const body = m[3];
  const when = /when\s+args\s+contains\s+"([^"]+)"/.exec(body);
  if (!when) return { ok: false, rule: null, errors: [{ line: 2, col: 3, message: 'missing when clause' }] };
  if (id < 1000 || id > 999999) return { ok: false, rule: null, errors: [{ line: 1, col: 6, message: 'rule id out of range' }] };
  const get = (k, d) => { const x = new RegExp(`${k}\\s+(\\S+)`).exec(body); return x ? x[1] : d; };
  return {
    ok: true,
    errors: [],
    rule: { id, name: m[2], severity: get('severity', 'medium'), score: Number(get('score', 3)), category: get('category', 'generic'), needle: when[1].toLowerCase() },
  };
}

function parseRuleFile(text) {
  const chunks = String(text).split(/^(?=rule\s)/m).map((s) => s.trim()).filter(Boolean);
  const rules = [];
  const errors = [];
  for (const source of chunks) {
    const v = validateRuleSource(source);
    if (v.ok) rules.push({ id: v.rule.id, source });
    else errors.push(...v.errors);
  }
  return { rules, errors };
}

function compileRules(records) {
  const rules = [];
  const errors = [];
  for (const r of records) {
    if (r.enabled === false) continue;
    const v = validateRuleSource(r.source);
    if (!v.ok) { errors.push({ ruleId: r.id, ...v.errors[0] }); continue; }
    rules.push({ ...v.rule, version: r.version });
  }
  const rulesetVersion = 'sha256-' + crypto.createHash('sha256').update(JSON.stringify(rules.map((r) => [r.id, r.version]))).digest('hex').slice(0, 12);
  return { rules, errors, rulesetVersion };
}

function createRateLimiter(opts) {
  let o = { ...opts };
  const hits = new Map();
  return {
    check(key, now) {
      const list = (hits.get(key) || []).filter((t) => t > now - o.windowMs);
      list.push(now);
      hits.set(key, list);
      return { checked: true, limited: o.enabled && list.length > o.maxRequests, count: list.length, limit: o.maxRequests, windowMs: o.windowMs };
    },
    configure(n) { o = { ...n }; },
    reset() { hits.clear(); },
  };
}

function safeDecode(s) { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch { return String(s); } }

function inspect(raw, ctx) {
  const started = process.hrtime.bigint();
  const cfg = ctx.config;
  const [p, qs = ''] = String(raw.url || '/').split('?');
  const args = qs ? qs.split('&').map((kv) => { const i = kv.indexOf('='); return i < 0 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)]; }) : [];
  const bodyText = raw.body ? Buffer.from(raw.body).toString('utf8') : '';
  const bodyArgs = bodyText && /urlencoded/.test(raw.headers['content-type'] || '') ? bodyText.split('&').map((kv) => kv.split('=')) : [];
  const targets = [
    ...args.map(([k, v]) => ({ location: `query.${safeDecode(k)}`, value: safeDecode(v) })),
    ...bodyArgs.map(([k, v]) => ({ location: `body.${safeDecode(k)}`, value: safeDecode(v || '') })),
  ];
  const path = safeDecode(p);
  const matches = [];
  const suppressed = [];
  for (const rule of ctx.rules) {
    for (const t of targets) {
      if (!t.value.toLowerCase().includes(rule.needle)) continue;
      const m = {
        ruleId: rule.id, ruleName: rule.name, ruleVersion: rule.version, severity: rule.severity, points: rule.score,
        category: rule.category, tags: [rule.category], location: t.location, operator: 'contains',
        excerpt: t.value.slice(0, 120), decodedVia: ['url'], suppressedBy: null,
      };
      const exc = (ctx.exceptions || []).find((x) => x.ruleId === rule.id
        && (x.scope.pathPrefix === null || path.startsWith(x.scope.pathPrefix))
        && (x.scope.location === null || x.scope.location === t.location)
        && (x.scope.method === null || x.scope.method === raw.method));
      if (exc) suppressed.push({ ...m, suppressedBy: exc.id });
      else matches.push(m);
    }
  }
  const total = matches.reduce((s, m) => s + m.points, 0);
  const byCategory = {};
  for (const m of matches) byCategory[m.category] = (byCategory[m.category] || 0) + m.points;
  let verdict = total >= cfg.thresholds.block ? 'block' : total >= cfg.thresholds.flag ? 'flag' : 'allow';
  let statusCode = verdict === 'block' ? 403 : null;
  let blockReason = verdict === 'block' ? 'SCORE_THRESHOLD' : null;
  if ((raw.bodyBytes || 0) > cfg.limits.maxBodyBytes) { verdict = 'block'; statusCode = 413; blockReason = 'BODY_TOO_LARGE'; }
  let rateLimit = { checked: false, limited: false, count: 0, limit: cfg.rateLimit.maxRequests, windowMs: cfg.rateLimit.windowMs };
  if (ctx.rateLimiter && cfg.rateLimit.enabled) {
    rateLimit = ctx.rateLimiter.check(ctx.clientKey, ctx.now);
    if (rateLimit.limited) { verdict = 'block'; statusCode = 429; blockReason = 'RATE_LIMITED'; }
  }
  const wouldBlock = verdict === 'block';
  const action = wouldBlock ? (cfg.mode === 'block' ? 'blocked' : 'logged') : 'allowed';
  if (raw.headers['x-fake-engine-throw']) throw new Error('fake engine failure');
  return {
    verdict, action, wouldBlock, statusCode: action === 'blocked' ? statusCode : null, blockReason: wouldBlock ? blockReason : null, mode: cfg.mode,
    score: { total, flagThreshold: cfg.thresholds.flag, blockThreshold: cfg.thresholds.block, byCategory, contributions: matches.map((m) => ({ source: 'rule', id: String(m.ruleId), points: m.points, reason: m.ruleName })) },
    matches, suppressed, anomalies: [], rateLimit,
    request: { method: raw.method, path, queryNames: args.map((a) => a[0]), bodyNames: [], contentType: raw.headers['content-type'] || null, bodyBytes: raw.bodyBytes || 0, inspectedBytes: bodyText.length, truncated: false, userAgent: (raw.headers['user-agent'] || '').slice(0, 80) || null },
    explanation: matches.length ? matches.map((m) => `Rule ${m.ruleId} '${m.ruleName}' matched ${m.location} (+${m.points})`) : ['No rule matched.'],
    recommendation: verdict === 'allow' ? 'Allow.' : 'Review.',
    engine: { engineVersion: 'fake-1', rulesetVersion: ctx.rulesetVersion, configVersion: ctx.configVersion },
    timings: { parseMs: 0, rulesMs: 0, totalMs: Number(process.hrtime.bigint() - started) / 1e6 },
  };
}

const DEFAULT_RULES = `
rule 942100 "SQLi boolean tautology" {
  when args contains "or 1=1"
  severity critical
  score 5
  category sqli
}
rule 941100 "XSS script tag" {
  when args contains "<script"
  severity high
  score 5
  category xss
}
rule 930100 "Path traversal" {
  when args contains "../"
  severity medium
  score 3
  category traversal
}
`;

module.exports = {
  ENGINE_VERSION: 'fake-1', DEFAULT_CONFIG, validateConfig, validateRuleSource, parseRuleFile, compileRules,
  createRateLimiter, inspect, redact: (x) => x, excerpt: (s) => String(s).slice(0, 120), DEFAULT_RULES,
};
