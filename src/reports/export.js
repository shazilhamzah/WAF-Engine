'use strict';
/**
 * Report export (contract §8, owner Wahaj).
 *
 *   const { buildReport } = require('./src/reports/export');
 *   const { filename, contentType, body } = buildReport({
 *     events,          // full Event objects (contract §5.2 "Event"); only sanitized fields are used
 *     stats,           // optional dashboard stats (GET /api/stats shape)
 *     config,          // active EngineConfig (mode, thresholds, limits, rateLimit)
 *     rulesetVersion, configVersion,
 *     generatedBy,     // e.g. { username: 'alice', role: 'operator' } or 'alice'
 *     generatedAt,     // ISO string (default: now)
 *     filters,         // the filters used to select the events
 *   }, 'json' | 'csv' | 'html');
 *
 * Sanitization guarantees (tested in test/unit/reports):
 *  - never includes stored samples (headers / bodies), client pseudonyms, session data or secrets;
 *  - excerpts are re-redacted, control characters escaped and capped at 120 characters;
 *  - secret-looking query parameters in paths are masked;
 *  - HTML: every value is HTML-escaped; the document has no scripts and a restrictive CSP meta tag;
 *  - CSV: RFC 4180 quoting, cells beginning with = + - @ TAB CR are prefixed with ' (formula injection).
 */

const FORMATS = Object.freeze(['json', 'csv', 'html']);
const CONTENT_TYPES = Object.freeze({
  json: 'application/json; charset=utf-8',
  csv: 'text/csv; charset=utf-8',
  html: 'text/html; charset=utf-8',
});
const EXCERPT_MAX = 120;
const TEXT_MAX = 500;
const MASK = '[REDACTED]';
const SECRET_NAME_RE = /pass(word|wd|phrase)?|pwd|secret|token|cookie|authori[sz]ation|api[-_]?key|session|csrf|credential|private[-_]?key|^sid$|^waf_sid$/i;
const SECRET_VALUE_RES = [
  /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}/gi,
  /\b(pass(word|wd)?|pwd|secret|token|api[-_]?key|session(id)?|sid|csrf(token)?)\s*[=:]\s*("[^"]*"|'[^']*'|[^\s&;,"']+)/gi,
];

// ---------------------------------------------------------------------------------------------
// Sanitizers
// ---------------------------------------------------------------------------------------------

/** Escapes control characters so they are visible but inert (\n, \x00 …). */
function escapeControls(str) {
  return String(str).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, (c) => {
    if (c === '\n') return '\\n';
    if (c === '\r') return '\\r';
    if (c === '\t') return '\\t';
    return `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
  });
}

function cap(str, max) {
  const s = String(str);
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Plain text field: controls escaped, length capped. null/undefined → null. */
function safeText(value, max = TEXT_MAX) {
  if (value === null || value === undefined) return null;
  return cap(escapeControls(String(value)), max);
}

/** Masks secrets that may appear inside an excerpt (tokens, password=…, Bearer …). */
function redactSecretsInText(str) {
  let out = String(str);
  for (const re of SECRET_VALUE_RES) {
    out = out.replace(re, (m, ...groups) => {
      const key = groups[0];
      if (/^(bearer|basic)$/i.test(key)) return `${key} ${MASK}`;
      const sep = m.includes('=') ? '=' : ':';
      return `${key}${sep}${MASK}`;
    });
  }
  return out;
}

/** Redacted, ≤120-char, control-free excerpt; fully masked when its location is secret. */
function safeExcerpt(excerpt, location) {
  if (excerpt === null || excerpt === undefined) return null;
  const loc = String(location || '');
  const name = loc.includes('.') ? loc.slice(loc.indexOf('.') + 1) : '';
  if (/^(cookie|header\.(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token))/i.test(loc)
    || (name && SECRET_NAME_RE.test(name.split('.').pop()))) {
    return MASK;
  }
  return cap(escapeControls(redactSecretsInText(excerpt)), EXCERPT_MAX);
}

/** Masks values of secret-looking query parameters in a path ("/x?token=abc" → "/x?token=[REDACTED]"). */
function redactPath(path) {
  if (path === null || path === undefined) return null;
  const s = String(path);
  const q = s.indexOf('?');
  if (q < 0) return cap(escapeControls(s), 2048);
  const base = s.slice(0, q);
  const query = s.slice(q + 1).split('&').map((pair) => {
    const eq = pair.indexOf('=');
    const rawName = eq >= 0 ? pair.slice(0, eq) : pair;
    let name = rawName;
    try { name = decodeURIComponent(rawName.replace(/\+/g, ' ')); } catch { /* keep raw */ }
    return eq >= 0 && SECRET_NAME_RE.test(name) ? `${rawName}=${MASK}` : pair;
  }).join('&');
  return cap(escapeControls(`${base}?${query}`), 2048);
}

function num(v) {
  const n = Number(v);
  return v === null || v === undefined || v === '' || !Number.isFinite(n) ? null : n;
}

function sanitizeMatch(m) {
  const x = m || {};
  return {
    ruleId: num(x.ruleId) ?? safeText(x.ruleId, 20),
    ruleName: safeText(x.ruleName, 120),
    ruleVersion: num(x.ruleVersion),
    severity: safeText(x.severity, 20),
    points: num(x.points),
    category: safeText(x.category, 40),
    tags: Array.isArray(x.tags) ? x.tags.slice(0, 20).map((t) => safeText(t, 40)) : [],
    location: safeText(x.location, 120),
    operator: safeText(x.operator, 40),
    excerpt: safeExcerpt(x.excerpt, x.location),
    decodedVia: Array.isArray(x.decodedVia) ? x.decodedVia.slice(0, 10).map((d) => safeText(d, 40)) : [],
    suppressedBy: safeText(x.suppressedBy, 80),
  };
}

/**
 * Projection of a stored Event into the report shape. Only whitelisted, sanitized fields survive;
 * in particular `sample`, `clientId` and any raw header/body values are dropped.
 */
function sanitizeEvent(evt) {
  const e = evt || {};
  const d = (e.decision && typeof e.decision === 'object') ? e.decision : {};
  const score = d.score || {};
  const eng = d.engine || {};
  const req = d.request || {};
  const matches = Array.isArray(d.matches) ? d.matches.filter((m) => m && !m.suppressedBy).slice(0, 100).map(sanitizeMatch) : [];
  const seen = new Set();
  const suppressed = [
    ...(Array.isArray(d.suppressed) ? d.suppressed : []),
    ...(Array.isArray(d.matches) ? d.matches.filter((m) => m && m.suppressedBy) : []),
  ].filter((m) => {
    if (!m) return false;
    const key = `${m.ruleId}|${m.location}|${m.suppressedBy}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 100).map(sanitizeMatch);
  return {
    id: safeText(e.id, 100),
    ts: safeText(e.ts, 40),
    source: safeText(e.source, 20),
    label: safeText(e.label, 200),
    method: safeText(e.method || req.method, 16),
    path: redactPath(e.path || req.path),
    verdict: safeText(e.verdict || d.verdict, 10),
    action: safeText(e.action || d.action, 10),
    score: num(score.total) ?? num(e.score) ?? 0,
    flagThreshold: num(score.flagThreshold),
    blockThreshold: num(score.blockThreshold),
    byCategory: Object.fromEntries(Object.entries(score.byCategory || {}).slice(0, 30).map(([k, v]) => [safeText(k, 40), num(v)])),
    mode: safeText(e.mode || d.mode, 10),
    wouldBlock: Boolean(d.wouldBlock),
    statusCode: num(d.statusCode),
    blockReason: safeText(d.blockReason, 40),
    matchedRuleIds: matches.map((m) => m.ruleId),
    matches,
    suppressed,
    anomalies: Array.isArray(d.anomalies) ? d.anomalies.slice(0, 50).map((a) => ({
      code: safeText(a && a.code, 60), message: safeText(a && a.message, 300), points: num(a && a.points),
    })) : [],
    rateLimited: Boolean(d.rateLimit && d.rateLimit.limited),
    explanation: Array.isArray(d.explanation) ? d.explanation.slice(0, 50).map((t) => redactSecretsInText(safeText(t, TEXT_MAX))) : [],
    recommendation: d.recommendation ? redactSecretsInText(safeText(d.recommendation, TEXT_MAX)) : null,
    rulesetVersion: safeText(e.rulesetVersion || eng.rulesetVersion, 80),
    configVersion: num(e.configVersion ?? eng.configVersion),
    engineVersion: safeText(eng.engineVersion, 40),
    latencyMs: num(e.latencyMs),
    submittedBy: safeText(e.submittedBy, 64),
    replayOf: safeText(e.replayOf, 100),
  };
}

/** Only the tunable, non-secret configuration fields. */
function sanitizeConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') return null;
  const pick = (o, keys) => (o && typeof o === 'object' ? Object.fromEntries(keys.filter((k) => k in o).map((k) => [k, typeof o[k] === 'boolean' ? o[k] : num(o[k])])) : null);
  return {
    mode: safeText(cfg.mode, 10),
    thresholds: pick(cfg.thresholds, ['flag', 'block']),
    limits: pick(cfg.limits, ['maxBodyBytes', 'inspectBodyBytes', 'maxUrlLength', 'maxHeaderCount', 'maxArgs', 'decodeRounds']),
    rateLimit: pick(cfg.rateLimit, ['enabled', 'windowMs', 'maxRequests']),
  };
}

function sanitizeFilters(filters) {
  const out = {};
  for (const [k, v] of Object.entries(filters || {})) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) out[safeText(k, 40)] = v.slice(0, 500).map((x) => safeText(x, 100));
    else out[safeText(k, 40)] = safeText(v, 200);
  }
  return out;
}

function generatorText(generatedBy) {
  if (!generatedBy) return 'unknown';
  if (typeof generatedBy === 'string') return safeText(generatedBy, 100);
  const name = safeText(generatedBy.username || generatedBy.name || 'unknown', 64);
  return generatedBy.role ? `${name} (${safeText(generatedBy.role, 20)})` : name;
}

// ---------------------------------------------------------------------------------------------
// Summary metrics
// ---------------------------------------------------------------------------------------------

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

function summarize(events) {
  const byVerdict = { allow: 0, flag: 0, block: 0 };
  const byAction = { allowed: 0, logged: 0, blocked: 0 };
  const bySource = {};
  const byCategory = {};
  const rules = new Map();
  let wouldBlockLogged = 0;
  let withSuppressed = 0;
  let scoreSum = 0;
  let scoreMax = 0;
  const latencies = [];
  for (const e of events) {
    if (e.verdict in byVerdict) byVerdict[e.verdict] += 1;
    if (e.action in byAction) byAction[e.action] += 1;
    if (e.source) bySource[e.source] = (bySource[e.source] || 0) + 1;
    if (e.wouldBlock && e.action !== 'blocked') wouldBlockLogged += 1;
    if (e.suppressed.length) withSuppressed += 1;
    scoreSum += e.score || 0;
    scoreMax = Math.max(scoreMax, e.score || 0);
    if (e.latencyMs !== null) latencies.push(e.latencyMs);
    for (const [cat, pts] of Object.entries(e.byCategory)) if (pts) byCategory[cat] = (byCategory[cat] || 0) + 1;
    for (const m of e.matches) {
      const key = String(m.ruleId);
      const r = rules.get(key) || { ruleId: m.ruleId, name: m.ruleName, category: m.category, count: 0 };
      r.count += 1;
      rules.set(key, r);
    }
  }
  latencies.sort((a, b) => a - b);
  const total = events.length;
  return {
    totalEvents: total,
    byVerdict,
    byAction,
    bySource,
    byCategory,
    // False-positive review aids: events that were flagged/blocked, events that monitor mode let through,
    // and events where approved exceptions suppressed matches.
    falsePositiveReview: {
      flaggedOrBlocked: byVerdict.flag + byVerdict.block,
      wouldBlockButLogged: wouldBlockLogged,
      withSuppressedMatches: withSuppressed,
      allowedWithoutMatches: events.filter((e) => e.verdict === 'allow' && e.matches.length === 0).length,
    },
    topRules: [...rules.values()].sort((a, b) => b.count - a.count || String(a.ruleId).localeCompare(String(b.ruleId))).slice(0, 10),
    score: { average: total ? Math.round((scoreSum / total) * 100) / 100 : 0, max: scoreMax },
    latency: { p50Ms: percentile(latencies, 50), p95Ms: percentile(latencies, 95) },
  };
}

// ---------------------------------------------------------------------------------------------
// Formats
// ---------------------------------------------------------------------------------------------

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/`/g, '&#96;');
}

const FORMULA_START = /^[=+\-@\t\r]/;
/** One CSV cell: formula-injection prefix + RFC 4180 quoting (every cell quoted). */
function csvCell(value) {
  if (value === null || value === undefined) return '""';
  let s = typeof value === 'number' || typeof value === 'boolean' ? String(value) : String(value);
  if (typeof value === 'string' && FORMULA_START.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

function toCsv(meta, events) {
  const header = [
    'id', 'timestamp', 'source', 'label', 'method', 'path', 'verdict', 'action', 'score', 'flag_threshold',
    'block_threshold', 'mode', 'would_block', 'status_code', 'block_reason', 'matched_rules', 'categories',
    'match_locations', 'excerpts', 'decoded_via', 'suppressed_rules', 'anomalies', 'explanation', 'recommendation',
    'ruleset_version', 'config_version', 'engine_version', 'latency_ms', 'replay_of', 'submitted_by',
  ];
  const rows = [header];
  for (const e of events) {
    rows.push([
      e.id, e.ts, e.source, e.label, e.method, e.path, e.verdict, e.action, e.score, e.flagThreshold,
      e.blockThreshold, e.mode, e.wouldBlock, e.statusCode, e.blockReason,
      e.matches.map((m) => `${m.ruleId} ${m.ruleName || ''}`.trim()).join(' | '),
      Object.keys(e.byCategory).join(' | '),
      e.matches.map((m) => m.location).join(' | '),
      e.matches.map((m) => m.excerpt).join(' | '),
      e.matches.map((m) => m.decodedVia.join('+') || 'none').join(' | '),
      e.suppressed.map((m) => `${m.ruleId} by ${m.suppressedBy || '?'}`).join(' | '),
      e.anomalies.map((a) => a.code).join(' | '),
      e.explanation.join(' | '),
      e.recommendation, e.rulesetVersion, e.configVersion, e.engineVersion, e.latencyMs, e.replayOf, e.submittedBy,
    ]);
  }
  // UTF-8 BOM helps spreadsheet tools detect the encoding; CRLF per RFC 4180.
  return `﻿${rows.map((r) => r.map(csvCell).join(',')).join('\r\n')}\r\n`;
}

const HTML_STYLE = `
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem;color:#172033;line-height:1.5}
h1{font-size:1.6rem;margin-bottom:.25rem}h2{font-size:1.2rem;margin-top:2rem;border-bottom:2px solid #c9d2e0}h3{font-size:1rem;margin:1rem 0 .25rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.9rem}th,td{border:1px solid #c9d2e0;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#eef2f8}code{font-family:ui-monospace,Consolas,monospace;background:#eef2f8;padding:0 .25rem;overflow-wrap:anywhere;word-break:break-word}
.meta{color:#4a5568}.badge{font-weight:700}.allow{color:#14532d}.flag{color:#713f12}.block{color:#7f1d1d}
.event{border:1px solid #c9d2e0;border-radius:6px;padding:.5rem 1rem;margin:1rem 0;page-break-inside:avoid}
.note{background:#dbeafe;padding:.5rem .75rem;border-radius:6px}`;

const VERDICT_ICON = { allow: '✔', flag: '⚑', block: '⛔' };

function htmlTable(headers, rows) {
  if (!rows.length) return '<p class="meta">None.</p>';
  return `<table><thead><tr>${headers.map((h) => `<th scope="col">${escapeHtml(h)}</th>`).join('')}</tr></thead><tbody>${
    rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

function kvRows(obj) {
  return Object.entries(obj).map(([k, v]) => [escapeHtml(k), escapeHtml(v)]);
}

function toHtml(meta, summary, events) {
  const e = escapeHtml;
  const cfg = meta.config;
  const filterRows = Object.entries(meta.filters).map(([k, v]) => [e(k), e(Array.isArray(v) ? v.join(', ') : v)]);
  const eventSections = events.map((ev) => {
    const cls = ['allow', 'flag', 'block'].includes(ev.verdict) ? ev.verdict : '';
    const matchRows = ev.matches.map((m) => [
      `<code>${e(m.ruleId)}</code> ${e(m.ruleName)}`, e(m.ruleVersion), e(m.severity), m.points === null ? '' : `+${e(m.points)}`,
      e(m.category), `<code>${e(m.location)}</code>`, e(m.operator), `<code>${e(m.excerpt)}</code>`, e(m.decodedVia.join(', ') || 'none'),
    ]);
    const supRows = ev.suppressed.map((m) => [`<code>${e(m.ruleId)}</code> ${e(m.ruleName)}`, `<code>${e(m.location)}</code>`, `<code>${e(m.excerpt)}</code>`, `<code>${e(m.suppressedBy)}</code>`]);
    return `<section class="event">
<h3>${e(ev.method)} <code>${e(ev.path)}</code></h3>
<p><span class="badge ${cls}">${e(VERDICT_ICON[ev.verdict] || '?')} ${e(ev.verdict)}</span> · action <strong>${e(ev.action)}</strong>${ev.statusCode ? ` · HTTP ${e(ev.statusCode)}` : ''} · mode ${e(ev.mode)} · score <strong>${e(ev.score)}</strong> (flag ${e(ev.flagThreshold)}, block ${e(ev.blockThreshold)})${ev.wouldBlock ? ' · would block' : ''}${ev.blockReason ? ` · reason ${e(ev.blockReason)}` : ''}</p>
<p class="meta">Event <code>${e(ev.id)}</code> · ${e(ev.ts)} · source ${e(ev.source)}${ev.label ? ` · “${e(ev.label)}”` : ''}${ev.submittedBy ? ` · by ${e(ev.submittedBy)}` : ''}${ev.replayOf ? ` · replay of <code>${e(ev.replayOf)}</code>` : ''}</p>
<p><strong>Explanation</strong></p>
${ev.explanation.length ? `<ol>${ev.explanation.map((t) => `<li>${e(t)}</li>`).join('')}</ol>` : '<p class="meta">No rule matched and no anomalies were found.</p>'}
${ev.recommendation ? `<p><strong>Recommendation:</strong> ${e(ev.recommendation)}</p>` : ''}
${matchRows.length ? htmlTable(['Rule', 'Ver', 'Severity', 'Points', 'Category', 'Location', 'Operator', 'Excerpt (redacted)', 'Decoded via'], matchRows) : ''}
${supRows.length ? `<p><strong>Suppressed by approved exceptions</strong></p>${htmlTable(['Rule', 'Location', 'Excerpt', 'Exception'], supRows)}` : ''}
${ev.anomalies.length ? `<p><strong>Anomalies</strong></p>${htmlTable(['Code', 'Points', 'Meaning'], ev.anomalies.map((a) => [`<code>${e(a.code)}</code>`, e(a.points), e(a.message)]))}` : ''}
<p class="meta">engine ${e(ev.engineVersion)} · ruleset <code>${e(ev.rulesetVersion)}</code> · config v${e(ev.configVersion)}${ev.latencyMs !== null ? ` · latency ${e(ev.latencyMs)} ms` : ''}</p>
</section>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAF Studio report ${e(meta.generatedAt)}</title>
<style>${HTML_STYLE}</style>
</head>
<body>
<header>
<h1>WAF Studio — decision report</h1>
<p class="meta">Generated ${e(meta.generatedAt)} by ${e(meta.generatedBy)} · ${e(meta.generator)}</p>
<p class="note">Sanitized export: excerpts are redacted and limited to ${EXCERPT_MAX} characters; request samples, secret headers, cookies, client identifiers and session data are not included.</p>
</header>
<main>
<h2>Context</h2>
${htmlTable(['Field', 'Value'], [
    ['Ruleset version', `<code>${e(meta.rulesetVersion)}</code>`],
    ['Configuration version', e(meta.configVersion)],
    ['Mode', e(cfg && cfg.mode)],
    ['Thresholds (flag / block)', cfg && cfg.thresholds ? `${e(cfg.thresholds.flag)} / ${e(cfg.thresholds.block)}` : ''],
    ['Rate limit', cfg && cfg.rateLimit ? `${cfg.rateLimit.enabled ? 'enabled' : 'disabled'} · ${e(cfg.rateLimit.maxRequests)} per ${e(cfg.rateLimit.windowMs)} ms` : ''],
  ])}
<h3>Filters used</h3>
${filterRows.length ? htmlTable(['Filter', 'Value'], filterRows) : '<p class="meta">None (most recent events).</p>'}
<h2>Summary</h2>
${htmlTable(['Metric', 'Value'], [
    ['Events in report', e(summary.totalEvents)],
    ['Verdicts (allow / flag / block)', `${e(summary.byVerdict.allow)} / ${e(summary.byVerdict.flag)} / ${e(summary.byVerdict.block)}`],
    ['Actions (allowed / logged / blocked)', `${e(summary.byAction.allowed)} / ${e(summary.byAction.logged)} / ${e(summary.byAction.blocked)}`],
    ['Flagged or blocked (review for false positives)', e(summary.falsePositiveReview.flaggedOrBlocked)],
    ['Would block but only logged (monitor mode)', e(summary.falsePositiveReview.wouldBlockButLogged)],
    ['Events with matches suppressed by exceptions', e(summary.falsePositiveReview.withSuppressedMatches)],
    ['Allowed with no matches', e(summary.falsePositiveReview.allowedWithoutMatches)],
    ['Score average / max', `${e(summary.score.average)} / ${e(summary.score.max)}`],
    ['Latency p50 / p95 (ms)', `${e(summary.latency.p50Ms ?? '—')} / ${e(summary.latency.p95Ms ?? '—')}`],
  ])}
<h3>By source</h3>
${htmlTable(['Source', 'Events'], kvRows(summary.bySource))}
<h3>By category</h3>
${htmlTable(['Category', 'Events'], kvRows(summary.byCategory))}
<h3>Top rules</h3>
${htmlTable(['Rule', 'Name', 'Category', 'Matches'], summary.topRules.map((r) => [`<code>${e(r.ruleId)}</code>`, e(r.name), e(r.category), e(r.count)]))}
<h2>Events (${e(events.length)})</h2>
${eventSections || '<p class="meta">No events matched the filters.</p>'}
</main>
<footer><p class="meta">WAF Studio — local learning WAF. This report is a sanitized record for review; it is not a substitute for the audit log.</p></footer>
</body>
</html>
`;
}

function timestampForFilename(iso) {
  const d = new Date(iso);
  const safe = Number.isNaN(d.getTime()) ? new Date() : d;
  return safe.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Builds a sanitized report.
 * @returns {{ filename: string, contentType: string, body: string, count: number }}
 */
function buildReport(input, format) {
  const fmt = String(format || '').toLowerCase();
  if (!FORMATS.includes(fmt)) throw new TypeError(`Unsupported report format: ${format}`);
  const opts = input || {};
  const events = (Array.isArray(opts.events) ? opts.events : []).map(sanitizeEvent);
  const generatedAt = safeText(opts.generatedAt, 40) || new Date().toISOString();
  const meta = {
    generator: 'WAF Studio report export v1',
    generatedAt,
    generatedBy: generatorText(opts.generatedBy),
    filters: sanitizeFilters(opts.filters),
    rulesetVersion: safeText(opts.rulesetVersion, 80),
    configVersion: num(opts.configVersion),
    config: sanitizeConfig(opts.config),
  };
  const summary = summarize(events);
  const filename = `waf-studio-report-${timestampForFilename(generatedAt)}.${fmt}`;
  let body;
  if (fmt === 'json') {
    const stats = opts.stats && typeof opts.stats === 'object' ? {
      totals: opts.stats.totals || null,
      latency: opts.stats.latency || null,
      mode: safeText(opts.stats.mode, 10),
    } : null;
    body = `${JSON.stringify({ report: meta, summary, stats, events }, null, 2)}\n`;
  } else if (fmt === 'csv') {
    body = toCsv(meta, events);
  } else {
    body = toHtml(meta, summary, events);
  }
  return { filename, contentType: CONTENT_TYPES[fmt], body, count: events.length };
}

module.exports = {
  buildReport,
  FORMATS,
  CONTENT_TYPES,
  // exported for unit tests
  sanitizeEvent,
  sanitizeConfig,
  safeExcerpt,
  redactPath,
  escapeHtml,
  csvCell,
  summarize,
};
