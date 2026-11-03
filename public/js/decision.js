// decision fields are attacker influenced so they are only inserted as text
import { h, s, code } from './dom.js';
import { formatMs, formatBytes, shortHash, scoreScaleMax, formatTs, prettyJson } from './lib/format.js';
import { hashFor } from './lib/query.js';
import { verdictBadge, actionBadge, modeBadge, severityBadge, chip, table, kvList, card, emptyState, statusLabel } from './ui.js';

export function scoreBar(score) {
  const sc = score || {};
  const total = Number(sc.total) || 0;
  const flag = Number(sc.flagThreshold);
  const block = Number(sc.blockThreshold);
  const max = scoreScaleMax(sc);
  const W = 400; const barY = 18; const barH = 16;
  const x = (v) => (Math.max(0, Math.min(max, v)) / max) * W;
  const tone = Number.isFinite(block) && total >= block ? 'bad' : Number.isFinite(flag) && total >= flag ? 'warn' : 'ok';
  const parts = [
    s('rect', { class: 'track', x: 0, y: barY, width: W, height: barH, rx: 3 }),
    s('rect', { class: `fill-${tone}`, x: 0, y: barY, width: x(total).toFixed(1), height: barH, rx: 3 }),
  ];
  if (Number.isFinite(flag)) {
    parts.push(s('line', { class: 'marker', x1: x(flag), y1: barY - 4, x2: x(flag), y2: barY + barH + 4 }));
    parts.push(s('text', { x: Math.max(0, x(flag) - 14).toFixed(1), y: barY + barH + 16 }, `flag ${flag}`));
  }
  if (Number.isFinite(block)) {
    parts.push(s('line', { class: 'marker', x1: x(block), y1: barY - 4, x2: x(block), y2: barY + barH + 4 }));
    parts.push(s('text', { x: Math.min(W - 44, x(block) - 4).toFixed(1), y: 12 }, `block ${block}`));
  }
  const label = `Anomaly score ${total}. Flag threshold ${Number.isFinite(flag) ? flag : 'unknown'}, block threshold ${Number.isFinite(block) ? block : 'unknown'}.`;
  return h('div', { class: 'score' },
    h('p', null, h('strong', null, `Score ${total}`), ` — flag at ${Number.isFinite(flag) ? flag : '—'}, block at ${Number.isFinite(block) ? block : '—'}`,
      tone === 'bad' ? ' (at or above block threshold)' : tone === 'warn' ? ' (at or above flag threshold)' : ' (below thresholds)'),
    s('svg', { class: 'scorebar', viewBox: `0 0 ${W} 54`, role: 'img', 'aria-label': label }, ...parts));
}

function categoryLine(byCategory) {
  const entries = Object.entries(byCategory || {});
  if (!entries.length) return null;
  return h('p', null, 'By category: ', ...entries.map(([k, v], i) => [i ? ' · ' : '', chip(`${k} ${v}`, 'info')]));
}

export function decisionSummary(event) {
  const d = (event && event.decision) || {};
  const expl = Array.isArray(d.explanation) ? d.explanation : [];
  return h('div', { class: 'decision-summary' },
    h('div', { class: 'badges' },
      verdictBadge(d.verdict || event.verdict),
      actionBadge(d.action || event.action),
      d.statusCode ? chip(`HTTP ${d.statusCode}`, 'bad') : null,
      modeBadge(d.mode || event.mode),
      d.wouldBlock && d.action !== 'blocked' ? chip('would block in block mode', 'warn') : null),
    scoreBar(d.score),
    expl.length ? h('ol', { class: 'explanation' }, ...expl.slice(0, 5).map((t) => h('li', null, String(t)))) : h('p', { class: 'muted' }, 'No rule matched; no warnings.'),
    d.recommendation ? h('p', { class: 'recommendation' }, 'Recommendation: ', String(d.recommendation)) : null);
}

function exceptionLink(event, m) {
  const req = (event.decision && event.decision.request) || {};
  const path = req.path || String(event.path || '').split('?')[0] || '/';
  return hashFor('/exceptions', {
    new: 1, ruleId: m.ruleId, location: m.location, pathPrefix: path, method: req.method || event.method, event: event.id,
  });
}

function matchesTable(event, list, { canRequest, suppressed }) {
  const columns = [
    { key: 'rule', label: 'Rule', render: (m) => h('span', null, code(m.ruleId), ' ', String(m.ruleName || '')), rowHeader: true },
    { key: 'ruleVersion', label: 'Ver', className: 'num' },
    { key: 'severity', label: 'Severity', render: (m) => severityBadge(m.severity) },
    { key: 'points', label: 'Points', className: 'num', render: (m) => (m.points === undefined ? '—' : `+${m.points}`) },
    { key: 'category', label: 'Category' },
    { key: 'location', label: 'Location', render: (m) => code(m.location) },
    { key: 'operator', label: 'Operator' },
    { key: 'excerpt', label: 'Matched excerpt', render: (m) => code(m.excerpt, 'code excerpt') },
    { key: 'decodedVia', label: 'Decoded via', render: (m) => (Array.isArray(m.decodedVia) && m.decodedVia.length ? h('span', null, ...m.decodedVia.map((d) => [chip(d, 'info'), ' '])) : 'none') },
    { key: 'tags', label: 'Tags', render: (m) => (Array.isArray(m.tags) && m.tags.length ? m.tags.join(', ') : '—') },
  ];
  if (suppressed) columns.push({ key: 'suppressedBy', label: 'Suppressed by', render: (m) => code(m.suppressedBy) });
  else if (canRequest) {
    columns.push({ key: 'act', label: 'Tuning', render: (m) => h('a', { class: 'btn btn-small', href: exceptionLink(event, m) }, 'Request exception') });
  }
  return table({ caption: suppressed ? 'Suppressed matches' : 'Rule matches', columns, rows: list, empty: suppressed ? 'No matches were suppressed.' : 'No rule matched this request.' });
}

export function evidenceSections(event, { canRequest }) {
  const d = event.decision || {};
  const req = d.request || {};
  const rl = d.rateLimit || null;
  const eng = d.engine || {};
  const t = d.timings || {};
  const contributions = (d.score && d.score.contributions) || [];
  const expl = Array.isArray(d.explanation) ? d.explanation : [];

  return [
    card('Score',
      scoreBar(d.score),
      categoryLine(d.score && d.score.byCategory),
      contributions.length ? h('details', null, h('summary', null, 'Score contributions'),
        table({
          caption: 'Score contributions', className: 'table-compact',
          columns: [
            { key: 'source', label: 'Source' },
            { key: 'id', label: 'Id', render: (c) => code(c.id) },
            { key: 'points', label: 'Points', className: 'num', render: (c) => `+${c.points}` },
            { key: 'reason', label: 'Reason', render: (c) => String(c.reason || '') },
          ],
          rows: contributions,
        })) : null),
    card('Why this decision',
      expl.length ? h('ol', { class: 'explanation' }, ...expl.map((x) => h('li', null, String(x)))) : h('p', { class: 'muted' }, 'No rule matched and no anomalies were found.'),
      d.recommendation ? h('p', { class: 'recommendation' }, 'Recommendation: ', String(d.recommendation)) : null,
      d.blockReason ? h('p', null, 'Block reason: ', code(d.blockReason)) : null),
    card('Rule matches', matchesTable(event, d.matches || [], { canRequest })),
    (d.suppressed && d.suppressed.length) ? card('Suppressed by approved exceptions',
      h('p', { class: 'muted small' }, 'These matches were found but did not count towards the score because an approved exception covers them.'),
      matchesTable(event, d.suppressed, { suppressed: true })) : null,
    card('Parser anomalies', (d.anomalies && d.anomalies.length) ? table({
      caption: 'Parser anomalies', className: 'table-compact',
      columns: [
        { key: 'code', label: 'Code', render: (a) => code(a.code) },
        { key: 'points', label: 'Points', className: 'num', render: (a) => (a.points ? `+${a.points}` : '0') },
        { key: 'message', label: 'Meaning', render: (a) => String(a.message || '') },
      ],
      rows: d.anomalies,
    }) : emptyState('No parser anomalies.')),
    card('Rate limit', rl && rl.checked ? kvList([
      ['Status', rl.limited ? statusLabel('limited', 'bad') : statusLabel('within limit', 'ok')],
      ['Count in window', `${rl.count} / ${rl.limit}`],
      ['Window', rl.windowMs ? `${Math.round(rl.windowMs / 1000)} s` : '—'],
    ]) : emptyState('Rate limiting was not checked for this event (console analysis is not rate-limited by the WAF stage).')),
    card('Request summary (sanitized)', kvList([
      ['Method', code(req.method || event.method)],
      ['Path', code(req.path || event.path)],
      ['Query parameter names', (req.queryNames && req.queryNames.length) ? h('span', null, ...req.queryNames.map((n) => [code(n), ' '])) : '—'],
      ['Body field names', (req.bodyNames && req.bodyNames.length) ? h('span', null, ...req.bodyNames.map((n) => [code(n), ' '])) : '—'],
      ['Content type', req.contentType ? code(req.contentType) : '—'],
      ['Body size', `${formatBytes(req.bodyBytes)} (inspected ${formatBytes(req.inspectedBytes)}${req.truncated ? ', truncated' : ''})`],
      ['User agent', req.userAgent ? code(req.userAgent) : '—'],
    ])),
    card('Reproducibility', kvList([
      ['Engine version', code(eng.engineVersion)],
      ['Ruleset version', code(event.rulesetVersion || eng.rulesetVersion)],
      ['Config version', code(event.configVersion ?? eng.configVersion)],
      ['Timings', `parse ${formatMs(t.parseMs)} · rules ${formatMs(t.rulesMs)} · total ${formatMs(t.totalMs)}`],
      ['Recorded', formatTs(event.ts)],
      ['Source', event.source],
      ['Submitted by', event.submittedBy || '—'],
      ['Client (pseudonym)', event.clientId ? code(event.clientId) : '—'],
      ['Replay of', event.replayOf ? h('a', { href: `#/events/${encodeURIComponent(event.replayOf)}` }, code(event.replayOf)) : '—'],
    ])),
    event.sample ? card('Stored sample (redacted)',
      h('p', { class: 'muted small' }, 'Secrets such as authorization and cookie headers or password fields are masked before storage.'),
      h('pre', null, prettyJson(event.sample))) : null,
    h('details', { class: 'card' }, h('summary', null, 'Raw decision JSON'), h('pre', null, prettyJson(d))),
  ];
}

export function versionLine(event) {
  const eng = (event.decision && event.decision.engine) || {};
  return `engine ${eng.engineVersion || '—'} · ruleset ${shortHash(event.rulesetVersion || eng.rulesetVersion)} · config v${event.configVersion ?? eng.configVersion ?? '—'}`;
}
