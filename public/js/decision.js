// decision fields are attacker influenced so they are only inserted as text
import { h, s, code } from './dom.js';
import { formatMs, formatBytes, shortHash, scoreScaleMax, formatTs, prettyJson } from './lib/format.js';
import { hashFor } from './lib/query.js';
import { outcomeBadge, severityBadge, chip, table, kvList, card, statusLabel } from './ui.js';

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
    h('p', null, h('strong', null, `Score ${total}`), ` — flag at ${Number.isFinite(flag) ? flag : '—'}, block at ${Number.isFinite(block) ? block : '—'}`),
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
      outcomeBadge({ verdict: d.verdict || event.verdict, action: d.action || event.action }),
      d.statusCode ? chip(`HTTP ${d.statusCode}`, 'bad') : null),
    scoreBar(d.score),
    expl.length ? h('ol', { class: 'explanation' }, ...expl.slice(0, 5).map((t) => h('li', null, String(t)))) : null,
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
    { key: 'severity', label: 'Severity', render: (m) => severityBadge(m.severity) },
    { key: 'points', label: 'Points', className: 'num', render: (m) => (m.points === undefined ? '—' : `+${m.points}`) },
    { key: 'category', label: 'Category' },
    { key: 'location', label: 'Location', render: (m) => code(m.location) },
    { key: 'excerpt', label: 'Matched excerpt', render: (m) => code(m.excerpt, 'code excerpt') },
    { key: 'decodedVia', label: 'Decoded via', render: (m) => (Array.isArray(m.decodedVia) && m.decodedVia.length ? h('span', null, ...m.decodedVia.map((d) => [chip(d, 'info'), ' '])) : 'none') },
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
  const t = d.timings || {};
  const expl = Array.isArray(d.explanation) ? d.explanation : [];
  const anomalies = Array.isArray(d.anomalies) ? d.anomalies : [];
  const suppressed = Array.isArray(d.suppressed) ? d.suppressed : [];

  return [
    card('Decision & score',
      scoreBar(d.score),
      categoryLine(d.score && d.score.byCategory),
      d.recommendation ? h('p', { class: 'recommendation' }, 'Recommendation: ', String(d.recommendation)) : null,
      d.blockReason ? h('p', null, 'Block reason: ', code(d.blockReason)) : null,
      expl.length ? h('details', null, h('summary', null, `Decision steps (${expl.length})`),
        h('ol', { class: 'explanation' }, ...expl.map((x) => h('li', null, String(x))))) : null),
    card('Rule matches',
      matchesTable(event, d.matches || [], { canRequest }),
      suppressed.length ? h('details', null, h('summary', null, `Suppressed by exceptions (${suppressed.length})`),
        matchesTable(event, suppressed, { suppressed: true })) : null,
      anomalies.length ? h('details', { open: true }, h('summary', null, `Parser anomalies (${anomalies.length})`),
        table({
          caption: 'Parser anomalies', className: 'table-compact',
          columns: [
            { key: 'code', label: 'Code', render: (a) => code(a.code) },
            { key: 'points', label: 'Points', className: 'num', render: (a) => (a.points ? `+${a.points}` : '0') },
            { key: 'message', label: 'Meaning', render: (a) => String(a.message || '') },
          ],
          rows: anomalies,
        })) : null,
      (rl && rl.checked) ? h('details', { open: Boolean(rl.limited) }, h('summary', null, 'Rate limit'),
        kvList([
          ['Status', rl.limited ? statusLabel('limited', 'bad') : statusLabel('within limit', 'ok')],
          ['Count in window', `${rl.count} / ${rl.limit}`],
          ['Window', rl.windowMs ? `${Math.round(rl.windowMs / 1000)} s` : '—'],
        ])) : null),
    card('Request & metadata',
      kvList([
        (req.queryNames && req.queryNames.length) ? ['Query parameters', h('span', null, ...req.queryNames.map((n) => [code(n), ' ']))] : null,
        (req.bodyNames && req.bodyNames.length) ? ['Body fields', h('span', null, ...req.bodyNames.map((n) => [code(n), ' ']))] : null,
        req.contentType ? ['Content type', code(req.contentType)] : null,
        ['Body size', `${formatBytes(req.bodyBytes)} (inspected ${formatBytes(req.inspectedBytes)}${req.truncated ? ', truncated' : ''})`],
        req.userAgent ? ['User agent', code(req.userAgent)] : null,
        ['Recorded', formatTs(event.ts)],
        ['Timings', `parse ${formatMs(t.parseMs)} · rules ${formatMs(t.rulesMs)} · total ${formatMs(t.totalMs)}`],
        ['Versions', versionLine(event)],
        event.clientId ? ['Client', code(event.clientId)] : null,
        event.submittedBy ? ['Submitted by', event.submittedBy] : null,
        event.replayOf ? ['Replay of', h('a', { href: `#/events/${encodeURIComponent(event.replayOf)}` }, code(event.replayOf))] : null,
      ]),
      event.sample ? h('details', null, h('summary', null, 'Stored sample (redacted)'), h('pre', null, prettyJson(event.sample))) : null,
      h('details', null, h('summary', null, 'Raw decision JSON'), h('pre', null, prettyJson(d)))),
  ];
}

export function versionLine(event) {
  const eng = (event.decision && event.decision.engine) || {};
  return `engine ${eng.engineVersion || '—'} · ruleset ${shortHash(event.rulesetVersion || eng.rulesetVersion)} · config v${event.configVersion ?? eng.configVersion ?? '—'}`;
}
