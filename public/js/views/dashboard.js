// Overview: clear outcomes first; evidence and policy details remain one step away.
import { h, s, mount, code } from '../dom.js';
import { api } from '../api.js';
import { can } from '../lib/roles.js';
import { hashFor } from '../lib/query.js';
import { summarizeOutcomes, eventOutcome, CATEGORY_NAMES, SOURCE_NAMES } from '../lib/dashboard.js';
import { formatNumber, formatMs, hourLabel, formatTs, truncate } from '../lib/format.js';
import { pageHeader, card, table, hbar, loading, errorPanel, emptyState, select, busy } from '../ui.js';

const WINDOWS = [
  { value: '1', label: 'Last hour' }, { value: '6', label: 'Last 6 hours' },
  { value: '24', label: 'Last 24 hours' }, { value: '72', label: 'Last 3 days' },
  { value: '168', label: 'Last 7 days' },
];

function metric(label, value, description, kind = '') {
  return h('div', { class: ['overview-metric', kind] },
    h('span', { class: 'metric-label' }, label),
    h('span', { class: 'metric-value' }, formatNumber(value)),
    h('span', { class: 'metric-description' }, description));
}

function outcomeBadge(event) {
  const info = eventOutcome(event);
  return h('span', { class: ['badge', `tone-${info.tone}`] },
    h('span', { 'aria-hidden': 'true' }, info.icon), ' ', info.text);
}

function bucketLabel(hour, hours) {
  const date = new Date(hour);
  if (Number.isNaN(date.getTime())) return '—';
  return hours > 24
    ? `${date.getDate()} ${date.toLocaleString('en', { month: 'short' })} ${hourLabel(hour)}h`
    : `${hourLabel(hour)}:00`;
}

/** Stacked actions are mutually exclusive; flagged is an overlapping verdict, not a fourth bar. */
function timeline(buckets, hours) {
  const total = buckets.reduce((n, b) => n + (b.allowed || 0) + (b.logged || 0) + (b.blocked || 0), 0);
  if (!total) return h('div', { class: 'chart-empty' },
    h('p', null, 'No inspections in this window'),
    h('p', { class: 'muted small' }, 'Choose a longer time range or inspect a request to see activity.'));
  const compact = window.matchMedia('(max-width: 720px)').matches;
  const W = compact ? 360 : 720; const H = 195; const left = 34; const bottom = 28;
  const max = Math.max(1, ...buckets.map((b) => (b.allowed || 0) + (b.logged || 0) + (b.blocked || 0)));
  const bw = (W - left - 8) / buckets.length;
  const scaleY = (v) => (v / max) * (H - bottom - 12);
  const bars = [];
  const every = Math.max(1, Math.ceil(buckets.length / (compact ? 2 : 6)));
  for (const value of [...new Set([0, Math.round(max / 2), max])]) {
    const y = H - bottom - scaleY(value);
    bars.push(s('line', { class: 'axis', x1: left, y1: y, x2: W, y2: y }));
    bars.push(s('text', { x: left - 8, y: y + 4, 'text-anchor': 'end' }, formatNumber(value)));
  }
  buckets.forEach((b, i) => {
    const x = left + i * bw + 2;
    let y = H - bottom;
    for (const [key, label] of [['allowed', 'Passed'], ['logged', 'Monitor only'], ['blocked', 'Blocked']]) {
      const value = Number(b[key]) || 0;
      if (!value) continue;
      const height = scaleY(value);
      y -= height;
      bars.push(s('rect', { class: `bar-${key}`, x: x.toFixed(1), y: y.toFixed(1), width: Math.max(1, bw - 4).toFixed(1), height: height.toFixed(1), rx: 2 },
        s('title', null, `${formatTs(b.hour)} · ${label}: ${value}`)));
    }
    if (i % every === 0 || i === buckets.length - 1) {
      const last = i === buckets.length - 1;
      bars.push(s('text', { x: last ? W - 8 : i === 0 ? left + 2 : x + bw / 2 - 2, y: H - 7,
        'text-anchor': last ? 'end' : i === 0 ? 'start' : 'middle' }, bucketLabel(b.hour, hours)));
    }
  });
  return h('div', null,
    h('div', { class: 'timeline-wrap' }, s('svg', {
      class: 'timeline overview-timeline', viewBox: `0 0 ${W} ${H}`, role: 'img',
      'aria-label': `${total} inspections by hour. The expandable data table gives exact counts and local times.`,
    }, ...bars)),
    h('div', { class: 'legend-row', 'aria-hidden': 'true' },
      h('span', null, h('span', { class: 'swatch swatch-allowed' }), 'Passed'),
      h('span', null, h('span', { class: 'swatch swatch-logged' }), 'Monitor only'),
      h('span', null, h('span', { class: 'swatch swatch-blocked' }), 'Blocked')),
    h('details', { class: 'chart-data' }, h('summary', null, 'View exact counts'), table({
      caption: 'Hourly inspection outcomes, local time', className: 'table-compact',
      columns: [
        { key: 'hour', label: 'Local time', render: (b) => formatTs(b.hour) },
        { key: 'allowed', label: 'Passed', className: 'num' },
        { key: 'logged', label: 'Monitor only', className: 'num' },
        { key: 'blocked', label: 'Blocked', className: 'num' },
      ], rows: buckets.map((b) => ({ ...b, allowed: b.allowed || 0, logged: b.logged || 0, blocked: b.blocked || 0 })),
    })));
}

export async function render(ctx) {
  let hours = '24'; let loadSeq = 0; let rulesExpanded = false; let systemExpanded = false;
  const body = h('div', null, loading());
  const windowSel = select(WINDOWS, hours, { id: 'overview-window', on: { change: () => { hours = windowSel.value; load(); } } });
  const refreshBtn = h('button', { type: 'button', class: 'btn', on: { click: () => busy(refreshBtn, load) } }, '↻ Refresh');
  const filter = h('label', { class: 'overview-window', for: 'overview-window' }, h('span', null, 'Time range'), windowSel);
  mount(ctx.el,
    pageHeader('Overview', filter, refreshBtn),
    h('p', { class: 'overview-intro' }, 'All inspections · Proxy traffic, manual analyses, imports and replays.'),
    body);

  async function load() {
    const seq = ++loadSeq;
    const selectedHours = Number(hours);
    const from = new Date(Date.now() - selectedHours * 3600000).toISOString();
    body.setAttribute('aria-busy', 'true');
    let stats; let recent;
    try {
      [stats, recent] = await Promise.all([api.stats(selectedHours), api.events({ limit: 5, offset: 0, from })]);
    } catch (err) {
      if (seq !== loadSeq || !ctx.isCurrent() || (err && err.status === 401)) return;
      mount(body, errorPanel(err, load));
      body.setAttribute('aria-busy', 'false');
      return;
    }
    if (seq !== loadSeq || !ctx.isCurrent()) return;
    // Keep the single global protection indicator in sync with this snapshot.
    ctx.refreshMode(stats.mode);
    const totals = summarizeOutcomes(stats.totals);
    const lat = stats.latency || {};
    const categories = Object.entries(stats.byCategory || {}).sort((a, b) => b[1] - a[1]);
    const catMax = Math.max(1, ...categories.map(([, n]) => n));
    const top = stats.topRules || [];
    const topMax = Math.max(1, ...top.map((r) => r.count || 0));
    const canDetail = can(ctx.role, 'events.detail');
    const eventsUrl = hashFor('/events', { from });
    const needsReview = totals.flagged || totals.blocked || totals.monitored;
    const reviewUrl = hashFor('/events', { from, ...(totals.flagged ? { verdict: 'flag' } : { action: totals.blocked ? 'blocked' : 'logged' }) });
    const recommend = totals.total === 0 ? 'Start with a sample to see how inspection works.'
      : needsReview ? 'Review recent detections and confirm they match your traffic.'
        : 'No flagged or blocked inspections in this time range.';
    const rulesDetails = h('details', { class: 'overview-disclosure', open: rulesExpanded, on: { toggle: (e) => { rulesExpanded = e.currentTarget.open; } } },
      h('summary', null, 'Matched rules'),
      table({ caption: 'Most frequently matched rules', className: 'table-compact', empty: 'No rule matches in this window.',
        columns: [
          { key: 'ruleId', label: 'Rule', render: (r) => code(r.ruleId) },
          { key: 'name', label: 'Name', render: (r) => truncate(r.name, 48) },
          { key: 'count', label: 'Matches', render: (r) => hbar(r.count || 0, topMax) },
        ], rows: top,
      }));
    const details = h('details', { class: 'overview-system', open: systemExpanded, on: { toggle: (e) => { systemExpanded = e.currentTarget.open; } } },
      h('summary', null, 'System details'),
      h('dl', { class: 'kv' },
        h('dt', null, 'Ruleset'), h('dd', null, code(stats.rulesetVersion || '—')),
        h('dt', null, 'Configuration'), h('dd', null, `Version ${stats.configVersion ?? '—'}`),
        h('dt', null, 'Inspection latency'), h('dd', null, `Average ${formatMs(lat.avgMs)} · Median ${formatMs(lat.p50Ms)} · p95 ${formatMs(lat.p95Ms)}`)),
      h('p', { class: 'muted small' }, 'Counts include every inspection source. Flagged is a detection verdict and can overlap passed outcomes; monitor-only decisions are included in passed.'));

    const activity = card('Inspection activity',
      h('p', { class: 'card-description' }, 'Recorded outcomes by hour · Local time'),
      timeline(stats.timeline || [], selectedHours));
    const detections = card('Detected patterns',
      h('p', { class: 'card-description' }, 'Inspections matching each category. One inspection can match several.'),
      categories.length ? h('ul', { class: 'category-list' }, ...categories.map(([category, count]) => h('li', null,
        h('span', { class: 'category-name' }, CATEGORY_NAMES[category] || category), hbar(count, catMax))))
        : emptyState('No detection patterns in this window.'),
      rulesDetails);
    const recentCard = h('section', { class: 'card overview-events', 'aria-labelledby': 'recent-title' },
      h('div', { class: 'section-heading' },
        h('div', null, h('h2', { id: 'recent-title', class: 'card-title' }, 'Recent inspections'),
          h('p', { class: 'card-description' }, 'Latest five in the selected time range')),
        h('a', { href: eventsUrl }, 'View all events →')),
      table({ caption: 'Recent inspections in the selected time range', empty: 'No inspections in this time range.',
        columns: [
          { key: 'ts', label: 'Time', render: (e) => formatTs(e.ts) },
          { key: 'request', label: 'Request', render: (e) => h('div', { class: 'request-preview' },
            canDetail ? h('a', { href: `#/events/${encodeURIComponent(e.id)}` }, code(`${e.method} ${truncate(e.path, 60)}`))
              : code(`${e.method} ${truncate(e.path, 60)}`),
            h('span', { class: 'muted small' }, SOURCE_NAMES[e.source] || e.source)),
          },
          { key: 'outcome', label: 'Outcome', render: outcomeBadge },
          { key: 'score', label: 'Score', className: 'num' },
        ], rows: recent.items || [],
      }));

    mount(body,
      h('div', { class: 'overview-metrics' },
        metric('Total inspections', totals.total, 'All sources'),
        metric('Blocked', totals.blocked, 'Block decisions', totals.blocked ? 'has-blocks' : ''),
        metric('Passed', totals.passed, `${formatNumber(totals.flagged)} flagged · ${formatNumber(totals.monitored)} monitor-only`)),
      h('div', { class: 'overview-guidance' },
        h('p', null, h('span', { class: 'guidance-label' }, 'Recommended action'), recommend),
        needsReview ? h('a', { href: reviewUrl }, 'Review events →') : can(ctx.role, 'samples.submit')
          ? h('a', { href: '#/analyze' }, 'Analyze a request →') : null),
      h('div', { class: 'overview-charts' }, activity, detections),
      recentCard,
      h('div', { class: 'overview-bottom' }, details,
        h('span', { class: 'muted small', role: 'status' }, `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`)));
    body.setAttribute('aria-busy', 'false');
  }
  const breakpoint = window.matchMedia('(max-width: 720px)');
  const resize = () => load();
  await load();
  if (!ctx.isCurrent()) return;
  breakpoint.addEventListener('change', resize);
  return () => breakpoint.removeEventListener('change', resize);
}
