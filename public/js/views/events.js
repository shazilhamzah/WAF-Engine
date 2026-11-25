import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { can } from '../lib/roles.js';
import { pageInfo, hashFor, buildQuery } from '../lib/query.js';
import { swr } from '../cache.js';
import { formatTs, truncate, formatMs, dateInputToIso } from '../lib/format.js';
import { icon } from '../icons.js';
import { pageHeader, card, field, select, table, pagination, outcomeBadge, skeletonTable, errorPanel, showStatus, busy, markSharedRequest, staleWarning } from '../ui.js';

const PAGE = 50;
const FILTER_KEYS = ['verdict', 'action', 'source', 'ruleId', 'q', 'from', 'to'];

function isoToDateInput(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export async function render(ctx) {
  const q = ctx.query;
  const offset = Math.max(0, parseInt(q.offset, 10) || 0);
  const canDetail = can(ctx.role, 'events.detail');
  const canCompare = can(ctx.role, 'events.compare');
  const canExport = can(ctx.role, 'reports.export');
  const selected = [];

  const verdict = select([{ value: '', label: 'Any' }, 'allow', 'flag', 'block'], q.verdict || '');
  const action = select([{ value: '', label: 'Any' }, 'allowed', 'logged', 'blocked'], q.action || '');
  const source = select([{ value: '', label: 'Any' }, 'proxy', 'console', 'import', 'replay'], q.source || '');
  const ruleId = h('input', { type: 'text', inputmode: 'numeric', pattern: '[0-9]*', maxlength: 6, value: q.ruleId || '' });
  const text = h('input', { type: 'search', maxlength: 200, value: q.q || '', placeholder: 'path or label', dataset: { shortcut: 'search' }, 'aria-keyshortcuts': '/' });
  const from = h('input', { type: 'date', value: isoToDateInput(q.from) });
  const to = h('input', { type: 'date', value: isoToDateInput(q.to) });
  const compareBtn = h('button', { type: 'button', class: 'btn btn-primary', disabled: true, on: { click: goCompare } }, 'Compare (0/2)');
  const fmt = select(['html', 'csv', 'json'], 'html', { 'aria-label': 'Export format' });
  const exportBtn = h('button', { type: 'button', class: 'btn', on: { click: doExport } }, icon('download'), 'Export');

  function currentFilters() {
    const f = {};
    for (const k of FILTER_KEYS) if (q[k]) f[k] = q[k];
    return f;
  }

  function apply(e) {
    e.preventDefault();
    if (ruleId.value && !/^\d{4,6}$/.test(ruleId.value.trim())) {
      ruleId.setAttribute('aria-invalid', 'true');
      showStatus('Rule id must be a number between 1000 and 999999.', 'error');
      ruleId.focus();
      return;
    }
    ctx.navigate(hashFor('/events', {
      verdict: verdict.value, action: action.value, source: source.value,
      ruleId: ruleId.value.trim(), q: text.value.trim(),
      from: dateInputToIso(from.value), to: dateInputToIso(to.value, true),
    }));
  }

  function goCompare() {
    if (selected.length === 2) ctx.navigate(hashFor('/compare', { a: selected[0], b: selected[1] }));
  }

  async function doExport() {
    await busy(exportBtn, async () => {
      const params = selected.length
        ? { format: fmt.value, ids: selected }
        : { format: fmt.value, from: q.from || dateInputToIso(from.value), to: q.to || dateInputToIso(to.value, true), verdict: q.verdict || verdict.value };
      const r = await api.exportReport(params);
      showStatus(`Downloaded ${r.name}.`, 'success');
    });
  }

  function toggle(id, checkbox) {
    const i = selected.indexOf(id);
    if (checkbox.checked && i < 0) selected.push(id);
    if (!checkbox.checked && i >= 0) selected.splice(i, 1);
    compareBtn.disabled = selected.length !== 2;
    compareBtn.textContent = `Compare (${selected.length}/2)`;
    for (const cb of ctx.el.querySelectorAll('input.pick')) {
      cb.disabled = !cb.checked && selected.length >= 2;
    }
  }

  const filters = h('form', { class: 'form', role: 'search', 'aria-label': 'Filter events', on: { submit: apply } },
    h('div', { class: 'form-row' },
      field(['Search ', h('kbd', { class: 'kbd', 'aria-hidden': 'true', title: 'Press / to jump here' }, '/')], text), field('Verdict', verdict), field('Source', source),
      field('From', from), field('To', to),
      h('div', { class: 'btn-group' },
        h('button', { type: 'submit', class: 'btn btn-primary' }, 'Filter'),
        h('a', { class: 'btn', href: '#/events' }, 'Reset'))),
    h('details', { class: 'filter-more', open: Boolean(q.action || q.ruleId) },
      h('summary', null, 'More filters'),
      h('div', { class: 'form-row' }, field('Action', action), field('Rule id', ruleId))));

  const headerActions = [];
  if (canExport) headerActions.push(h('span', { class: 'btn-group' }, fmt, exportBtn));
  if (canCompare) headerActions.push(compareBtn);

  const columns = [];
  if (canCompare) {
    columns.push({
      key: 'pick', label: '',
      render: (e) => {
        const picked = selected.includes(e.id);
        const cb = h('input', { type: 'checkbox', class: 'pick', checked: picked, disabled: !picked && selected.length >= 2, 'aria-label': `Select event ${e.id} for comparison` });
        cb.addEventListener('change', () => toggle(e.id, cb));
        // the label is the tap target so the small checkbox still gets a full-size hit area
        return h('label', { class: 'pick-hit' }, cb);
      },
    });
  }
  columns.push(
    { key: 'ts', label: 'Time', render: (e) => formatTs(e.ts) },
    { key: 'source', label: 'Source', render: (e) => (e.label ? h('span', null, e.source, h('br'), h('span', { class: 'muted small' }, truncate(e.label, 40))) : e.source) },
    { key: 'req', label: 'Request', className: 'wrap-anywhere', render: (e) => (canDetail
      ? h('a', { href: `#/events/${encodeURIComponent(e.id)}`, 'aria-label': `Details for ${e.method} ${truncate(e.path, 60)}`, on: { click: markSharedRequest } }, code(`${e.method} ${truncate(e.path, 80)}`))
      : code(`${e.method} ${truncate(e.path, 80)}`)) },
    { key: 'outcome', label: 'Outcome', render: outcomeBadge },
    { key: 'score', label: 'Score', className: 'num' },
    { key: 'rules', label: 'Rules', render: (e) => (Array.isArray(e.matchedRuleIds) && e.matchedRuleIds.length ? e.matchedRuleIds.join(', ') : '—') },
    { key: 'lat', label: 'Latency', className: 'num', render: (e) => formatMs(e.latencyMs) },
  );

  const results = h('div', null, skeletonTable(columns, 8, { caption: 'Events' }));
  mount(ctx.el,
    pageHeader('Events', ...headerActions),
    card(null, filters),
    card(null, results));

  const paint = (data) => mount(results,
    table({ caption: 'Events', columns, rows: data.items || [],
      empty: pageInfo(data.total, PAGE, offset).beyond ? 'This page is past the end of the results.' : 'No events match these filters.' }),
    pagination({
      total: data.total || 0, limit: PAGE, offset,
      onPage: (o) => ctx.navigate(hashFor('/events', { ...currentFilters(), offset: o || '' })),
    }));
  const query = { ...currentFilters(), limit: PAGE, offset };
  const load = () => swr(`events${buildQuery(query)}`, () => api.events(query), paint,
    { isCurrent: ctx.isCurrent, onStaleError: staleWarning });

  try {
    await load();
  } catch (err) {
    if (err && err.status === 401) return;
    mount(results, errorPanel(err, () => ctx.navigate(location.hash)));
    return;
  }
  ctx.onRevalidate(load);
}
