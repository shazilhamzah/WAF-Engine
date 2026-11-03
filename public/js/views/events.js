import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { can } from '../lib/roles.js';
import { hashFor } from '../lib/query.js';
import { formatTs, truncate, formatMs, dateInputToIso } from '../lib/format.js';
import { pageHeader, card, field, select, table, pagination, verdictBadge, actionBadge, loading, errorPanel, showStatus } from '../ui.js';

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
  const selected = [];

  const verdict = select([{ value: '', label: 'Any' }, 'allow', 'flag', 'block'], q.verdict || '');
  const action = select([{ value: '', label: 'Any' }, 'allowed', 'logged', 'blocked'], q.action || '');
  const source = select([{ value: '', label: 'Any' }, 'proxy', 'console', 'import', 'replay'], q.source || '');
  const ruleId = h('input', { type: 'text', inputmode: 'numeric', pattern: '[0-9]*', maxlength: 6, value: q.ruleId || '' });
  const text = h('input', { type: 'search', maxlength: 200, value: q.q || '', placeholder: 'path or label' });
  const from = h('input', { type: 'date', value: isoToDateInput(q.from) });
  const to = h('input', { type: 'date', value: isoToDateInput(q.to) });
  const compareBtn = h('button', { type: 'button', class: 'btn btn-primary', disabled: true, on: { click: goCompare } }, 'Compare selected (0/2)');

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

  function toggle(id, checkbox) {
    const i = selected.indexOf(id);
    if (checkbox.checked && i < 0) selected.push(id);
    if (!checkbox.checked && i >= 0) selected.splice(i, 1);
    compareBtn.disabled = selected.length !== 2;
    compareBtn.textContent = `Compare selected (${selected.length}/2)`;
    for (const cb of ctx.el.querySelectorAll('input.pick')) {
      cb.disabled = !cb.checked && selected.length >= 2;
    }
  }

  const filters = h('form', { class: 'form', role: 'search', 'aria-label': 'Filter events', on: { submit: apply } },
    h('div', { class: 'form-row' },
      field('Verdict', verdict), field('Action', action), field('Source', source),
      field('Rule id', ruleId), field('Text', text)),
    h('div', { class: 'form-row' },
      field('From', from), field('To', to),
      h('div', { class: 'btn-group' },
        h('button', { type: 'submit', class: 'btn btn-primary' }, 'Apply filters'),
        h('a', { class: 'btn', href: '#/events' }, 'Reset'))));

  const results = h('div', null, loading());
  mount(ctx.el,
    pageHeader('Events', canCompare ? compareBtn : null),
    card('Filters', filters),
    card(null, results));

  let data;
  try {
    data = await api.events({ ...currentFilters(), limit: PAGE, offset });
  } catch (err) {
    if (err && err.status === 401) return;
    mount(results, errorPanel(err, () => ctx.navigate(location.hash)));
    return;
  }
  if (!ctx.isCurrent()) return;

  const columns = [];
  if (canCompare) {
    columns.push({
      key: 'pick', label: 'Select',
      render: (e) => {
        const cb = h('input', { type: 'checkbox', class: 'pick', 'aria-label': `Select event ${e.id} for comparison` });
        cb.addEventListener('change', () => toggle(e.id, cb));
        return cb;
      },
    });
  }
  columns.push(
    { key: 'ts', label: 'Time', render: (e) => formatTs(e.ts) },
    { key: 'source', label: 'Source', render: (e) => (e.label ? h('span', null, e.source, h('br'), h('span', { class: 'muted small' }, truncate(e.label, 40))) : e.source) },
    { key: 'req', label: 'Request', className: 'wrap-anywhere', render: (e) => (canDetail
      ? h('a', { href: `#/events/${encodeURIComponent(e.id)}`, 'aria-label': `Details for ${e.method} ${truncate(e.path, 60)}` }, code(`${e.method} ${truncate(e.path, 80)}`))
      : code(`${e.method} ${truncate(e.path, 80)}`)) },
    { key: 'verdict', label: 'Verdict', render: (e) => verdictBadge(e.verdict) },
    { key: 'action', label: 'Action', render: (e) => actionBadge(e.action) },
    { key: 'score', label: 'Score', className: 'num' },
    { key: 'mode', label: 'Mode' },
    { key: 'rules', label: 'Rules', render: (e) => (Array.isArray(e.matchedRuleIds) && e.matchedRuleIds.length ? e.matchedRuleIds.join(', ') : '—') },
    { key: 'lat', label: 'Latency', className: 'num', render: (e) => formatMs(e.latencyMs) },
  );

  mount(results,
    ctx.role === 'viewer' ? h('p', { class: 'note' }, 'Viewers see sanitized summaries only. Evidence, comparison and replay need the operator role.') : null,
    table({ caption: 'Events', columns, rows: data.items || [], empty: 'No events match these filters.' }),
    pagination({
      total: data.total || 0, limit: PAGE, offset,
      onPage: (o) => ctx.navigate(hashFor('/events', { ...currentFilters(), offset: o || '' })),
    }));
}
