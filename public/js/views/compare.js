import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { hashFor } from '../lib/query.js';
import { formatTs } from '../lib/format.js';
import { compareEventRows, displayValue } from '../lib/diff.js';
import { pageHeader, card, field, table, verdictBadge, actionBadge, skeleton, skeletonLine, placeholderTable, errorPanel, emptyState, showStatus } from '../ui.js';

function cell(row, side) {
  const v = row[side];
  if (row.field === 'verdict') return verdictBadge(v);
  if (row.field === 'action') return actionBadge(v);
  if (row.field === 'ts') return formatTs(v);
  if (row.field === 'id' || row.field === 'replayOf') return v ? h('a', { href: `#/events/${encodeURIComponent(v)}` }, code(v)) : '—';
  if (row.field === 'request' || row.field === 'rulesetVersion') return code(displayValue(v));
  return displayValue(v);
}

const COLUMNS = [
  { key: 'label', label: 'Field', rowHeader: true, render: (r) => (r.changed ? h('span', null, r.label, ' ', h('span', { class: 'changed-mark' }, '≠')) : r.label) },
  { key: 'a', label: 'Event A', className: 'wrap-anywhere', render: (r) => cell(r, 'a') },
  { key: 'b', label: 'Event B', className: 'wrap-anywhere', render: (r) => cell(r, 'b') },
];

export async function render(ctx) {
  const hasBoth = Boolean(ctx.query.a && ctx.query.b);
  const a = h('input', { type: 'text', value: ctx.query.a || '', maxlength: 100, spellcheck: 'false', placeholder: 'evt_…' });
  const b = h('input', { type: 'text', value: ctx.query.b || '', maxlength: 100, spellcheck: 'false', placeholder: 'evt_…' });
  const out = h('div');
  const form = h('form', { class: 'form', on: { submit: (e) => {
    e.preventDefault();
    if (!a.value.trim() || !b.value.trim()) { showStatus('Enter two event ids.', 'error'); return; }
    ctx.navigate(hashFor('/compare', { a: a.value.trim(), b: b.value.trim() }));
  } } },
  h('div', { class: 'form-row' }, field('Event A', a), field('Event B', b),
    h('div', { class: 'btn-group' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Compare'))));

  const picker = hasBoth
    ? h('details', { class: 'card' }, h('summary', null, `Change events (${ctx.query.a} vs ${ctx.query.b})`), form)
    : card(null, form);

  mount(ctx.el, pageHeader('Compare events', h('a', { class: 'btn', href: '#/events' }, 'Back to events')), picker, out);

  if (!hasBoth) {
    mount(out, emptyState('Select two events from the Events list or enter their IDs above.'));
    return;
  }
  mount(out, skeleton(card(null, h('h2', { class: 'card-title' }, skeletonLine('short')), placeholderTable(COLUMNS, 6, { caption: 'Differences between Event A and Event B' }))));
  let res;
  try {
    res = await api.compare(ctx.query.a, ctx.query.b);
  } catch (err) {
    if (err && err.status === 401) return;
    mount(out, errorPanel(err));
    return;
  }
  if (!ctx.isCurrent()) return;
  const rows = compareEventRows(res.a, res.b);
  const primary = rows.filter((r) => r.changed || r.field === 'id' || r.field === 'request');
  const unchanged = rows.filter((r) => !r.changed && r.field !== 'id' && r.field !== 'request');
  const changes = rows.filter((r) => r.changed).length;

  mount(out,
    card(`${changes} difference${changes === 1 ? '' : 's'}`,
      table({
        caption: 'Differences between Event A and Event B',
        columns: COLUMNS,
        rows: primary,
        rowClass: (r) => (r.changed ? 'row-changed' : null),
      }),
      unchanged.length ? h('details', null,
        h('summary', null, `Unchanged fields (${unchanged.length})`),
        table({ caption: 'Unchanged fields', columns: COLUMNS, rows: unchanged, className: 'table-compact' })) : null));
}
