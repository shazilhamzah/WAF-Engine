import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { hashFor } from '../lib/query.js';
import { formatTs } from '../lib/format.js';
import { compareEventRows, summarizeDiff, displayValue } from '../lib/diff.js';
import { pageHeader, card, field, table, verdictBadge, actionBadge, loading, errorPanel, emptyState, showStatus } from '../ui.js';
import { scoreBar } from '../decision.js';

function cell(row, side) {
  const v = row[side];
  if (row.field === 'verdict') return verdictBadge(v);
  if (row.field === 'action') return actionBadge(v);
  if (row.field === 'ts') return formatTs(v);
  if (row.field === 'id' || row.field === 'replayOf') return v ? h('a', { href: `#/events/${encodeURIComponent(v)}` }, code(v)) : '—';
  if (row.field === 'request' || row.field === 'rulesetVersion') return code(displayValue(v));
  return displayValue(v);
}

export async function render(ctx) {
  const a = h('input', { type: 'text', value: ctx.query.a || '', maxlength: 100, spellcheck: 'false', placeholder: 'evt_…' });
  const b = h('input', { type: 'text', value: ctx.query.b || '', maxlength: 100, spellcheck: 'false', placeholder: 'evt_…' });
  const out = h('div');
  const form = h('form', { class: 'form', on: { submit: (e) => {
    e.preventDefault();
    if (!a.value.trim() || !b.value.trim()) { showStatus('Enter two event ids.', 'error'); return; }
    ctx.navigate(hashFor('/compare', { a: a.value.trim(), b: b.value.trim() }));
  } } },
  h('div', { class: 'form-row' }, field('Event A', a), field('Event B', b),
    h('div', null, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Compare'))));

  mount(ctx.el, pageHeader('Compare events'),
    card(null, form, h('p', { class: 'muted small' }, 'Tip: tick two events in ', h('a', { href: '#/events' }, 'Events'), ' and press “Compare selected”.')),
    out);

  if (!ctx.query.a || !ctx.query.b) {
    mount(out, emptyState('Choose two events to compare.'));
    return;
  }
  mount(out, loading('Comparing…'));
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
  const changes = rows.filter((r) => r.changed).length;
  const summary = summarizeDiff(res.diff, res.a, res.b);

  mount(out,
    card('Summary of differences',
      h('p', null, h('strong', null, `${changes} field${changes === 1 ? '' : 's'} differ.`)),
      h('ul', { class: 'diff-summary' }, ...summary.map((t) => h('li', null, t)))),
    card('Side by side', table({
      caption: 'Event A versus event B',
      columns: [
        { key: 'label', label: 'Field', rowHeader: true, render: (r) => (r.changed ? h('span', null, r.label, ' ', h('span', { class: 'changed-mark' }, '≠ changed')) : r.label) },
        { key: 'a', label: 'A', className: 'wrap-anywhere', render: (r) => cell(r, 'a') },
        { key: 'b', label: 'B', className: 'wrap-anywhere', render: (r) => cell(r, 'b') },
      ],
      rows,
      rowClass: (r) => (r.changed ? 'row-changed' : null),
    })),
    h('div', { class: 'grid-2' },
      card('Score A', scoreBar(res.a.decision && res.a.decision.score)),
      card('Score B', scoreBar(res.b.decision && res.b.decision.score))),
    h('div', { class: 'grid-2' },
      card('Explanation A', explanation(res.a)),
      card('Explanation B', explanation(res.b))));
}

function explanation(evt) {
  const list = (evt.decision && evt.decision.explanation) || [];
  return list.length ? h('ol', { class: 'explanation' }, ...list.map((t) => h('li', null, String(t)))) : emptyState('No rule matched.');
}
