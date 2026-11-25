import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { hashFor, buildQuery, pageInfo } from '../lib/query.js';
import { swr } from '../cache.js';
import { formatTs, formatNumber, truncate, prettyJson, dateInputToIso } from '../lib/format.js';
import { pageHeader, card, field, select, table, pagination, statusBadge, skeletonTable, errorPanel, busy, message, staleWarning } from '../ui.js';

const PAGE = 50;
const KEYS = ['action', 'actor', 'outcome', 'from', 'to'];

const COLUMNS = [
  { key: 'seq', label: 'Seq', className: 'num', rowHeader: true },
  { key: 'ts', label: 'Time', render: (a) => formatTs(a.ts) },
  { key: 'actor', label: 'Actor', render: (a) => `${a.actorName || '—'}${a.actorRole ? ` (${a.actorRole})` : ''}` },
  { key: 'action', label: 'Action', render: (a) => code(a.action) },
  { key: 'target', label: 'Target', render: (a) => (a.targetType ? `${a.targetType} ${truncate(a.targetId || '', 24)}` : '—') },
  { key: 'outcome', label: 'Outcome', render: (a) => statusBadge(a.outcome) },
  { key: 'client', label: 'Client', render: (a) => (a.clientId ? code(a.clientId) : '—') },
  { key: 'details', label: 'Details', render: (a) => (a.details && Object.keys(a.details).length
    ? h('details', null, h('summary', null, truncate(JSON.stringify(a.details), 40)), h('pre', null, prettyJson(a.details)))
    : '—') },
  { key: 'hash', label: 'Hash', render: (a) => code(truncate(a.hash || '', 12)) },
];

export async function render(ctx) {
  const q = ctx.query;
  const offset = Math.max(0, parseInt(q.offset, 10) || 0);
  const action = h('input', { type: 'text', maxlength: 64, value: q.action || '', placeholder: 'e.g. config.update', spellcheck: 'false', dataset: { shortcut: 'search' }, 'aria-keyshortcuts': '/' });
  const actor = h('input', { type: 'text', maxlength: 64, value: q.actor || '', placeholder: 'username' });
  const outcome = select([{ value: '', label: 'Any' }, 'success', 'failure', 'denied'], q.outcome || '');
  const from = h('input', { type: 'date' });
  const to = h('input', { type: 'date' });
  const verifyOut = h('div', { 'aria-live': 'polite' });
  const verifyBtn = h('button', { type: 'button', class: 'btn btn-primary', on: { click: () => busy(verifyBtn, verify) } }, 'Verify chain');
  const results = h('div', null, skeletonTable(COLUMNS, 8, { caption: 'Audit records' }));

  function filters() {
    const f = {};
    for (const k of KEYS) if (q[k]) f[k] = q[k];
    return f;
  }

  async function verify() {
    const res = await api.verifyAudit();
    mount(verifyOut, res.ok
      ? message('success', 'Hash chain verified')
      : message('error', `Chain broken at seq ${res.brokenAt} (${formatNumber(res.checked)} checked). A record was altered or removed outside the application — investigate and restore from backup.`));
  }

  const form = h('form', { class: 'form', role: 'search', 'aria-label': 'Filter audit log', on: { submit: (e) => {
    e.preventDefault();
    ctx.navigate(hashFor('/audit', {
      action: action.value.trim(), actor: actor.value.trim(), outcome: outcome.value,
      from: dateInputToIso(from.value) || q.from, to: dateInputToIso(to.value, true) || q.to,
    }));
  } } },
  h('div', { class: 'form-row' },
    field(['Action ', h('kbd', { class: 'kbd', 'aria-hidden': 'true', title: 'Press / to jump here' }, '/')], action), field('Actor', actor), field('Outcome', outcome), field('From', from), field('To', to),
    h('div', { class: 'btn-group' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Filter'), h('a', { class: 'btn', href: '#/audit' }, 'Reset'))));

  const paint = (res) => paintAudit(results, res, ctx, filters, offset);
  mount(ctx.el,
    pageHeader('Audit log', verifyBtn),
    verifyOut,
    card(null, form),
    card(null, results));

  const query = { ...filters(), limit: PAGE, offset };
  const load = () => swr(`audit${buildQuery(query)}`, () => api.audit(query), paint, { isCurrent: ctx.isCurrent, onStaleError: staleWarning });
  try {
    await load();
  } catch (err) {
    if (err && err.status === 401) return;
    mount(results, errorPanel(err));
    return;
  }
  ctx.onRevalidate(load);
}

function paintAudit(results, res, ctx, filters, offset) {
  mount(results,
    table({
      caption: 'Audit records',
      columns: COLUMNS,
      rows: res.items || [],
      empty: pageInfo(res.total, PAGE, offset).beyond ? 'This page is past the end of the results.' : 'No audit records match these filters.',
    }),
    pagination({ total: res.total || 0, limit: PAGE, offset, onPage: (o) => ctx.navigate(hashFor('/audit', { ...filters(), offset: o || '' })) }));
}
