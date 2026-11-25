// Audit console (admin): filters, append-only log table, hash-chain verification.
import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { hashFor } from '../lib/query.js';
import { formatTs, formatNumber, truncate, prettyJson, dateInputToIso } from '../lib/format.js';
import { pageHeader, card, field, select, table, pagination, statusBadge, loading, errorPanel, busy } from '../ui.js';

const PAGE = 50;
const KEYS = ['action', 'actor', 'outcome', 'from', 'to'];

export async function render(ctx) {
  const q = ctx.query;
  const offset = Math.max(0, parseInt(q.offset, 10) || 0);
  const action = h('input', { type: 'text', maxlength: 64, value: q.action || '', placeholder: 'e.g. config.update', spellcheck: 'false' });
  const actor = h('input', { type: 'text', maxlength: 64, value: q.actor || '', placeholder: 'username' });
  const outcome = select([{ value: '', label: 'Any' }, 'success', 'failure', 'denied'], q.outcome || '');
  const from = h('input', { type: 'date' });
  const to = h('input', { type: 'date' });
  const verifyOut = h('div', { 'aria-live': 'polite' });
  const verifyBtn = h('button', { type: 'button', class: 'btn btn-primary', on: { click: () => busy(verifyBtn, verify) } }, 'Verify chain');
  const results = h('div', null, loading());

  function filters() {
    const f = {};
    for (const k of KEYS) if (q[k]) f[k] = q[k];
    return f;
  }

  async function verify() {
    const res = await api.verifyAudit();
    mount(verifyOut, res.ok
      ? h('p', { class: 'status-msg status-success' }, `✔ Chain intact — ${formatNumber(res.checked)} records checked; every hash links to the previous one.`)
      : h('p', { class: 'status-msg status-error' }, `⛔ Chain broken at seq ${res.brokenAt} (${formatNumber(res.checked)} checked). A record was altered or removed outside the application — investigate and restore from backup.`));
  }

  const form = h('form', { class: 'form', role: 'search', 'aria-label': 'Filter audit log', on: { submit: (e) => {
    e.preventDefault();
    ctx.navigate(hashFor('/audit', {
      action: action.value.trim(), actor: actor.value.trim(), outcome: outcome.value,
      from: dateInputToIso(from.value) || q.from, to: dateInputToIso(to.value, true) || q.to,
    }));
  } } },
  h('div', { class: 'form-row' }, field('Action', action), field('Actor', actor), field('Outcome', outcome), field('From', from), field('To', to)),
  h('div', { class: 'btn-group' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Apply filters'), h('a', { class: 'btn', href: '#/audit' }, 'Reset')));

  mount(ctx.el,
    pageHeader('Audit log', verifyBtn),
    verifyOut,
    h('p', { class: 'muted small' }, 'Append-only: the database refuses updates and deletes, and each record stores the SHA-256 of the previous one. Client addresses are pseudonymous (c_…).'),
    card('Filters', form),
    card(null, results));

  let res;
  try {
    res = await api.audit({ ...filters(), limit: PAGE, offset });
  } catch (err) {
    if (err && err.status === 401) return;
    mount(results, errorPanel(err));
    return;
  }
  if (!ctx.isCurrent()) return;
  mount(results,
    table({
      caption: 'Audit records',
      columns: [
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
      ],
      rows: res.items || [],
      empty: 'No audit records match these filters.',
    }),
    pagination({ total: res.total || 0, limit: PAGE, offset, onPage: (o) => ctx.navigate(hashFor('/audit', { ...filters(), offset: o || '' })) }));
}
