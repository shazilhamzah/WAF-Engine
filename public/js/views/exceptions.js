import { h, mount, code } from '../dom.js';
import { api, actionKey } from '../api.js';
import { can } from '../lib/roles.js';
import { hashFor } from '../lib/query.js';
import { formatTs, truncate, dateInputToIso } from '../lib/format.js';
import { METHODS } from '../lib/samples.js';
import { swr } from '../cache.js';
import { pageHeader, card, field, select, table, statusBadge, outcomeBadge, skeletonTable, errorPanel, showStatus, confirmDialog, fieldErrors, busy, staleWarning } from '../ui.js';

const STATUSES = ['pending', 'approved', 'rejected', 'revoked'];

export function scopeOf(x) {
  const sc = (x && x.scope) || {};
  return {
    pathPrefix: sc.pathPrefix ?? (x && x.pathPrefix) ?? null,
    location: sc.location ?? (x && x.location) ?? null,
    method: sc.method ?? (x && x.method) ?? null,
  };
}

export function isOwnRequest(exc, user) {
  if (!exc || !user) return false;
  if (exc.requestedById !== undefined && exc.requestedById !== null) return exc.requestedById === user.id;
  const by = exc.requestedBy;
  const byId = by && typeof by === 'object' ? by.id : by;
  const byName = (by && typeof by === 'object' ? by.username : null) || exc.requestedByName || null;
  return (byId !== null && byId !== undefined && (byId === user.id || byId === user.username)) || (byName !== null && byName === user.username);
}

function who(v, name) {
  if (name) return name;
  if (v && typeof v === 'object') return v.username || v.id || '—';
  return v || '—';
}

export function scopeText(sc) {
  const parts = [];
  parts.push(sc.pathPrefix ? `path starts with ${sc.pathPrefix}` : 'any path');
  parts.push(sc.location ? `at ${sc.location}` : 'any location');
  parts.push(sc.method ? `method ${sc.method}` : 'any method');
  return parts.join(' · ');
}

export async function render(ctx) {
  const q = ctx.query;
  const status = STATUSES.includes(q.status) ? q.status : 'pending';
  const canReview = can(ctx.role, 'exceptions.review');

  const ruleId = h('input', { type: 'text', inputmode: 'numeric', maxlength: 6, value: q.ruleId || '', required: true });
  const pathPrefix = h('input', { type: 'text', maxlength: 512, value: q.pathPrefix || '', spellcheck: 'false', placeholder: '/search' });
  const location = h('input', { type: 'text', maxlength: 200, value: q.location || '', spellcheck: 'false', placeholder: 'query.q' });
  const method = select([{ value: '', label: 'Any method' }, ...METHODS], METHODS.includes(q.method) ? q.method : '');
  const reason = h('textarea', { rows: 3, maxlength: 500, required: true, placeholder: 'Why is this match a false positive?' });
  const expires = h('input', { type: 'date' });
  const formErrors = h('div');
  const previewBox = h('div', { 'aria-live': 'polite' });
  const sourceEvent = q.event || null;

  function readForm() {
    const problems = [];
    const id = ruleId.value.trim();
    if (!/^\d{4,6}$/.test(id) || Number(id) < 1000) problems.push({ field: 'Rule id', message: 'must be a number between 1000 and 999999' });
    const pp = pathPrefix.value.trim();
    if (pp && !pp.startsWith('/')) problems.push({ field: 'Path prefix', message: "must start with '/'" });
    if (!pp && !location.value.trim()) problems.push({ field: 'Scope', message: 'set at least a path prefix or a location — a rule-wide exception is too broad' });
    const scope = { pathPrefix: pp || null, location: location.value.trim() || null, method: method.value || null };
    ruleId.setAttribute('aria-invalid', String(problems.some((p) => p.field === 'Rule id')));
    return { ruleId: Number(id), scope, problems };
  }

  const previewBtn = h('button', { type: 'button', class: 'btn', on: { click: () => busy(previewBtn, preview) } }, 'Preview impact');
  const submitBtn = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Submit request');

  async function preview() {
    const { ruleId: rid, scope, problems } = readForm();
    mount(formErrors, fieldErrors(problems));
    if (problems.length) return;
    const res = await api.previewException(rid, scope);
    const sample = res.sample || [];
    mount(previewBox,
      h('p', { class: 'note' }, `This exception would have suppressed rule ${rid} in ${res.affectedEvents} recent event${res.affectedEvents === 1 ? '' : 's'} (${scopeText(scope)}).`),
      sample.length ? table({
        caption: 'Recent events affected', className: 'table-compact',
        columns: [
          { key: 'ts', label: 'Time', render: (e) => formatTs(e.ts) },
          { key: 'req', label: 'Request', render: (e) => h('a', { href: `#/events/${encodeURIComponent(e.id)}` }, code(`${e.method} ${truncate(e.path, 60)}`)) },
          { key: 'outcome', label: 'Outcome', render: outcomeBadge },
          { key: 'score', label: 'Score', className: 'num' },
        ],
        rows: sample,
      }) : null);
  }

  async function submitRequest(e) {
    e.preventDefault();
    const { ruleId: rid, scope, problems } = readForm();
    if (!reason.value.trim()) problems.push({ field: 'Reason', message: 'required' });
    const exp = dateInputToIso(expires.value, true);
    if (exp && Date.parse(exp) < Date.now()) problems.push({ field: 'Expires', message: 'must be in the future' });
    mount(formErrors, fieldErrors(problems));
    if (problems.length) return;
    const body = { ruleId: rid, scope, reason: reason.value.trim() };
    if (sourceEvent) body.sourceEventId = sourceEvent;
    if (exp) body.expiresAt = exp;
    submitBtn.disabled = true;
    try {
      const res = await api.requestException(body, requestKey);
      requestKey.reset();
      ctx.flash(`Exception ${res.exception && res.exception.id} requested. An administrator other than you must approve it.`, 'success');
      ctx.navigate(hashFor('/exceptions', { status: 'pending' }));
    } catch (err) {
      if (err && err.code === 'VALIDATION_FAILED') mount(formErrors, fieldErrors(err.details));
      if (err && err.status !== 401) showStatus(err.friendly, 'error');
    } finally {
      submitBtn.disabled = false;
    }
  }

  const requestKey = actionKey();
  const requestForm = h('form', { class: 'form', novalidate: true, on: { submit: submitRequest } },
    sourceEvent ? h('p', { class: 'muted small' }, 'Pre-filled from event ', h('a', { href: `#/events/${encodeURIComponent(sourceEvent)}` }, code(sourceEvent)), '.') : null,
    h('div', { class: 'form-row' },
      field('Rule id', ruleId),
      field('Path prefix', pathPrefix, 'Only requests whose path starts with this.'),
      field('Location', location, 'e.g. query.q, body.comment, header.user-agent'),
      field('Method', method)),
    field('Reason (required)', reason),
    h('div', { class: 'form-row' }, field('Expires (optional)', expires, 'Exceptions should be temporary where possible.')),
    formErrors,
    h('div', { class: 'btn-group' }, previewBtn, submitBtn),
    previewBox);

  const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Exception status' },
    ...STATUSES.map((st) => h('a', {
      class: 'tab', role: 'tab', href: hashFor('/exceptions', { status: st }),
      'aria-selected': String(st === status), id: `tab-${st}`,
    }, st[0].toUpperCase() + st.slice(1))));
  const listBox = h('div', { role: 'tabpanel', 'aria-labelledby': `tab-${status}` });

  async function review(exc, kind, btn) {
    const titles = { approve: 'Approve exception', reject: 'Reject exception', revoke: 'Revoke exception' };
    const sc = scopeOf(exc);
    const { confirmed, values } = await confirmDialog({
      title: `${titles[kind]} ${exc.id}?`,
      body: h('div', null,
        h('p', null, `Rule ${exc.ruleId} — ${scopeText(sc)}`),
        h('p', null, 'Requested reason: ', String(exc.reason || '—')),
        kind === 'approve' ? h('p', { class: 'warn-note' }, 'Once approved, matching requests will no longer score for this rule in the proxy and console.') : null,
        kind === 'revoke' ? h('p', null, 'The rule will apply again to matching requests immediately.') : null),
      confirmLabel: titles[kind].split(' ')[0],
      danger: kind !== 'approve',
      fields: [{ name: 'note', label: 'Review note', type: 'textarea', required: false, maxlength: 500 }],
    });
    if (!confirmed) return;
    await busy(btn, async () => {
      if (kind === 'approve') await api.approveException(exc.id, values.note);
      else if (kind === 'reject') await api.rejectException(exc.id, values.note);
      else await api.revokeException(exc.id, values.note);
      showStatus(`Exception ${exc.id} ${kind === 'approve' ? 'approved' : kind === 'reject' ? 'rejected' : 'revoked'}.`, 'success');
      await loadList({ skipCache: true });
    });
  }

  function actionsFor(exc) {
    if (!canReview) return '—';
    const own = isOwnRequest(exc, ctx.user);
    const out = [];
    if (exc.status === 'pending') {
      const ap = h('button', { type: 'button', class: 'btn btn-small btn-primary', disabled: own, 'aria-describedby': own ? `own-note-${exc.id}` : null }, 'Approve');
      ap.addEventListener('click', () => review(exc, 'approve', ap));
      const rj = h('button', { type: 'button', class: 'btn btn-small', disabled: own, 'aria-describedby': own ? `own-note-${exc.id}` : null }, 'Reject');
      rj.addEventListener('click', () => review(exc, 'reject', rj));
      out.push(ap, rj);
      if (own) out.push(h('span', { id: `own-note-${exc.id}`, class: 'small muted' }, 'Your request — another administrator must review it.'));
    } else if (exc.status === 'approved') {
      const rv = h('button', { type: 'button', class: 'btn btn-small btn-danger' }, 'Revoke');
      rv.addEventListener('click', () => review(exc, 'revoke', rv));
      out.push(rv);
    }
    return out.length ? h('div', { class: 'btn-group' }, ...out) : '—';
  }

  function paintList(res) {
    const items = (res.items || []).filter((x) => !x.status || x.status === status);
    mount(listBox, table({ caption: `${status} exceptions`, columns, rows: items, empty: `No ${status} exceptions.` }));
  }

  async function loadList({ skipCache = false } = {}) {
    try {
      await swr(`exceptions:${status}`, () => api.exceptions(status), paintList, { isCurrent: ctx.isCurrent, onStaleError: staleWarning, skipCache });
    } catch (err) {
      if (err && err.status === 401) return;
      mount(listBox, errorPanel(err, () => loadList()));
    }
  }

  const columns = [
    { key: 'id', label: 'Id', render: (x) => code(x.id), rowHeader: true },
    { key: 'ruleId', label: 'Rule', render: (x) => code(x.ruleId) },
    { key: 'scope', label: 'Scope', render: (x) => scopeText(scopeOf(x)) },
    { key: 'reason', label: 'Reason', className: 'wrap-anywhere', render: (x) => truncate(x.reason, 120) },
    { key: 'status', label: 'Status', render: (x) => statusBadge(x.status) },
    { key: 'requestedBy', label: 'Requested', render: (x) => h('span', null, who(x.requestedBy, x.requestedByName), h('br'), h('span', { class: 'small muted' }, formatTs(x.createdAt))) },
    { key: 'reviewedBy', label: 'Reviewed', render: (x) => (x.reviewedBy ? h('span', null, who(x.reviewedBy, x.reviewedByName), h('br'), h('span', { class: 'small muted' }, formatTs(x.reviewedAt)), x.reviewNote ? h('span', { class: 'small' }, h('br'), `“${truncate(x.reviewNote, 80)}”`) : null) : '—') },
    { key: 'expiresAt', label: 'Expires', render: (x) => (x.expiresAt ? formatTs(x.expiresAt) : 'never') },
    { key: 'src', label: 'Source event', render: (x) => (x.sourceEventId ? h('a', { href: `#/events/${encodeURIComponent(x.sourceEventId)}` }, code(truncate(x.sourceEventId, 16))) : '—') },
    { key: 'act', label: 'Actions', render: actionsFor },
  ];
  mount(listBox, skeletonTable(columns, 4, { caption: `${status} exceptions` }));

  const requestDisclosure = h('details', { class: 'card', open: Boolean(q.new) },
    h('summary', null, q.new ? 'Request an exception (pre-filled from event)' : 'Request an exception'),
    requestForm);
  const newBtn = h('button', {
    type: 'button', class: 'btn',
    on: { click: () => { requestDisclosure.open = true; (ruleId.value ? reason : ruleId).focus(); } },
  }, '+ Request exception');

  mount(ctx.el,
    pageHeader('Exceptions', newBtn),
    requestDisclosure,
    card(null, tabs, listBox));
  if (q.new) reason.focus();
  else if (q.request) { requestDisclosure.open = true; ruleId.focus(); }
  await loadList();
  ctx.onRevalidate(loadList);
}

