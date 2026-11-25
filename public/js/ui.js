import { h, s, mount, clear, uid, code } from './dom.js';
import { verdictInfo, actionInfo, severityInfo, statusInfo, modeInfo, formatNumber } from './lib/format.js';
import { eventOutcome } from './lib/dashboard.js';
import { rolesForRoute } from './lib/roles.js';
import { icon } from './icons.js';

export function badge(text, tone, extraClass) {
  return h('span', { class: ['badge', `tone-${tone}`, extraClass] },
    h('span', { class: 'dot', 'aria-hidden': 'true' }), text);
}
const badgeFrom = (info, extraClass) => badge(info.text, info.tone, extraClass);
export const verdictBadge = (v) => badgeFrom(verdictInfo(v));
export const actionBadge = (a) => badgeFrom(actionInfo(a));
export const severityBadge = (sv) => badgeFrom(severityInfo(sv));
export const statusBadge = (st) => badgeFrom(statusInfo(st));
export const modeBadge = (m) => badgeFrom(modeInfo(m), 'badge-mode');
export const outcomeBadge = (event) => badgeFrom(eventOutcome(event || {}));
export function chip(text, tone = 'muted') {
  return h('span', { class: ['chip', `tone-${tone}`] }, text);
}
export function statusLabel(text, tone = 'muted') {
  return h('span', { class: ['status-label', `tone-${tone}`] }, h('span', { class: 'dot', 'aria-hidden': 'true' }), text);
}

const MESSAGE_ICONS = { error: 'alert', warn: 'alert', success: 'check', info: 'info' };
export function message(kind, ...children) {
  return h('p', { class: ['status-msg', `status-${kind}`] }, icon(MESSAGE_ICONS[kind] || 'info'), h('span', null, ...children));
}

let statusTimer = null;
export function showStatus(text, kind = 'info') {
  const region = document.getElementById('status');
  if (!region) return;
  clearTimeout(statusTimer);
  const prefix = kind === 'error' ? 'Error: ' : '';
  const msg = message(kind, prefix, text);
  msg.appendChild(h('button', { type: 'button', class: 'link-btn status-close', 'aria-label': 'Dismiss message', on: { click: () => clearStatus() } }, icon('x')));
  mount(region, msg);
  if (kind !== 'error') statusTimer = setTimeout(clearStatus, 8000);
}
export function clearStatus() {
  const region = document.getElementById('status');
  if (region) clear(region);
}
// reversible actions happen at once and offer Undo for a few seconds instead of asking first.
// the timer pauses while the toast is hovered or focused so nobody loses the chance to undo
export const UNDO_MS = 8000;
let activeToast = null;

function toastHost() {
  let host = document.getElementById('toast-host');
  if (!host) {
    host = h('div', { id: 'toast-host', class: 'toast-host' });
    document.body.appendChild(host);
  }
  return host;
}

export function undoToast(text, { onUndo, onExpire, duration = UNDO_MS, shortcut = null } = {}) {
  if (activeToast) activeToast.dismiss();
  let timer = null;
  let left = duration;
  let startedAt = 0;
  let done = false;
  const undoBtn = h('button', { type: 'button', class: 'btn btn-small toast-undo', 'aria-keyshortcuts': shortcut ? shortcut.aria : null },
    'Undo', shortcut ? h('kbd', { class: 'kbd', 'aria-hidden': 'true' }, shortcut.label) : null);
  const closeBtn = h('button', { type: 'button', class: 'link-btn toast-close', 'aria-label': 'Dismiss' }, icon('x'));
  const el = h('div', { class: 'toast', role: 'status', 'aria-live': 'polite' }, h('span', { class: 'toast-text' }, text), undoBtn, closeBtn);

  function start() {
    if (timer || done) return;
    startedAt = Date.now();
    timer = setTimeout(() => finish(false), left);
  }
  function pause() { if (timer) { clearTimeout(timer); timer = null; left -= Date.now() - startedAt; } }
  function finish(undone) {
    if (done) return;
    done = true;
    clearTimeout(timer);
    if (activeToast === api) activeToast = null;
    el.classList.add('toast-leaving');
    // the exit is a transition so it can never trap input; removal does not wait on it if transitions are off
    el.addEventListener('transitionend', () => el.remove(), { once: true });
    setTimeout(() => el.remove(), 400);
    if (undone && onUndo) onUndo();
    if (!undone && onExpire) onExpire();
  }
  const api = { undo: () => finish(true), dismiss: () => finish(false), get open() { return !done; } };
  undoBtn.addEventListener('click', api.undo);
  closeBtn.addEventListener('click', api.dismiss);
  el.addEventListener('pointerenter', pause);
  el.addEventListener('pointerleave', () => { if (!done && !el.contains(document.activeElement)) start(); });
  el.addEventListener('focusin', pause);
  el.addEventListener('focusout', (e) => { if (!done && !el.contains(e.relatedTarget)) start(); });
  toastHost().appendChild(el);
  activeToast = api;
  start();
  return api;
}

export function currentToast() { return activeToast; }

// a background refresh failed while cached data is on screen
export function staleWarning(err) {
  if (err && err.status === 401) return;
  showStatus(`Could not refresh, showing the last loaded data. ${(err && err.friendly) || ''}`.trim(), 'warn');
}

export function showError(err) {
  showStatus((err && err.friendly) || (err && err.message) || 'Unexpected error.', 'error');
}

export function pageHeader(title, ...actions) {
  return h('div', { class: 'page-head' },
    h('h1', { id: 'page-title', tabindex: '-1' }, title),
    actions.length ? h('div', { class: 'page-actions' }, ...actions) : null);
}

export function card(title, ...children) {
  return h('section', { class: 'card', 'aria-label': typeof title === 'string' ? title : null },
    title ? h('h2', { class: 'card-title' }, title) : null, ...children);
}

export function loading(text = 'Loading…') {
  return h('p', { class: 'loading', role: 'status' }, h('span', { class: 'spinner', 'aria-hidden': 'true' }), ' ', text);
}

// skeletons stay invisible for the first 300 ms so fast loads never flash grey blocks,
// but they hold the final layout's space from the start so nothing jumps when data lands
export const SKELETON_DELAY_MS = 300;

export function skeletonLine(size) {
  return h('span', { class: ['skeleton-line', size ? `skeleton-${size}` : null], 'aria-hidden': 'true' });
}

export function skeleton(...children) {
  const el = h('div', { class: 'skeleton', 'aria-busy': 'true', 'data-pending': '' },
    h('span', { class: 'sr-only', role: 'status' }, 'Loading…'), ...children);
  setTimeout(() => el.removeAttribute('data-pending'), SKELETON_DELAY_MS);
  return el;
}

// the same table component as the loaded state, with placeholder cells
export function placeholderTable(columns, rows = 5, extra = {}) {
  return table({
    ...extra,
    columns: columns.map((c) => ({ ...c, render: () => skeletonLine() })),
    rows: Array.from({ length: rows }, () => ({})),
  });
}

export function skeletonTable(columns, rows = 5, extra = {}) {
  return skeleton(placeholderTable(columns, rows, extra));
}

export function pageSkeleton({ delay = SKELETON_DELAY_MS } = {}) {
  const el = skeleton(
    h('div', { class: 'page-head' }, h('div', { class: 'skeleton-heading' }, skeletonLine('title'))),
    card(null, skeletonLine(), skeletonLine(), skeletonLine('short')));
  if (!delay) el.removeAttribute('data-pending');
  return el;
}

// the clicked request line morphs into the event page header during the view transition
export function markSharedRequest(e) {
  const el = e.currentTarget.querySelector('code');
  if (el) el.classList.add('vt-event-request');
}

export function emptyState(text) {
  return h('p', { class: 'empty' }, text);
}

export function errorPanel(err, retry) {
  return h('div', { class: 'panel panel-error', role: 'alert' },
    message('error', (err && err.friendly) || 'Could not load this page.'),
    retry ? h('button', { type: 'button', class: 'btn', on: { click: retry } }, 'Try again') : null);
}

export function rolePanel(route, role) {
  const roles = rolesForRoute(route);
  return h('div', { class: 'panel panel-role', role: 'region', 'aria-labelledby': 'page-title' },
    icon('lock', 'panel-icon'),
    h('h1', { id: 'page-title', tabindex: '-1' }, 'Not available for your role'),
    h('p', null, `This page needs the ${roles.join(' or ') || 'appropriate'} role. You are signed in as ${role}.`),
    h('p', null, h('a', { href: '#/dashboard', class: 'btn' }, 'Back to dashboard')));
}

export function kvList(pairs, cls) {
  return h('dl', { class: ['kv', cls] }, ...pairs.filter(Boolean).map(([k, v]) => [
    h('dt', null, k), h('dd', null, v === null || v === undefined || v === '' ? '—' : v),
  ]));
}

export function table({ caption, columns, rows, empty = 'No records.', className, rowClass }) {
  if (!rows || rows.length === 0) return emptyState(empty);
  return h('div', { class: 'table-wrap' },
    h('table', { class: ['table', className] },
      caption ? h('caption', { class: 'sr-only-caption' }, caption) : null,
      h('thead', null, h('tr', null, ...columns.map((c) => h('th', { scope: 'col', class: c.className }, c.label)))),
      h('tbody', null, ...rows.map((row) => h('tr', { class: rowClass ? rowClass(row) : null },
        ...columns.map((c, i) => {
          const val = c.render ? c.render(row) : row[c.key];
          const content = val === null || val === undefined || val === '' ? '—' : val;
          return i === 0 && c.rowHeader
            ? h('th', { scope: 'row', class: c.className, 'data-label': c.label }, content)
            : h('td', { class: c.className, 'data-label': c.label }, content);
        }))))));
}

export function pagination({ total, limit, offset, onPage }) {
  const pages = Math.max(1, Math.ceil((total || 0) / limit));
  const page = Math.floor(offset / limit) + 1;
  const from = total ? offset + 1 : 0;
  const to = Math.min(offset + limit, total || 0);
  return h('nav', { class: 'pager', 'aria-label': 'Pagination' },
    h('button', { type: 'button', class: 'btn btn-small', disabled: page <= 1, on: { click: () => onPage(Math.max(0, offset - limit)) } }, icon('chevron-left'), 'Previous'),
    h('span', { class: 'pager-info' }, `${formatNumber(from)}–${formatNumber(to)} of ${formatNumber(total || 0)} · page ${page} / ${pages}`),
    h('button', { type: 'button', class: 'btn btn-small', disabled: page >= pages, on: { click: () => onPage(offset + limit) } }, 'Next', icon('chevron-right')));
}

export function field(label, control, hint) {
  const id = control.id || uid('fld');
  control.id = id;
  let hintEl = null;
  if (hint) {
    hintEl = h('small', { class: 'hint', id: `${id}-hint` }, hint);
    control.setAttribute('aria-describedby', `${id}-hint`);
  }
  return h('div', { class: 'field' }, h('label', { for: id }, label), control, hintEl);
}

export function select(options, value, attrs = {}) {
  return h('select', { ...attrs, value },
    ...options.map((o) => (typeof o === 'string' ? h('option', { value: o }, o) : h('option', { value: o.value }, o.label))));
}

export function fieldErrors(details) {
  if (!details || !details.length) return null;
  return h('ul', { class: 'field-errors', role: 'alert' },
    ...details.map((d) => h('li', null, d.field ? `${d.field}: ` : '', d.message || String(d))));
}

// bars use svg attributes instead of inline styles because of the strict csp
export function hbar(value, max, label) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return h('span', { class: 'hbar' },
    s('svg', { class: 'hbar-svg', viewBox: '0 0 100 8', preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
      s('rect', { class: 'hbar-track', x: 0, y: 0, width: 100, height: 8, rx: 2 }),
      s('rect', { class: 'hbar-fill', x: 0, y: 0, width: pct.toFixed(2), height: 8, rx: 2 })),
    h('span', { class: 'hbar-label' }, label === undefined ? formatNumber(value) : label));
}

export function confirmDialog({ title, body, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false, fields = [] }) {
  return new Promise((resolve) => {
    const previous = document.activeElement;
    const titleId = uid('dlg-title');
    const errorBox = h('p', { class: 'dialog-error', role: 'alert' });
    const inputs = {};
    const fieldEls = fields.map((f) => {
      let control;
      if (f.type === 'textarea') control = h('textarea', { name: f.name, rows: 3, required: f.required, maxlength: f.maxlength || 500 });
      else control = h('input', { type: f.type || 'text', name: f.name, required: f.required, autocomplete: f.autocomplete || 'off', maxlength: f.maxlength || 500 });
      if (f.value) control.value = f.value;
      inputs[f.name] = control;
      return field(f.required ? `${f.label} (required)` : f.label, control, f.hint);
    });
    const confirmBtn = h('button', { type: 'submit', class: ['btn', danger ? 'btn-danger' : 'btn-primary'] }, confirmLabel);
    const cancelBtn = h('button', { type: 'button', class: 'btn', on: { click: () => finish(false) } }, cancelLabel);
    const form = h('form', { method: 'dialog', class: 'dialog-form', novalidate: true },
      h('h2', { id: titleId, class: 'dialog-title' }, title),
      h('div', { class: 'dialog-body' }, body),
      ...fieldEls, errorBox,
      h('div', { class: 'dialog-actions' }, cancelBtn, confirmBtn));
    const dlg = h('dialog', { class: 'dialog', 'aria-labelledby': titleId, 'aria-modal': 'true' }, form);
    let done = false;
    function finish(confirmed) {
      if (done) return;
      const values = {};
      for (const [k, el] of Object.entries(inputs)) values[k] = el.value.trim();
      if (confirmed) {
        const missing = fields.filter((f) => f.required && !values[f.name]);
        if (missing.length) {
          errorBox.textContent = `Please fill in: ${missing.map((m) => m.label).join(', ')}.`;
          inputs[missing[0].name].focus();
          return;
        }
      }
      done = true;
      if (dlg.open) dlg.close();
      dlg.remove();
      if (previous && typeof previous.focus === 'function') previous.focus();
      resolve({ confirmed, values });
    }
    form.addEventListener('submit', (e) => { e.preventDefault(); finish(true); });
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); finish(false); });
    dlg.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); finish(false); return; }
      if (e.key !== 'Tab') return;
      const focusables = [...dlg.querySelectorAll('button, input, textarea, select, a[href]')].filter((el) => !el.disabled);
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    document.body.appendChild(dlg);
    if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
    const firstInput = fieldEls.length ? inputs[fields[0].name] : (danger ? cancelBtn : confirmBtn);
    firstInput.focus();
  });
}

export function diffTable(rows, fmt = (v) => String(v)) {
  return table({
    caption: 'Changes',
    columns: [
      { key: 'path', label: 'Setting', render: (r) => code(r.path) },
      { key: 'from', label: 'Current', render: (r) => fmt(r.from) },
      { key: 'to', label: 'New', render: (r) => h('strong', null, fmt(r.to)) },
    ],
    rows,
    empty: 'No changes.',
    className: 'table-compact',
  });
}

export async function busy(button, fn) {
  const prev = button ? button.disabled : false;
  if (button) { button.disabled = true; button.setAttribute('aria-busy', 'true'); }
  try {
    return await fn();
  } catch (err) {
    showError(err);
    return undefined;
  } finally {
    if (button) { button.disabled = prev; button.removeAttribute('aria-busy'); }
  }
}
