// Shared UI components built on the safe DOM helper.
import { h, s, mount, clear, uid, code } from './dom.js';
import { verdictInfo, actionInfo, severityInfo, statusInfo, modeInfo, formatNumber } from './lib/format.js';
import { rolesForRoute } from './lib/roles.js';

// ---- Badges (icon + text; colour is an extra cue only) ---------------------------------
function badgeFrom(info, extraClass) {
  return h('span', { class: ['badge', `tone-${info.tone}`, extraClass] },
    h('span', { class: 'badge-icon', 'aria-hidden': 'true' }, info.icon), ' ', info.text);
}
export const verdictBadge = (v) => badgeFrom(verdictInfo(v));
export const actionBadge = (a) => badgeFrom(actionInfo(a));
export const severityBadge = (sv) => badgeFrom(severityInfo(sv));
export const statusBadge = (st) => badgeFrom(statusInfo(st));
export const modeBadge = (m) => badgeFrom(modeInfo(m), 'badge-mode');
export function chip(text, tone = 'muted') {
  return h('span', { class: ['chip', `tone-${tone}`] }, text);
}

// ---- Global status region (aria-live) ---------------------------------------------------
let statusTimer = null;
export function showStatus(message, kind = 'info') {
  const region = document.getElementById('status');
  if (!region) return;
  clearTimeout(statusTimer);
  const icon = kind === 'error' ? '⚠' : kind === 'success' ? '✔' : 'ⓘ';
  const prefix = kind === 'error' ? 'Error: ' : '';
  mount(region, h('p', { class: ['status-msg', `status-${kind}`] },
    h('span', { 'aria-hidden': 'true' }, `${icon} `), prefix, message,
    h('button', { type: 'button', class: 'link-btn status-close', 'aria-label': 'Dismiss message', on: { click: () => clearStatus() } }, '✕')));
  if (kind !== 'error') statusTimer = setTimeout(clearStatus, 8000);
}
export function clearStatus() {
  const region = document.getElementById('status');
  if (region) clear(region);
}
/** Shows an ApiError (or any error) in the status region. */
export function showError(err) {
  showStatus((err && err.friendly) || (err && err.message) || 'Unexpected error.', 'error');
}

// ---- Panels -----------------------------------------------------------------------------
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

export function emptyState(text) {
  return h('p', { class: 'empty' }, text);
}

export function errorPanel(err, retry) {
  return h('div', { class: 'panel panel-error', role: 'alert' },
    h('p', null, h('span', { 'aria-hidden': 'true' }, '⚠ '), (err && err.friendly) || 'Could not load this page.'),
    retry ? h('button', { type: 'button', class: 'btn', on: { click: retry } }, 'Try again') : null);
}

/** "Not available for your role" state (server would return a generic 403 anyway). */
export function rolePanel(route, role) {
  const roles = rolesForRoute(route);
  return h('div', { class: 'panel panel-role', role: 'region', 'aria-labelledby': 'page-title' },
    h('h1', { id: 'page-title', tabindex: '-1' }, h('span', { 'aria-hidden': 'true' }, '🔒 '), 'Not available for your role'),
    h('p', null, `This page needs the ${roles.join(' or ') || 'appropriate'} role. You are signed in as ${role}.`),
    h('p', null, h('a', { href: '#/dashboard', class: 'btn' }, 'Back to dashboard')));
}

// ---- Key/value list -----------------------------------------------------------------------
export function kvList(pairs, cls) {
  return h('dl', { class: ['kv', cls] }, ...pairs.filter(Boolean).map(([k, v]) => [
    h('dt', null, k), h('dd', null, v === null || v === undefined || v === '' ? '—' : v),
  ]));
}

// ---- Tables (th scope=col; td data-label for stacked mobile cards) ------------------------
/**
 * table({ caption, columns: [{ key, label, render(row) → Node|string, className }], rows, empty })
 */
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

// ---- Pagination ---------------------------------------------------------------------------
export function pagination({ total, limit, offset, onPage }) {
  const pages = Math.max(1, Math.ceil((total || 0) / limit));
  const page = Math.floor(offset / limit) + 1;
  const from = total ? offset + 1 : 0;
  const to = Math.min(offset + limit, total || 0);
  return h('nav', { class: 'pager', 'aria-label': 'Pagination' },
    h('button', { type: 'button', class: 'btn btn-small', disabled: page <= 1, on: { click: () => onPage(Math.max(0, offset - limit)) } }, '‹ Previous'),
    h('span', { class: 'pager-info' }, `${formatNumber(from)}–${formatNumber(to)} of ${formatNumber(total || 0)} · page ${page} / ${pages}`),
    h('button', { type: 'button', class: 'btn btn-small', disabled: page >= pages, on: { click: () => onPage(offset + limit) } }, 'Next ›'));
}

// ---- Form fields ---------------------------------------------------------------------------
/** Labelled field. `control` is an input/select/textarea element (id assigned automatically). */
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

/** Marks fields with server validation details: [{field, message}] → aria-invalid + message. */
export function fieldErrors(details) {
  if (!details || !details.length) return null;
  return h('ul', { class: 'field-errors', role: 'alert' },
    ...details.map((d) => h('li', null, d.field ? `${d.field}: ` : '', d.message || String(d))));
}

// ---- Bars (SVG; attributes, not inline styles, so the strict CSP is respected) -------------
export function hbar(value, max, label) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return h('span', { class: 'hbar' },
    s('svg', { class: 'hbar-svg', viewBox: '0 0 100 8', preserveAspectRatio: 'none', 'aria-hidden': 'true', focusable: 'false' },
      s('rect', { class: 'hbar-track', x: 0, y: 0, width: 100, height: 8, rx: 2 }),
      s('rect', { class: 'hbar-fill', x: 0, y: 0, width: pct.toFixed(2), height: 8, rx: 2 })),
    h('span', { class: 'hbar-label' }, label === undefined ? formatNumber(value) : label));
}

// ---- Modal dialog (native <dialog>; focus trap, Esc closes, focus returns) ------------------
/**
 * confirmDialog({ title, body, confirmLabel, danger, fields: [{ name, label, type, required, value, hint }] })
 * → Promise<{ confirmed: boolean, values: {} }>
 */
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

/** Small "diff" table used in confirmation dialogs: rows [{ path, from, to }]. */
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

/** Run an async action with a button disabled meanwhile; errors go to the status region. */
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
