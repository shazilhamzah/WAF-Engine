// Reports: choose a format and filters, download via GET /api/reports/export.
import { h, mount, uid } from '../dom.js';
import { api } from '../api.js';
import { parseIdList } from '../lib/query.js';
import { dateInputToIso } from '../lib/format.js';
import { pageHeader, card, field, select, showStatus, fieldErrors, busy } from '../ui.js';

const FORMATS = [
  { value: 'html', label: 'HTML — readable, self-contained report' },
  { value: 'csv', label: 'CSV — one row per event (spreadsheet-safe)' },
  { value: 'json', label: 'JSON — machine-readable, includes explanations' },
];

export function render(ctx) {
  const group = uid('fmt');
  const radios = FORMATS.map((f, i) => {
    const id = `${group}-${f.value}`;
    const input = h('input', { type: 'radio', name: group, id, value: f.value, checked: i === 0 });
    return h('label', { for: id }, input, f.label);
  });
  const from = h('input', { type: 'date' });
  const to = h('input', { type: 'date' });
  const verdict = select([{ value: '', label: 'Any' }, 'allow', 'flag', 'block'], '');
  const ids = h('textarea', { rows: 2, maxlength: 20000, spellcheck: 'false', placeholder: 'evt_… , evt_… (optional)' });
  const errors = h('div');
  const btn = h('button', { type: 'submit', class: 'btn btn-primary' }, '⇩ Download report');

  async function onSubmit(e) {
    e.preventDefault();
    const fmt = (ctx.el.querySelector(`input[name="${group}"]:checked`) || {}).value || 'html';
    const list = parseIdList(ids.value);
    const problems = [];
    if (list.length > 500) problems.push({ field: 'Event ids', message: 'at most 500 ids per report' });
    if (list.some((x) => !/^[A-Za-z0-9_-]{1,100}$/.test(x))) problems.push({ field: 'Event ids', message: 'ids may only contain letters, digits, _ and -' });
    const f = dateInputToIso(from.value);
    const t = dateInputToIso(to.value, true);
    if (f && t && f > t) problems.push({ field: 'Dates', message: '“From” must be before “To”' });
    mount(errors, fieldErrors(problems));
    if (problems.length) return;
    await busy(btn, async () => {
      const res = await api.exportReport({ format: fmt, from: f, to: t, verdict: verdict.value, ids: list });
      showStatus(`Downloaded ${res.name}. The export was recorded in the audit log.`, 'success');
    });
  }

  mount(ctx.el,
    pageHeader('Export a report'),
    card(null,
      h('form', { class: 'form', novalidate: true, on: { submit: onSubmit } },
        h('fieldset', null, h('legend', null, 'Format'), h('div', { class: 'radio-row' }, ...radios)),
        h('div', { class: 'form-row' }, field('From', from), field('To', to), field('Verdict', verdict)),
        field('Event ids (optional)', ids, 'Comma or space separated. Leave empty to export by date/verdict (most recent events first).'),
        errors,
        h('div', null, btn))),
    h('p', { class: 'note' },
      'ⓘ Reports are sanitized: they contain redacted ≤120-character excerpts only, never secret headers, cookies, passwords or session data. ',
      'HTML reports are escaped and script-free; CSV cells are protected against spreadsheet formula injection. Every export is recorded in the audit log.'));
}
