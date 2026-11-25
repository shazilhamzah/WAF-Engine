import { h, mount, clear } from '../dom.js';
import { api, actionKey } from '../api.js';
import { EXAMPLES, METHODS, LIMITS, exampleByKey, validateSample, rowsToHeaders, headersToRows, normalizeSample } from '../lib/samples.js';
import { pageHeader, card, field, select, fieldErrors, showStatus, undoToast } from '../ui.js';
import { shortcut } from '../keys.js';

const UNDO_KEY = shortcut('mod+z');
import { decisionSummary } from '../decision.js';
import { icon } from '../icons.js';

export function render(ctx) {
  const label = h('input', { type: 'text', maxlength: LIMITS.labelMax, placeholder: 'Optional label for history' });
  const method = select(METHODS, 'GET');
  const path = h('input', { type: 'text', required: true, maxlength: LIMITS.pathMax, value: '/search?q=hello', spellcheck: 'false', autocomplete: 'off' });
  const body = h('textarea', { rows: 5, spellcheck: 'false', placeholder: 'Request body (optional)' });
  const headerList = h('div', { class: 'header-list' });
  const errors = h('div');
  const resultSlot = h('div', { 'aria-live': 'polite' });
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Analyze');
  let toast = null;
  // one Idempotency-Key per submit intent; a retry of the same sample reuses it, an edited one gets a new key
  const submitKey = actionKey();

  const exampleOptions = [
    { value: '', label: 'Load example…' },
    ...EXAMPLES.map((ex) => ({ value: ex.key, label: `${ex.kind === 'attack' ? '⚠ ' : '✓ '}${ex.label}` })),
  ];
  const exampleSelect = select(exampleOptions, '', {
    'aria-label': 'Load example sample',
    on: {
      change: () => {
        const ex = EXAMPLES.find((x) => x.key === exampleSelect.value);
        if (ex) loadExample(ex.key, ex.label);
      },
    },
  });

  function headerRow(name = '', value = '') {
    const n = h('input', { type: 'text', value: name, maxlength: 100, spellcheck: 'false', autocomplete: 'off', class: 'hdr-name', placeholder: 'Header-Name' });
    const v = h('input', { type: 'text', value, maxlength: LIMITS.headerValueMax, spellcheck: 'false', autocomplete: 'off', class: 'hdr-value', placeholder: 'Value' });
    const row = h('div', { class: 'header-row' },
      field('Header name', n),
      field('Header value', v),
      h('button', { type: 'button', class: 'btn btn-small', 'aria-label': 'Remove header', on: { click: () => removeHeader(row) } }, icon('x')));
    return row;
  }

  // removing happens at once; Undo puts the row back where it was
  function removeHeader(row) {
    const next = row.nextSibling;
    const name = row.querySelector('.hdr-name').value.trim();
    row.remove();
    addBtn.focus();
    toast = undoToast(name ? `Removed header ${name}.` : 'Removed header.', {
      shortcut: UNDO_KEY,
      onUndo: () => {
        headerList.insertBefore(row, next && next.parentNode === headerList ? next : null);
        row.querySelector('input').focus();
      },
    });
  }
  const addBtn = h('button', { type: 'button', class: 'btn btn-small', on: { click: () => { const r = headerRow(); headerList.appendChild(r); r.querySelector('input').focus(); } } }, '+ Add header');

  function setHeaders(headers) {
    clear(headerList);
    for (const r of headersToRows(headers)) headerList.appendChild(headerRow(r.name, r.value));
  }

  function loadExample(key, exLabel) {
    const sample = exampleByKey(key);
    if (!sample) return;
    method.value = sample.method;
    path.value = sample.path;
    body.value = sample.body || '';
    setHeaders(sample.headers);
    label.value = exLabel;
    mount(errors);
  }

  function collect() {
    const rows = [...headerList.querySelectorAll('.header-row')].map((r) => ({
      name: r.querySelector('.hdr-name').value, value: r.querySelector('.hdr-value').value,
    }));
    const { headers, errors: hErr } = rowsToHeaders(rows);
    const sample = normalizeSample({ method: method.value, path: path.value.trim(), headers, body: body.value });
    return { sample, problems: [...hErr, ...validateSample(sample)] };
  }

  async function onSubmit(e) {
    e.preventDefault();
    const { sample, problems } = collect();
    path.setAttribute('aria-invalid', String(problems.some((p) => p.field === 'path')));
    mount(errors, fieldErrors(problems));
    if (problems.length) return;
    submit.disabled = true;
    mount(resultSlot, card('Result', h('p', { class: 'loading' }, 'Analyzing…')));
    try {
      const res = await api.analyze(sample, label.value.trim() || undefined, submitKey);
      submitKey.reset();
      const evt = res.event;
      mount(resultSlot, card('Result',
        decisionSummary(evt),
        h('div', { class: 'btn-group' },
          h('a', { class: 'btn btn-primary', href: `#/events/${encodeURIComponent(evt.id)}` }, 'Open full evidence', icon('arrow-right')),
          h('a', { class: 'btn', href: '#/events' }, 'Events'))));
    } catch (err) {
      mount(resultSlot);
      if (err && err.code === 'VALIDATION_FAILED') mount(errors, fieldErrors(err.details));
      else if (err && err.status !== 401) showStatus(err.friendly, 'error');
    } finally {
      submit.disabled = false;
    }
  }

  // clearing happens at once; Undo restores every field, header row and the last result
  function clearForm() {
    const saved = {
      example: exampleSelect.value, label: label.value, method: method.value, path: path.value, body: body.value,
      headers: [...headerList.childNodes], errors: [...errors.childNodes], result: [...resultSlot.childNodes],
    };
    exampleSelect.value = '';
    label.value = ''; method.value = 'GET'; path.value = '/'; body.value = '';
    setHeaders({}); mount(errors); mount(resultSlot);
    path.focus();
    toast = undoToast('Form cleared.', {
      shortcut: UNDO_KEY,
      onUndo: () => {
        exampleSelect.value = saved.example; label.value = saved.label; method.value = saved.method;
        path.value = saved.path; body.value = saved.body;
        mount(headerList, saved.headers); mount(errors, saved.errors); mount(resultSlot, saved.result);
        path.focus();
      },
    });
  }

  setHeaders({ 'user-agent': 'waf-studio-lab' });

  const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Analysis mode' },
    h('a', { class: 'tab', role: 'tab', href: '#/analyze', 'aria-selected': 'true' }, 'Single request'),
    h('a', { class: 'tab', role: 'tab', href: '#/import', 'aria-selected': 'false' }, 'Batch import (.json)'));

  mount(ctx.el,
    pageHeader('Analyze', exampleSelect),
    tabs,
    card(null,
      h('form', { class: 'form', novalidate: true, on: { submit: onSubmit } },
        h('div', { class: 'form-row' },
          field('Method', method),
          field('Path and query', path),
          field('Label', label)),
        h('details', { open: true }, h('summary', null, 'Headers'), headerList, addBtn),
        field('Body', body),
        errors,
        h('div', { class: 'btn-group' }, submit, h('button', { type: 'button', class: 'btn', on: { click: clearForm } }, 'Clear')))),
    resultSlot);
  // the undo would restore into a page that no longer exists, so leaving ends it
  return () => { if (toast && toast.open) toast.dismiss(); };
}
