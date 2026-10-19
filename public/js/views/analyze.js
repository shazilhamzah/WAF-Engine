// Analyze: build a sample (method, path, headers, body), submit, show the explainable decision.
import { h, mount, clear } from '../dom.js';
import { api } from '../api.js';
import { EXAMPLES, METHODS, LIMITS, exampleByKey, validateSample, rowsToHeaders, headersToRows, normalizeSample } from '../lib/samples.js';
import { pageHeader, card, field, select, fieldErrors, showStatus, emptyState } from '../ui.js';
import { decisionSummary, versionLine } from '../decision.js';

export function render(ctx) {
  const label = h('input', { type: 'text', maxlength: LIMITS.labelMax, placeholder: 'e.g. normal search' });
  const method = select(METHODS, 'GET');
  const path = h('input', { type: 'text', required: true, maxlength: LIMITS.pathMax, value: '/search?q=hello', spellcheck: 'false', autocomplete: 'off' });
  const body = h('textarea', { rows: 6, spellcheck: 'false', placeholder: 'Request body (optional)' });
  const headerList = h('div', { class: 'header-list' });
  const errors = h('div');
  const result = h('div', { 'aria-live': 'polite' }, emptyState('Submit a sample to see the decision and its evidence.'));
  const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, 'Analyze');

  function headerRow(name = '', value = '') {
    const n = h('input', { type: 'text', value: name, maxlength: 100, spellcheck: 'false', autocomplete: 'off', class: 'hdr-name' });
    const v = h('input', { type: 'text', value, maxlength: LIMITS.headerValueMax, spellcheck: 'false', autocomplete: 'off', class: 'hdr-value' });
    const row = h('div', { class: 'header-row' },
      field('Header name', n),
      field('Header value', v),
      h('button', { type: 'button', class: 'btn btn-small', 'aria-label': 'Remove header', on: { click: () => { row.remove(); addBtn.focus(); } } }, '✕'));
    return row;
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
    showStatus(`Loaded example "${exLabel}".`, 'info');
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
    if (problems.length) { showStatus('Fix the highlighted problems before submitting.', 'error'); return; }
    submit.disabled = true;
    mount(result, h('p', { class: 'loading' }, 'Analyzing…'));
    try {
      const res = await api.analyze(sample, label.value.trim() || undefined);
      const evt = res.event;
      mount(result,
        decisionSummary(evt),
        h('p', { class: 'muted small' }, `Event ${evt.id} · ${versionLine(evt)}`),
        h('div', { class: 'btn-group' },
          h('a', { class: 'btn btn-primary', href: `#/events/${encodeURIComponent(evt.id)}` }, 'Open full evidence →'),
          h('a', { class: 'btn', href: '#/events' }, 'History')));
      showStatus(`Analysis complete: ${evt.verdict || (evt.decision && evt.decision.verdict)}.`, 'success');
    } catch (err) {
      mount(result, emptyState('No result.'));
      if (err && err.code === 'VALIDATION_FAILED') mount(errors, fieldErrors(err.details));
      if (err && err.status !== 401) showStatus(err.friendly, 'error');
    } finally {
      submit.disabled = false;
    }
  }

  function clearForm() {
    label.value = ''; method.value = 'GET'; path.value = '/'; body.value = '';
    setHeaders({}); mount(errors); mount(result, emptyState('Submit a sample to see the decision and its evidence.'));
    path.focus();
  }

  setHeaders({ 'user-agent': 'waf-studio-lab' });

  mount(ctx.el,
    pageHeader('Analyze a request'),
    card('Load an example',
      h('p', { class: 'muted small' }, 'Safe lab samples: benign inputs (including false-positive candidates) and classic attack indicators.'),
      h('div', { class: 'btn-group' }, ...EXAMPLES.map((ex) => h('button', {
        type: 'button', class: ['btn', 'btn-small', ex.kind === 'attack' ? 'example-attack' : 'example-benign'],
        on: { click: () => loadExample(ex.key, ex.label) },
      }, ex.kind === 'attack' ? `⚠ ${ex.label}` : `✔ ${ex.label}`)))),
    card('Sample',
      h('form', { class: 'form', novalidate: true, on: { submit: onSubmit } },
        field('Label (optional)', label, 'Helps you find this event in history.'),
        h('div', { class: 'form-row' },
          field('Method', method),
          field('Path and query', path, "Must start with '/'. URL-encode spaces and special characters.")),
        h('fieldset', null, h('legend', null, 'Headers'), headerList, addBtn,
          h('p', { class: 'hint' }, `Up to ${LIMITS.headerMax} headers. Names: letters, digits and '-'.`)),
        field('Body', body, 'Up to 1 MiB. Leave empty for none.'),
        errors,
        h('div', { class: 'btn-group' }, submit, h('button', { type: 'button', class: 'btn', on: { click: clearForm } }, 'Clear')))),
    card('Result', result));
}
