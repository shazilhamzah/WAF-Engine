import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { LIMITS, parseImportText, importPayload } from '../lib/samples.js';
import { formatBytes, truncate, formatTs } from '../lib/format.js';
import { pageHeader, card, field, table, outcomeBadge, message } from '../ui.js';

export function buildImportPanel() {
  const fileInput = h('input', { type: 'file', accept: '.json,application/json' });
  const summary = h('div', { 'aria-live': 'polite' });
  const previewSlot = h('div');
  const outcomeSlot = h('div', { 'aria-live': 'polite' });
  const submit = h('button', { type: 'button', class: 'btn btn-primary', disabled: true }, 'Import');
  let parsed = null;
  let filename = null;

  async function onFile() {
    parsed = null;
    submit.disabled = true;
    mount(previewSlot); mount(outcomeSlot);
    const file = fileInput.files && fileInput.files[0];
    if (!file) { mount(summary); return; }
    filename = file.name;
    if (!/\.json$/i.test(file.name)) {
      mount(summary, message('error', 'The file must have a .json extension.'));
      return;
    }
    if (file.size > LIMITS.importFileMaxBytes) {
      mount(summary, message('error', `The file is ${formatBytes(file.size)}; the limit is 256 KB.`));
      return;
    }
    const text = await file.text();
    const res = parseImportText(text, file.size, file.name);
    if (res.error && !res.ok) {
      mount(summary, message('error', `${res.error}`),
        res.invalid.length ? invalidList(res.invalid) : null);
      return;
    }
    parsed = res;
    submit.disabled = false;
    submit.textContent = `Import ${res.samples.length} sample${res.samples.length === 1 ? '' : 's'}`;
    mount(summary,
      message('success', `${file.name} (${formatBytes(file.size)}) — ${res.samples.length} valid` +
        (res.invalid.length ? `, ${res.invalid.length} invalid (skipped)` : '')),
      res.invalid.length ? invalidList(res.invalid) : null);
    mount(previewSlot, card('Preview', table({
      caption: 'Samples to import',
      className: 'table-compact',
      columns: [
        { key: 'i', label: '#', className: 'num', render: (r) => String(r.i + 1) },
        { key: 'method', label: 'Method', render: (r) => code(r.s.method) },
        { key: 'path', label: 'Path', render: (r) => code(truncate(r.s.path, 80)) },
        { key: 'label', label: 'Label', render: (r) => r.label || '—' },
        { key: 'headers', label: 'Headers', className: 'num', render: (r) => String(Object.keys(r.s.headers).length) },
        { key: 'body', label: 'Body', render: (r) => (r.s.body ? formatBytes(new TextEncoder().encode(r.s.body).length) : '—') },
      ],
      rows: res.samples.slice(0, 100).map((s, i) => ({ s, i, label: res.labels[i] })),
    })));
  }

  function invalidList(invalid) {
    return h('details', { open: true }, h('summary', null, `Invalid entries (${invalid.length})`),
      h('ul', null, ...invalid.slice(0, 50).map((x) => h('li', null, `#${x.index + 1}: ${x.message}`))));
  }

  async function doImport() {
    if (!parsed) return;
    submit.disabled = true;
    try {
      const res = await api.importSamples(filename, importPayload(parsed));
      const events = res.events || [];
      mount(outcomeSlot, card('Result',
        message('success', `Imported ${res.imported ?? events.length}` +
          ((res.rejected && res.rejected.length) ? ` · rejected ${res.rejected.length}` : '')),
        (res.rejected && res.rejected.length) ? h('ul', null, ...res.rejected.map((r) => h('li', null, `#${(r.index ?? 0) + 1}: ${r.code || ''} ${r.message || ''}`))) : null,
        table({
          caption: 'Imported events',
          columns: [
            { key: 'ts', label: 'Time', render: (e) => formatTs(e.ts) },
            { key: 'req', label: 'Request', render: (e) => h('a', { href: `#/events/${encodeURIComponent(e.id)}` }, code(`${e.method} ${truncate(e.path, 60)}`)) },
            { key: 'outcome', label: 'Outcome', render: outcomeBadge },
            { key: 'score', label: 'Score', className: 'num' },
          ],
          rows: events,
          empty: 'No events were created.',
        })));
      parsed = null;
      fileInput.value = '';
      mount(previewSlot);
      mount(summary);
    } catch (err) {
      if (err && err.status !== 401) {
        mount(outcomeSlot, card('Result', message('error', `${err.friendly}`)));
        submit.disabled = false;
      }
    }
  }

  fileInput.addEventListener('change', onFile);
  submit.addEventListener('click', doImport);

  return h('div', null,
    card(null,
      field('Samples file (.json, ≤ 256 KB, ≤ 100 samples)', fileInput,
        'Array of { "method", "path", "headers", "body" } objects or { "samples": [...] }.'),
      summary,
      h('div', { class: 'btn-group' }, submit)),
    previewSlot,
    outcomeSlot);
}

export function render(ctx) {
  const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Analysis mode' },
    h('a', { class: 'tab', role: 'tab', href: '#/analyze', 'aria-selected': 'false' }, 'Single request'),
    h('a', { class: 'tab', role: 'tab', href: '#/import', 'aria-selected': 'true' }, 'Batch import (.json)'));
  mount(ctx.el,
    pageHeader('Analyze'),
    tabs,
    buildImportPanel());
}
