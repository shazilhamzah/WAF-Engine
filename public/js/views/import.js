// Import: choose a .json file (≤ 256 KB), validate structure client-side, preview, POST /api/import.
// The server re-validates file name, size, structure and every sample.
import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { LIMITS, parseImportText, importPayload } from '../lib/samples.js';
import { formatBytes, truncate, formatTs } from '../lib/format.js';
import { pageHeader, card, field, table, showStatus, verdictBadge, actionBadge, emptyState } from '../ui.js';

export function render(ctx) {
  const fileInput = h('input', { type: 'file', accept: '.json,application/json' });
  const summary = h('div', { 'aria-live': 'polite' });
  const preview = h('div');
  const outcome = h('div', { 'aria-live': 'polite' });
  const submit = h('button', { type: 'button', class: 'btn btn-primary', disabled: true }, 'Import');
  let parsed = null;
  let filename = null;

  async function onFile() {
    parsed = null;
    submit.disabled = true;
    mount(preview); mount(outcome);
    const file = fileInput.files && fileInput.files[0];
    if (!file) { mount(summary); return; }
    filename = file.name;
    if (!/\.json$/i.test(file.name)) {
      mount(summary, h('p', { class: 'status-msg status-error' }, '⚠ The file must have a .json extension.'));
      return;
    }
    if (file.size > LIMITS.importFileMaxBytes) {
      mount(summary, h('p', { class: 'status-msg status-error' }, `⚠ The file is ${formatBytes(file.size)}; the limit is 256 KB.`));
      return;
    }
    const text = await file.text();
    const res = parseImportText(text, file.size, file.name);
    if (res.error && !res.ok) {
      mount(summary, h('p', { class: 'status-msg status-error' }, `⚠ ${res.error}`),
        res.invalid.length ? invalidList(res.invalid) : null);
      return;
    }
    parsed = res;
    submit.disabled = false;
    submit.textContent = `Import ${res.samples.length} sample${res.samples.length === 1 ? '' : 's'}`;
    mount(summary,
      h('p', { class: 'status-msg status-success' }, `✔ ${file.name} (${formatBytes(file.size)}) — ${res.samples.length} valid sample(s)` +
        (res.invalid.length ? `, ${res.invalid.length} invalid (will be skipped)` : '')),
      res.invalid.length ? invalidList(res.invalid) : null);
    mount(preview, table({
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
    }));
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
      mount(outcome,
        h('p', { class: 'status-msg status-success' }, `✔ Imported ${res.imported ?? events.length} · rejected by server ${(res.rejected || []).length}`),
        (res.rejected && res.rejected.length) ? h('ul', null, ...res.rejected.map((r) => h('li', null, `#${(r.index ?? 0) + 1}: ${r.code || ''} ${r.message || ''}`))) : null,
        table({
          caption: 'Imported events',
          columns: [
            { key: 'ts', label: 'Time', render: (e) => formatTs(e.ts) },
            { key: 'req', label: 'Request', render: (e) => h('a', { href: `#/events/${encodeURIComponent(e.id)}` }, code(`${e.method} ${truncate(e.path, 60)}`)) },
            { key: 'verdict', label: 'Verdict', render: (e) => verdictBadge(e.verdict) },
            { key: 'action', label: 'Action', render: (e) => actionBadge(e.action) },
            { key: 'score', label: 'Score', className: 'num' },
          ],
          rows: events,
          empty: 'No events were created.',
        }));
      showStatus(`Imported ${res.imported ?? events.length} sample(s).`, 'success');
      parsed = null;
      fileInput.value = '';
      mount(preview);
      mount(summary);
    } catch (err) {
      if (err && err.status !== 401) {
        mount(outcome, h('p', { class: 'status-msg status-error' }, `⚠ ${err.friendly}`));
        submit.disabled = false;
      }
    }
  }

  fileInput.addEventListener('change', onFile);
  submit.addEventListener('click', doImport);

  mount(ctx.el,
    pageHeader('Import samples'),
    card('File',
      h('p', { class: 'muted small' },
        'A JSON file (≤ 256 KB, ≤ 100 samples) containing either an array of samples or {"samples": [...]}. Each sample: ',
        code('{ "method": "GET", "path": "/search?q=shoes", "headers": {}, "body": null }'), '.'),
      field('Samples file (.json)', fileInput),
      summary,
      h('div', { class: 'btn-group' }, submit)),
    card('Preview', h('div', null, preview, emptyState('Choose a file to preview its samples.'))),
    card('Result', outcome));

  // The preview card keeps its placeholder until a file is parsed.
  const placeholder = preview.nextSibling;
  const obs = new MutationObserver(() => { if (placeholder) placeholder.hidden = preview.childNodes.length > 0; });
  obs.observe(preview, { childList: true });
  return () => obs.disconnect();
}
