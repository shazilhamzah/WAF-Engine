import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { can } from '../lib/roles.js';
import { formatTs, shortHash, truncate } from '../lib/format.js';
import { pageHeader, card, table, severityBadge, loading, errorPanel, showStatus, confirmDialog, busy, message, statusLabel } from '../ui.js';
import { icon } from '../icons.js';

export const NEW_RULE_TEMPLATE = `rule 100100 "Describe what this rule detects" {
  when args contains "example-indicator"
  severity medium
  score 3
  category custom
  tags custom
  description "Why this input is suspicious"
}
`;

export function offsetFor(text, line, col) {
  const lines = String(text).split('\n');
  const l = Math.max(1, Math.min(lines.length, Number(line) || 1));
  let off = 0;
  for (let i = 0; i < l - 1; i += 1) off += lines[i].length + 1;
  return off + Math.max(0, Math.min(lines[l - 1].length, (Number(col) || 1) - 1));
}

export async function render(ctx) {
  const isAdmin = can(ctx.role, 'rules.write');
  const listBox = h('div', null, loading());
  const editor = h('textarea', { class: 'editor', rows: 14, spellcheck: 'false', autocomplete: 'off', 'aria-describedby': 'rule-editor-help' });
  const editorTitle = h('h2', { class: 'card-title', id: 'rule-editor-title' }, 'Rule editor');
  const validation = h('div', { 'aria-live': 'polite' });
  const historyBox = h('div');
  let editing = null;

  const validateBtn = h('button', { type: 'button', class: 'btn', on: { click: () => busy(validateBtn, validate) } }, 'Validate');
  const saveBtn = isAdmin ? h('button', { type: 'button', class: 'btn btn-primary', on: { click: () => busy(saveBtn, save) } }, 'Save rule') : null;
  const newBtn = isAdmin ? h('button', { type: 'button', class: 'btn', on: { click: startNew } }, '+ New rule') : null;

  function startNew() {
    editing = null;
    editor.value = NEW_RULE_TEMPLATE;
    editor.readOnly = false;
    editorTitle.textContent = 'New rule';
    mount(validation); mount(historyBox);
    editor.focus();
  }

  function startEdit(rule) {
    editing = rule.id;
    editor.value = rule.source || '';
    editor.readOnly = !isAdmin;
    editorTitle.textContent = `${isAdmin ? 'Edit' : 'View'} rule ${rule.id} (v${rule.version})`;
    mount(validation);
    editor.focus();
  }

  function showErrors(errors) {
    mount(validation,
      message('error', `${errors.length} problem${errors.length === 1 ? '' : 's'} found`),
      h('ul', { class: 'field-errors' }, ...errors.map((e) => h('li', null,
        (e.line ? h('button', { type: 'button', class: 'link-btn', on: { click: () => {
          const off = offsetFor(editor.value, e.line, e.col);
          editor.focus();
          editor.setSelectionRange(off, off + 1);
        } } }, `Line ${e.line}, col ${e.col || 1}`) : null),
        e.line ? ': ' : '', String(e.message || '')))));
    editor.setAttribute('aria-invalid', 'true');
  }

  async function validate() {
    const res = await api.validateRule(editor.value);
    if (res.ok) {
      editor.setAttribute('aria-invalid', 'false');
      const r = res.rule || {};
      mount(validation, message('success',
        `Valid: rule ${r.id ?? ''} “${r.name ?? ''}”${r.severity ? ` · ${r.severity}` : ''}${r.category ? ` · ${r.category}` : ''}${r.score !== undefined ? ` · score ${r.score}` : ''}`));
    } else {
      showErrors(res.errors || []);
    }
    return res.ok;
  }

  async function save() {
    try {
      if (editing === null) {
        const res = await api.createRule(editor.value, true);
        showStatus(`Rule ${res.rule && res.rule.id} created and enabled.`, 'success');
        editing = res.rule && res.rule.id;
      } else {
        const res = await api.updateRule(editing, { source: editor.value });
        showStatus(`Rule ${editing} updated to version ${res.rule && res.rule.version}.`, 'success');
      }
      await loadList();
    } catch (err) {
      if (err && err.code === 'VALIDATION_FAILED' && err.details.some((d) => d.line)) showErrors(err.details);
      else throw err;
    }
  }

  async function setEnabled(rule, enabled, btn) {
    if (!enabled) {
      const { confirmed } = await confirmDialog({
        title: `Disable rule ${rule.id}?`,
        body: h('p', null, `“${rule.name}” will stop matching immediately in the proxy and console. Requests that only matched this rule will no longer be flagged or blocked. This change is audited.`),
        confirmLabel: 'Disable rule', danger: true,
      });
      if (!confirmed) return;
    }
    await busy(btn, async () => {
      await api.updateRule(rule.id, enabled ? { enabled: true } : { enabled: false, confirm: true });
      showStatus(`Rule ${rule.id} ${enabled ? 'enabled' : 'disabled'}.`, 'success');
      await loadList();
    });
  }

  async function remove(rule, btn) {
    const { confirmed } = await confirmDialog({
      title: `Delete rule ${rule.id}?`,
      body: h('div', null, h('p', null, `“${rule.name}” will be removed from the active ruleset. Its version history is kept for the audit trail.`),
        h('p', null, h('strong', null, 'Consider disabling instead if you may need it again.'))),
      confirmLabel: 'Delete rule', danger: true,
    });
    if (!confirmed) return;
    await busy(btn, async () => {
      await api.deleteRule(rule.id);
      showStatus(`Rule ${rule.id} deleted.`, 'success');
      if (editing === rule.id) startNew();
      await loadList();
    });
  }

  async function showHistory(rule) {
    mount(historyBox, loading('Loading history…'));
    try {
      const res = await api.ruleHistory(rule.id);
      mount(historyBox, h('h3', null, `History of rule ${rule.id}`), table({
        caption: `Versions of rule ${rule.id}`,
        className: 'table-compact',
        columns: [
          { key: 'version', label: 'Version', className: 'num' },
          { key: 'change', label: 'Change' },
          { key: 'enabled', label: 'Enabled', render: (v) => (v.enabled ? 'yes' : 'no') },
          { key: 'changedBy', label: 'By' },
          { key: 'changedAt', label: 'When', render: (v) => formatTs(v.changedAt) },
          { key: 'source', label: 'Source', render: (v) => h('details', null, h('summary', null, 'Show'), h('pre', null, v.source || '')) },
        ],
        rows: res.items || [],
        empty: 'No history recorded.',
      }));
    } catch (err) {
      mount(historyBox, errorPanel(err));
    }
  }

  async function loadList() {
    let res;
    try {
      res = await api.rules();
    } catch (err) {
      if (err && err.status === 401) return;
      mount(listBox, errorPanel(err, loadList));
      return;
    }
    if (!ctx.isCurrent()) return;
    const items = (res.items || []).slice().sort((x, y) => Number(x.id) - Number(y.id));
    mount(listBox,
      h('p', { class: 'meta-line' }, h('span', null, 'Active ruleset ', code(shortHash(res.rulesetVersion, 20))),
        h('span', null, `${items.filter((r) => r.enabled).length} enabled of ${items.length}`)),
      (res.compileErrors && res.compileErrors.length) ? h('div', { class: 'warn-note' },
        h('p', null, icon('alert'), 'Some stored rules failed to compile and are not active:'),
        h('ul', null, ...res.compileErrors.map((e) => h('li', null, `Rule ${e.ruleId ?? '?'}: line ${e.line ?? '?'}, col ${e.col ?? '?'} — ${e.message || ''}`)))) : null,
      table({
        caption: 'Rules',
        columns: [
          { key: 'id', label: 'Id', render: (r) => code(r.id), rowHeader: true },
          { key: 'name', label: 'Name', render: (r) => truncate(r.name, 60) },
          { key: 'severity', label: 'Severity', render: (r) => severityBadge(r.severity) },
          { key: 'category', label: 'Category' },
          { key: 'version', label: 'Version', className: 'num' },
          { key: 'enabled', label: 'Status', render: (r) => (r.enabled ? statusLabel('enabled', 'ok') : statusLabel('disabled', 'muted')) },
          { key: 'actions', label: 'Actions', render: (r) => {
            const btns = [h('button', { type: 'button', class: 'btn btn-small', on: { click: () => startEdit(r) } }, isAdmin ? 'Edit' : 'View'),
              h('button', { type: 'button', class: 'btn btn-small', on: { click: () => showHistory(r) } }, 'History')];
            if (isAdmin) {
              const t = h('button', { type: 'button', class: 'btn btn-small', 'aria-pressed': String(Boolean(r.enabled)) }, r.enabled ? 'Disable' : 'Enable');
              t.addEventListener('click', () => setEnabled(r, !r.enabled, t));
              const d = h('button', { type: 'button', class: 'btn btn-small btn-danger' }, 'Delete');
              d.addEventListener('click', () => remove(r, d));
              btns.push(t, d);
            }
            return h('div', { class: 'btn-group' }, ...btns);
          } },
        ],
        rows: items,
        empty: 'No rules yet.',
      }));
  }

  mount(ctx.el,
    pageHeader('Rules', newBtn),
    isAdmin ? null : h('p', { class: 'note' }, 'You can read rules and validate DSL. Only administrators can create, change, enable/disable or delete rules.'),
    card('Ruleset', listBox),
    h('section', { class: 'card', 'aria-labelledby': 'rule-editor-title' },
      editorTitle,
      h('label', { for: 'rule-editor', class: 'sr-only' }, 'Rule source (DSL)'),
      editor,
      h('p', { class: 'hint', id: 'rule-editor-help' }, 'One rule per editor. Ids are integers 1000–999999. See docs/rule-dsl.md for targets and operators. Regexes are checked for catastrophic backtracking.'),
      h('div', { class: 'btn-group' }, validateBtn, saveBtn),
      validation,
      historyBox));
  editor.id = 'rule-editor';
  editor.value = NEW_RULE_TEMPLATE;
  if (!isAdmin) editorTitle.textContent = 'Validate DSL';
  await loadList();
}

