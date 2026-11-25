import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { can } from '../lib/roles.js';
import { formatTs } from '../lib/format.js';
import { icon } from '../icons.js';
import { diffObjects, displayValue } from '../lib/diff.js';
import { pageHeader, card, field, table, loading, errorPanel, showStatus, confirmDialog, diffTable, fieldErrors } from '../ui.js';

const LIMIT_FIELDS = [
  ['maxBodyBytes', 'Max body (bytes)', 'Larger requests are rejected (413) before rules run.'],
  ['inspectBodyBytes', 'Inspected body (bytes)', 'Bytes of the body that rules inspect.'],
  ['maxUrlLength', 'Max URL length', ''],
  ['maxHeaderCount', 'Max header count', ''],
  ['maxArgs', 'Max arguments', ''],
  ['decodeRounds', 'URL-decode rounds', 'Detects double/triple encoding.'],
];

export function checkConfig(cfg) {
  const errs = [];
  const int = (v) => Number.isInteger(v);
  const { flag, block } = cfg.thresholds || {};
  if (!int(flag) || !int(block) || flag < 1 || block > 100 || flag > block) {
    errs.push({ field: 'thresholds', message: 'need whole numbers with 1 ≤ flag ≤ block ≤ 100' });
  }
  for (const [k] of LIMIT_FIELDS) {
    const v = cfg.limits && cfg.limits[k];
    if (!int(v) || v < 1) errs.push({ field: `limits.${k}`, message: 'must be a positive whole number' });
  }
  if (cfg.limits && cfg.limits.inspectBodyBytes > cfg.limits.maxBodyBytes) {
    errs.push({ field: 'limits.inspectBodyBytes', message: 'cannot exceed max body' });
  }
  const rl = cfg.rateLimit || {};
  if (!int(rl.windowMs) || rl.windowMs < 1000) errs.push({ field: 'rateLimit.windowMs', message: 'must be ≥ 1000 ms' });
  if (!int(rl.maxRequests) || rl.maxRequests < 1) errs.push({ field: 'rateLimit.maxRequests', message: 'must be ≥ 1' });
  if (cfg.mode !== 'block' && cfg.mode !== 'monitor') errs.push({ field: 'mode', message: 'must be block or monitor' });
  return errs;
}

export async function render(ctx) {
  const isAdmin = can(ctx.role, 'config.write');
  const body = h('div', null, loading());
  const historyBox = h('div', null, loading());
  mount(ctx.el, pageHeader('Configuration'),
    body,
    h('details', { class: 'card' }, h('summary', null, 'Change history'), historyBox));

  async function load() {
    let res;
    try {
      res = await api.config();
    } catch (err) {
      if (err && err.status === 401) return;
      mount(body, errorPanel(err, load));
      return;
    }
    if (!ctx.isCurrent()) return;
    renderForm(res);
    loadHistory();
  }

  function num(value, attrs = {}) {
    return h('input', { type: 'number', inputmode: 'numeric', step: 1, min: 1, value, disabled: !isAdmin, ...attrs });
  }

  function renderForm(res) {
    const cfg = res.config || {};
    const modeName = `mode-${Date.now()}`;
    const modeBlock = h('input', { type: 'radio', name: modeName, value: 'block', checked: cfg.mode === 'block', disabled: !isAdmin, id: 'mode-block' });
    const modeMonitor = h('input', { type: 'radio', name: modeName, value: 'monitor', checked: cfg.mode === 'monitor', disabled: !isAdmin, id: 'mode-monitor' });
    const flag = num(cfg.thresholds && cfg.thresholds.flag, { max: 100 });
    const block = num(cfg.thresholds && cfg.thresholds.block, { max: 100 });
    const limits = {};
    for (const [k] of LIMIT_FIELDS) limits[k] = num(cfg.limits && cfg.limits[k]);
    const rlEnabled = h('input', { type: 'checkbox', checked: Boolean(cfg.rateLimit && cfg.rateLimit.enabled), disabled: !isAdmin, id: 'rl-enabled' });
    const rlWindow = num(cfg.rateLimit && cfg.rateLimit.windowMs, { min: 1000, step: 1000 });
    const rlMax = num(cfg.rateLimit && cfg.rateLimit.maxRequests);
    const errors = h('div');

    function collect() {
      const n = (el) => (el.value === '' ? NaN : Number(el.value));
      const next = JSON.parse(JSON.stringify(cfg));
      next.mode = modeMonitor.checked ? 'monitor' : 'block';
      next.thresholds = { ...(cfg.thresholds || {}), flag: n(flag), block: n(block) };
      next.limits = { ...(cfg.limits || {}) };
      for (const [k] of LIMIT_FIELDS) next.limits[k] = n(limits[k]);
      next.rateLimit = { ...(cfg.rateLimit || {}), enabled: rlEnabled.checked, windowMs: n(rlWindow), maxRequests: n(rlMax) };
      return next;
    }

    async function review(e) {
      e.preventDefault();
      const next = collect();
      const problems = checkConfig(next);
      mount(errors, fieldErrors(problems));
      if (problems.length) return;
      const changes = diffObjects(cfg, next);
      if (!changes.length) { showStatus('Nothing changed.', 'info'); return; }
      const modeChange = changes.find((c) => c.path === 'mode');
      const { confirmed, values } = await confirmDialog({
        title: 'Confirm configuration change',
        body: h('div', null,
          diffTable(changes, displayValue),
          modeChange && modeChange.to === 'monitor' ? h('p', { class: 'warn-note' }, icon('alert'), 'Monitor mode never blocks: attacks will be forwarded to the target and only logged.') : null),
        confirmLabel: 'Apply change',
        danger: Boolean(modeChange),
        fields: [{ name: 'reason', label: 'Reason', type: 'textarea', required: true, maxlength: 500 }],
      });
      if (!confirmed) return;
      try {
        const out = await api.updateConfig(next, values.reason);
        showStatus(`Configuration saved as version ${out.version}.`, 'success');
        window.dispatchEvent(new Event('waf:mode-changed'));
        await load();
      } catch (err) {
        if (err && err.code === 'VALIDATION_FAILED') mount(errors, fieldErrors(err.details));
        if (err && err.status !== 401) showStatus(err.friendly, 'error');
      }
    }

    mount(body,
      h('p', { class: 'meta-line' },
        h('span', null, 'Active version ', code(res.version)),
        h('span', null, `changed ${formatTs(res.changedAt)} by ${res.changedBy || '—'}`)),
      card(null,
        h('form', { class: 'form', novalidate: true, on: { submit: review } },
          h('fieldset', null, h('legend', null, 'Enforcement mode'),
            h('div', { class: 'radio-row' },
              h('label', { for: 'mode-block' }, modeBlock, 'Block (enforce 403)'),
              h('label', { for: 'mode-monitor' }, modeMonitor, 'Monitor (log only)'))),
          h('fieldset', null, h('legend', null, 'Thresholds'),
            h('div', { class: 'form-row' },
              field('Flag threshold', flag),
              field('Block threshold', block))),
          h('fieldset', null, h('legend', null, 'Limits'),
            h('div', { class: 'form-row' }, ...LIMIT_FIELDS.map(([k, label, hint]) => field(label, limits[k], hint || undefined)))),
          h('fieldset', null, h('legend', null, 'Rate limit'),
            h('div', { class: 'check-row' }, h('label', { for: 'rl-enabled' }, rlEnabled, 'Rate limiting enabled')),
            h('div', { class: 'form-row' },
              field('Window (ms)', rlWindow),
              field('Max requests per client', rlMax))),
          errors,
          isAdmin ? h('div', { class: 'btn-group' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Review changes…')) : null)));
  }

  async function loadHistory() {
    try {
      const res = await api.configHistory();
      const items = (res.items || []).slice().sort((a, b) => b.version - a.version);
      mount(historyBox, table({
        caption: 'Configuration versions',
        columns: [
          { key: 'version', label: 'Version', className: 'num', rowHeader: true },
          { key: 'changedAt', label: 'When', render: (r) => formatTs(r.changedAt) },
          { key: 'changedBy', label: 'By' },
          { key: 'reason', label: 'Reason', render: (r) => String(r.reason || '—') },
          { key: 'diff', label: 'Changes vs previous', render: (r) => {
            const prev = items.find((x) => x.version < r.version);
            if (!prev) return 'initial';
            const d = diffObjects(prev.config, r.config);
            return d.length ? h('ul', { class: 'small' }, ...d.map((c) => h('li', null, code(c.path), ` ${displayValue(c.from)} → ${displayValue(c.to)}`))) : 'no changes';
          } },
        ],
        rows: items,
        empty: 'No history.',
      }));
    } catch (err) {
      mount(historyBox, errorPanel(err));
    }
  }

  await load();
}
