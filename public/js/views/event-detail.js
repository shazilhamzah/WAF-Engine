import { h, mount, code } from '../dom.js';
import { api } from '../api.js';
import { can } from '../lib/roles.js';
import { hashFor } from '../lib/query.js';
import { truncate } from '../lib/format.js';
import { icon } from '../icons.js';
import { pageHeader, verdictBadge, actionBadge, modeBadge, chip, loading, showStatus, select, busy } from '../ui.js';
import { evidenceSections, versionLine } from '../decision.js';

const REPLAYABLE = new Set(['console', 'import', 'replay']);

export async function render(ctx) {
  const id = ctx.params.id;
  mount(ctx.el, loading('Loading event…'));
  let res;
  try {
    res = await api.event(id);
  } catch (err) {
    if (err && err.status === 404) {
      mount(ctx.el, h('div', { class: 'panel' }, h('h1', { id: 'page-title', tabindex: '-1' }, 'Event not found'),
        h('p', null, 'It may have been removed by a reset. ', h('a', { href: '#/events' }, 'Back to events'))));
      return;
    }
    throw err;
  }
  if (!ctx.isCurrent()) return;
  const event = res.event;
  const d = event.decision || {};
  const canReplay = can(ctx.role, 'events.replay') && REPLAYABLE.has(event.source) && event.sample !== null;
  const canRequest = can(ctx.role, 'exceptions.request');

  const replayBtn = h('button', { type: 'button', class: 'btn btn-primary', disabled: !canReplay, on: { click: replay } }, icon('refresh'), 'Replay with current rules');
  const fmt = select(['html', 'csv', 'json'], 'html', { 'aria-label': 'Export format' });
  const exportBtn = h('button', { type: 'button', class: 'btn', on: { click: doExport } }, icon('download'), 'Export this event');

  async function replay() {
    await busy(replayBtn, async () => {
      const r = await api.replay(event.id);
      ctx.flash(`Replayed with the current rules and configuration. New event ${r.event.id}.`, 'success');
      ctx.navigate(`#/events/${encodeURIComponent(r.event.id)}`);
    });
  }

  async function doExport() {
    await busy(exportBtn, async () => {
      const r = await api.exportReport({ format: fmt.value, ids: event.id });
      showStatus(`Downloaded ${r.name}. The export was recorded in the audit log.`, 'success');
    });
  }

  const actions = [replayBtn];
  if (can(ctx.role, 'reports.export')) actions.push(h('span', { class: 'btn-group' }, fmt, exportBtn));
  actions.push(h('a', { class: 'btn', href: hashFor('/compare', { a: event.id }) }, 'Compare with…'));
  if (event.replayOf) actions.push(h('a', { class: 'btn', href: hashFor('/compare', { a: event.replayOf, b: event.id }) }, 'Compare with original'));

  mount(ctx.el,
    pageHeader(`Event ${truncate(event.id, 40)}`),
    h('p', { class: 'muted' }, `${event.source}${event.label ? ` · “${event.label}”` : ''} · `, code(`${event.method} ${truncate(event.path, 120)}`)),
    h('div', { class: 'badges', 'aria-label': 'Decision' },
      verdictBadge(d.verdict || event.verdict),
      actionBadge(d.action || event.action),
      d.statusCode ? chip(`HTTP ${d.statusCode}`, 'bad') : null,
      h('span', null, 'mode ', modeBadge(d.mode || event.mode)),
      d.wouldBlock ? chip('would block: yes', d.action === 'blocked' ? 'bad' : 'warn') : chip('would block: no', 'ok')),
    h('div', { class: 'page-actions' }, ...actions),
    !canReplay && can(ctx.role, 'events.replay')
      ? h('p', { class: 'muted small' }, 'Replay is available for console and imported samples only; proxy events do not store the request body.')
      : null,
    h('p', { class: 'muted small' }, versionLine(event)),
    ...evidenceSections(event, { canRequest }).filter(Boolean));
}
