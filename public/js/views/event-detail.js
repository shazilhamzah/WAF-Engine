import { h, mount, code } from '../dom.js';
import { api, actionKey } from '../api.js';
import { can } from '../lib/roles.js';
import { hashFor } from '../lib/query.js';
import { truncate } from '../lib/format.js';
import { icon } from '../icons.js';
import { pageHeader, outcomeBadge, chip, showStatus, select, busy, card, skeleton, skeletonLine } from '../ui.js';
import { evidenceSections } from '../decision.js';

const REPLAYABLE = new Set(['console', 'import', 'replay']);

export async function render(ctx) {
  const id = ctx.params.id;
  mount(ctx.el, skeleton(
    h('div', { class: 'page-head' }, h('div', { class: 'skeleton-heading' }, skeletonLine('title'))),
    h('div', { class: 'badges' }, skeletonLine('short')),
    card(null, skeletonLine(), skeletonLine(), skeletonLine('short')),
    card(null, skeletonLine(), skeletonLine('short'))));
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

  const replayBtn = h('button', {
    type: 'button', class: 'btn btn-primary', disabled: !canReplay,
    title: !canReplay ? 'Replay is only available for console and imported samples' : null,
    on: { click: replay },
  }, icon('refresh'), 'Replay');
  const fmt = select(['html', 'csv', 'json'], 'html', { 'aria-label': 'Export format' });
  const exportBtn = h('button', { type: 'button', class: 'btn', on: { click: doExport } }, icon('download'), 'Export');

  const replayKey = actionKey();
  async function replay() {
    await busy(replayBtn, async () => {
      const r = await api.replay(event.id, replayKey);
      replayKey.reset();
      ctx.flash(`Replayed as event ${r.event.id}.`, 'success');
      ctx.navigate(`#/events/${encodeURIComponent(r.event.id)}`);
    });
  }

  async function doExport() {
    await busy(exportBtn, async () => {
      const r = await api.exportReport({ format: fmt.value, ids: event.id });
      showStatus(`Downloaded ${r.name}.`, 'success');
    });
  }

  const actions = [replayBtn];
  if (can(ctx.role, 'reports.export')) actions.push(h('span', { class: 'btn-group' }, fmt, exportBtn));
  actions.push(h('a', { class: 'btn', href: hashFor('/compare', { a: event.id }) }, 'Compare…'));
  if (event.replayOf) actions.push(h('a', { class: 'btn', href: hashFor('/compare', { a: event.replayOf, b: event.id }) }, 'Compare with original'));

  mount(ctx.el,
    pageHeader(`Event ${truncate(event.id, 40)}`, ...actions),
    h('div', { class: 'badges', 'aria-label': 'Decision' },
      outcomeBadge({ verdict: d.verdict || event.verdict, action: d.action || event.action }),
      d.statusCode ? chip(`HTTP ${d.statusCode}`, 'bad') : null,
      h('span', { class: 'muted' }, `${event.source}${event.label ? ` · “${event.label}”` : ''}`),
      code(`${event.method} ${truncate(event.path, 120)}`, 'code vt-event-request')),
    ...evidenceSections(event, { canRequest }).filter(Boolean));
}
