// command menu: every page and action the signed-in role can use, reachable with the keyboard alone
import { h, mount, uid } from './dom.js';
import { icon } from './icons.js';

let openMenu = null;

export function isCommandMenuOpen() { return Boolean(openMenu); }

export function closeCommandMenu() { if (openMenu) openMenu.close(); }

function matches(item, terms) {
  const hay = `${item.label} ${item.group} ${(item.keywords || []).join(' ')}`.toLowerCase();
  return terms.every((t) => hay.includes(t));
}

function score(item, query) {
  const label = item.label.toLowerCase();
  if (!query) return 0;
  if (label.startsWith(query)) return 0;
  if (label.includes(query)) return 1;
  return 2;
}

/**
 * items: [{ id, label, group, icon, keywords, shortcut: { label, aria }, run() }]
 */
export function openCommandMenu(items) {
  if (openMenu) { openMenu.focus(); return openMenu; }
  const previous = document.activeElement;
  const listId = uid('cmdk-list');
  const input = h('input', {
    type: 'text', class: 'cmdk-input', role: 'combobox', autocomplete: 'off', spellcheck: 'false',
    'aria-label': 'Search pages and actions', 'aria-expanded': 'true', 'aria-controls': listId,
    'aria-autocomplete': 'list', placeholder: 'Search pages and actions…',
  });
  const list = h('div', { class: 'cmdk-list', id: listId, role: 'listbox', 'aria-label': 'Pages and actions' });
  const count = h('p', { class: 'sr-only', role: 'status', 'aria-live': 'polite' });
  const footer = h('p', { class: 'cmdk-footer', 'aria-hidden': 'true' },
    h('span', null, h('kbd', { class: 'kbd' }, '↑'), h('kbd', { class: 'kbd' }, '↓'), ' to move'),
    h('span', null, h('kbd', { class: 'kbd' }, 'Enter'), ' to open'),
    h('span', null, h('kbd', { class: 'kbd' }, 'Esc'), ' to close'));
  const dlg = h('dialog', { class: 'dialog cmdk', 'aria-label': 'Command menu' },
    h('div', { class: 'cmdk-search' }, icon('search'), input),
    list, count, footer);

  let visible = [];
  let active = 0;

  function optionId(i) { return `${listId}-opt-${i}`; }

  function setActive(i, scroll = true) {
    if (!visible.length) { input.removeAttribute('aria-activedescendant'); return; }
    active = (i + visible.length) % visible.length;
    for (const el of list.querySelectorAll('[role="option"]')) {
      el.setAttribute('aria-selected', String(el.id === optionId(active)));
    }
    input.setAttribute('aria-activedescendant', optionId(active));
    const el = document.getElementById(optionId(active));
    if (el && scroll) el.scrollIntoView({ block: 'nearest' });
  }

  function paint() {
    const query = input.value.trim().toLowerCase();
    const terms = query.split(/\s+/).filter(Boolean);
    visible = items.filter((it) => matches(it, terms))
      .map((it, i) => ({ it, i, s: score(it, query) }))
      .sort((a, b) => a.s - b.s || a.i - b.i)
      .map((x) => x.it);
    // keep groups together in their original order once filtered
    const groups = [...new Set(items.map((it) => it.group))];
    visible.sort((a, b) => groups.indexOf(a.group) - groups.indexOf(b.group));
    let n = 0;
    const sections = groups.map((g) => {
      const inGroup = visible.filter((it) => it.group === g);
      if (!inGroup.length) return null;
      const headId = uid('cmdk-group');
      return h('div', { role: 'group', 'aria-labelledby': headId, class: 'cmdk-group' },
        h('p', { class: 'cmdk-group-label', id: headId }, g),
        ...inGroup.map((it) => {
          const index = n++;
          return h('div', {
            id: optionId(index), role: 'option', class: 'cmdk-option', 'aria-selected': 'false',
            'aria-keyshortcuts': it.shortcut ? it.shortcut.aria : null,
            on: {
              click: () => run(index),
              pointermove: () => { if (active !== index) setActive(index, false); },
            },
          },
          icon(it.icon || 'arrow-right'),
          h('span', { class: 'cmdk-label' }, it.label),
          it.shortcut ? h('kbd', { class: 'kbd', 'aria-hidden': 'true' }, it.shortcut.label) : null);
        }));
    });
    mount(list, ...sections, visible.length ? null : h('p', { class: 'cmdk-empty' }, 'No matching pages or actions.'));
    count.textContent = `${visible.length} result${visible.length === 1 ? '' : 's'}`;
    setActive(0);
  }

  function run(index) {
    const it = visible[index];
    if (!it) return;
    close(false);
    it.run();
  }

  function close(restoreFocus = true) {
    if (!openMenu) return;
    openMenu = null;
    if (dlg.open) dlg.close();
    dlg.remove();
    if (restoreFocus && previous && typeof previous.focus === 'function' && document.contains(previous)) previous.focus();
  }

  input.addEventListener('input', paint);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
    else if (e.key === 'Home' && e.ctrlKey) { e.preventDefault(); setActive(0); }
    else if (e.key === 'End' && e.ctrlKey) { e.preventDefault(); setActive(visible.length - 1); }
    else if (e.key === 'PageDown') { e.preventDefault(); setActive(Math.min(visible.length - 1, active + 5)); }
    else if (e.key === 'PageUp') { e.preventDefault(); setActive(Math.max(0, active - 5)); }
    else if (e.key === 'Enter') { e.preventDefault(); run(active); }
    else if (e.key === 'Tab') { e.preventDefault(); }
  });
  dlg.addEventListener('cancel', (e) => { e.preventDefault(); close(); });
  dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });

  document.body.appendChild(dlg);
  openMenu = { close: () => close(), focus: () => input.focus() };
  paint();
  if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
  input.focus();
  return openMenu;
}
