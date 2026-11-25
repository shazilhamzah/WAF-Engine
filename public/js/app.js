import { h, mount, clear } from './dom.js';
import { api, setCsrfToken, onUnauthorized, lastActivity } from './api.js';
import { parseHash } from './lib/query.js';
import { navGroupsFor, canOpenRoute, navFor, can } from './lib/roles.js';
import { modeBadge, rolePanel, showStatus, clearStatus, pageSkeleton, errorPanel, SKELETON_DELAY_MS, currentToast } from './ui.js';
import { icon } from './icons.js';
import { clearCache } from './cache.js';
import { isModEvent, isTypingTarget, shortcut, sequence } from './keys.js';
import { openCommandMenu, isCommandMenuOpen, closeCommandMenu } from './commands.js';

const VIEWS = {
  login: () => import('./views/login.js'),
  dashboard: () => import('./views/dashboard.js'),
  analyze: () => import('./views/analyze.js'),
  import: () => import('./views/import.js'),
  events: () => import('./views/events.js'),
  event: () => import('./views/event-detail.js'),
  compare: () => import('./views/compare.js'),
  rules: () => import('./views/rules.js'),
  config: () => import('./views/config.js'),
  exceptions: () => import('./views/exceptions.js'),
  audit: () => import('./views/audit.js'),
  reports: () => import('./views/reports.js'),
  users: () => import('./views/users.js'),
  account: () => import('./views/account.js'),
};

const NAV_ICONS = {
  dashboard: 'overview', events: 'list', reports: 'report', analyze: 'scan', import: 'upload',
  rules: 'shield-check', config: 'sliders', exceptions: 'clipboard', audit: 'history', users: 'users',
};

// "g" then a letter jumps to a page, shown in nav tooltips and the command menu
const GO_KEYS = { dashboard: 'o', events: 'e', analyze: 'a', rules: 'r', config: 'c', exceptions: 'x', audit: 'l', users: 'u' };
const ROUTE_FOR_KEY = Object.fromEntries(Object.entries(GO_KEYS).map(([route, key]) => [key, route]));
const MENU_KEY = shortcut('mod+k');
const SEQUENCE_MS = 1200;

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const state = {
  session: null,
  loginNotice: null,
  flash: null,
  controller: null,
  cleanup: null,
  revalidate: null,
  renderSeq: 0,
};

const $ = (id) => document.getElementById(id);

export function setSession(data) {
  if (!data || !data.user) {
    state.session = null;
    setCsrfToken(null);
    clearCache();
    return;
  }
  // cached screens belong to one signed-in user only
  if (!state.session || state.session.user.id !== data.user.id) clearCache();
  state.session = { user: data.user, csrfToken: data.csrfToken, expiresAt: data.expiresAt || null };
  setCsrfToken(data.csrfToken);
}

export function getSession() { return state.session; }

function navigate(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}

function flash(message, kind = 'success') {
  state.flash = { message, kind };
}

function sessionEnded(notice) {
  closeCommandMenu();
  setSession(null);
  state.loginNotice = notice || null;
  renderShell();
  if (location.hash !== '#/login') location.hash = '#/login';
  else render();
}

async function refreshMode(mode) {
  const slot = $('mode-badge');
  if (!slot || !state.session) return;
  try {
    const current = typeof mode === 'string' ? mode : (await api.stats(1)).mode;
    mount(slot, h('span', { class: 'sr-only' }, 'Current protection mode: '), modeBadge(current));
  } catch {
    clear(slot);
  }
}

async function logout() {
  try { await api.logout(); } catch { /* session may already be gone */ }
  sessionEnded('You have signed out.');
}

function renderShell() {
  const header = $('app-header');
  const nav = $('app-nav');
  const userBox = $('user-box');
  if (!state.session) {
    header.hidden = true;
    nav.hidden = true;
    clear(nav); clear(userBox); clear($('mode-badge'));
    document.body.classList.remove('signed-in');
    return;
  }
  const { user } = state.session;
  header.hidden = false;
  nav.hidden = false;
  document.body.classList.add('signed-in');
  mount(userBox,
    h('button', {
      type: 'button', class: 'btn btn-small btn-plain cmdk-trigger', 'aria-keyshortcuts': MENU_KEY.aria,
      title: `Search pages and actions (${MENU_KEY.label})`, on: { click: openMenu },
    }, icon('search'), h('span', { class: 'cmdk-trigger-label' }, 'Search'), h('kbd', { class: 'kbd', 'aria-hidden': 'true' }, MENU_KEY.label)),
    h('a', { href: '#/account', class: 'user-link', 'aria-label': `Account settings for ${user.username} (${user.role})` },
      h('span', { class: 'monogram', 'aria-hidden': 'true' }, user.username.slice(0, 1).toUpperCase()),
      h('span', { class: 'user-name' }, user.username),
      h('span', { class: 'user-role' }, user.role)),
    h('button', { type: 'button', class: 'btn btn-small btn-plain', on: { click: logout } }, icon('log-out'), 'Log out'));
  mount(nav, ...navGroupsFor(user.role).map((group) => {
    const links = h('ul', { class: 'nav-list' }, ...group.items.map((item) => h('li', null,
      h('a', {
        href: `#/${item.route}`, class: 'nav-link', dataset: { route: item.route },
        title: GO_KEYS[item.route] ? `${item.label} (${sequence('g', GO_KEYS[item.route]).label})` : null,
        'aria-keyshortcuts': GO_KEYS[item.route] ? sequence('g', GO_KEYS[item.route]).aria : null,
      },
        icon(NAV_ICONS[item.route] || 'list'), h('span', null, item.label)))));
    return group.collapsible
      ? h('details', { class: 'nav-group nav-disclosure' }, h('summary', null, group.label), links)
      : h('section', { class: 'nav-group', 'aria-label': group.label }, h('p', { class: 'nav-group-label' }, group.label), links);
  }));
  refreshMode();
}

function markActiveNav(route) {
  const active = route === 'event' || route === 'compare' || route === 'reports'
    ? 'events'
    : route === 'import' ? 'analyze' : route;
  for (const a of document.querySelectorAll('.nav-link')) {
    if (a.dataset.route === active) {
      a.setAttribute('aria-current', 'page');
      const group = a.closest('details');
      if (group) group.open = true;
    }
    else a.removeAttribute('aria-current');
  }
}

const VIEW_TRANSITION_WAIT_MS = 120;
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

// cross-fades the old screen into the new one; skipped for reduced motion and unsupported browsers
async function swapView(update) {
  if (typeof document.startViewTransition !== 'function' || reducedMotion.matches || document.visibilityState !== 'visible') {
    await update();
    return;
  }
  const transition = document.startViewTransition(update);
  transition.ready.catch(() => {});
  transition.finished.catch(() => {});
  try { await transition.updateCallbackDone; } catch { /* update errors surface through the render promise */ }
}

function closeMobileNav() {
  const toggle = $('nav-toggle');
  toggle.setAttribute('aria-expanded', 'false');
  $('app-nav').classList.remove('open');
}

async function render() {
  const seq = ++state.renderSeq;
  const { route, params, query } = parseHash(location.hash);
  const view = $('view');
  if (state.controller) state.controller.abort();
  if (typeof state.cleanup === 'function') { try { state.cleanup(); } catch { } }
  state.cleanup = null;
  state.revalidate = null;
  state.controller = new AbortController();
  closeMobileNav();

  if (state.flash) { showStatus(state.flash.message, state.flash.kind); state.flash = null; } else clearStatus();

  if (!state.session) {
    if (route !== 'login') { location.replace('#/login'); return; }
  } else if (route === 'login') {
    location.replace('#/dashboard');
    return;
  }

  const name = VIEWS[route] ? route : null;
  if (!name) {
    mount(view, h('div', { class: 'panel' },
      h('h1', { id: 'page-title', tabindex: '-1' }, 'Page not found'),
      h('p', null, h('a', { href: '#/dashboard' }, 'Go to the dashboard'))));
    focusTitle();
    return;
  }

  const role = state.session ? state.session.user.role : null;
  if (state.session) {
    markActiveNav(route);
    if (!canOpenRoute(role, route)) {
      mount(view, rolePanel(route, role));
      document.title = 'Not available · WAF Studio';
      focusTitle();
      return;
    }
  }

  // the old screen stays up while the view module loads; a skeleton only replaces it if that is slow
  const skeletonTimer = setTimeout(() => { if (seq === state.renderSeq) mount(view, pageSkeleton({ delay: 0 })); }, SKELETON_DELAY_MS);
  let mod;
  try {
    mod = await VIEWS[name]();
  } catch {
    clearTimeout(skeletonTimer);
    mount(view, errorPanel({ friendly: 'This screen failed to load.' }, () => render()));
    return;
  }
  clearTimeout(skeletonTimer);
  if (seq !== state.renderSeq) return;
  const container = h('div', { class: `view-${name}` });
  const ctx = {
    el: container,
    route, params, query,
    user: state.session ? state.session.user : null,
    role,
    session: state.session,
    signal: state.controller.signal,
    navigate, flash, refreshMode,
    setSession: (data) => { setSession(data); state.loginNotice = null; renderShell(); },
    loginNotice: state.loginNotice,
    sessionEnded,
    isCurrent: () => seq === state.renderSeq,
    // a view registers a refetch that runs when the window regains focus or the network returns
    onRevalidate: (fn) => { if (seq === state.renderSeq) state.revalidate = fn; },
  };
  let rendering;
  await swapView(async () => {
    mount(view, container);
    rendering = Promise.resolve().then(() => mod.render(ctx));
    // give fast data a moment so the transition lands on real content, never longer than that
    await Promise.race([rendering.catch(() => {}), new Promise((r) => setTimeout(r, VIEW_TRANSITION_WAIT_MS))]);
  });
  try {
    const cleanup = await rendering;
    if (seq === state.renderSeq) state.cleanup = cleanup || null;
  } catch (err) {
    if (seq !== state.renderSeq) return;
    if (err && err.status === 403) mount(container, rolePanel(route, role));
    else if (err && err.status === 401) return;
    else mount(container, errorPanel(err, () => render()));
  }
  const title = container.querySelector('h1');
  document.title = `${title ? title.textContent : 'WAF Studio'} · WAF Studio`;
  focusTitle();
}

function focusTitle() {
  const title = document.getElementById('page-title');
  const active = document.activeElement;
  const keepFocus = active && active.closest && (active.closest('#view form') || (active.closest('#view') && isTypingTarget(active)));
  if (title && active && active.closest && !keepFocus) {
    title.focus({ preventScroll: false });
  }
}

const REVALIDATE_MIN_GAP_MS = 2000;
let lastRevalidate = 0;
function revalidateView() {
  if (!state.session || typeof state.revalidate !== 'function' || document.visibilityState !== 'visible') return;
  if (Date.now() - lastRevalidate < REVALIDATE_MIN_GAP_MS) return;
  lastRevalidate = Date.now();
  try { Promise.resolve(state.revalidate()).catch(() => {}); } catch { /* view handles its own errors */ }
}

async function verifyAuditChain() {
  try {
    const res = await api.verifyAudit();
    if (res.ok) showStatus(`Audit hash chain verified (${res.checked ?? 'all'} records).`, 'success');
    else showStatus(`Audit chain broken at seq ${res.brokenAt}. Open the Audit log to investigate.`, 'error');
  } catch (err) {
    if (err && err.status !== 401) showStatus(err.friendly, 'error');
  }
}

function commandItems() {
  const { role } = state.session.user;
  const go = (route) => () => navigate(`#/${route}`);
  const items = navFor(role).map((item) => ({
    label: item.label, group: 'Go to', icon: NAV_ICONS[item.route], keywords: [item.group, item.route],
    shortcut: GO_KEYS[item.route] ? sequence('g', GO_KEYS[item.route]) : null, run: go(item.route),
  }));
  if (canOpenRoute(role, 'import')) items.push({ label: 'Batch import samples', group: 'Go to', icon: 'upload', keywords: ['json', 'upload', 'analyze'], run: go('import') });
  if (canOpenRoute(role, 'compare')) items.push({ label: 'Compare two events', group: 'Go to', icon: 'list', keywords: ['diff'], run: go('compare') });
  if (canOpenRoute(role, 'reports')) items.push({ label: 'Export a report', group: 'Go to', icon: 'download', keywords: ['csv', 'json', 'html', 'download'], run: go('reports') });
  items.push({ label: 'Account and password', group: 'Go to', icon: 'user', keywords: ['profile', 'change password', 'session'], run: go('account') });
  if (can(role, 'rules.write')) items.push({ label: 'New rule', group: 'Actions', icon: 'plus', keywords: ['create', 'dsl', 'add'], run: () => navigate('#/rules?new=1') });
  if (can(role, 'exceptions.request')) items.push({ label: 'Request an exception', group: 'Actions', icon: 'plus', keywords: ['false positive', 'allow', 'tuning'], run: () => navigate('#/exceptions?request=1') });
  if (can(role, 'users.manage')) items.push({ label: 'Create a user', group: 'Actions', icon: 'plus', keywords: ['add', 'account'], run: () => navigate('#/users?new=1') });
  if (can(role, 'audit.view')) items.push({ label: 'Verify audit hash chain', group: 'Actions', icon: 'shield-check', keywords: ['integrity', 'tamper'], run: verifyAuditChain });
  items.push({ label: 'Refresh this page', group: 'Actions', icon: 'refresh', keywords: ['reload'], run: () => render() });
  items.push({ label: 'Log out', group: 'Actions', icon: 'log-out', keywords: ['sign out'], run: logout });
  return items;
}

function openMenu() {
  if (state.session) openCommandMenu(commandItems());
}

let pendingGoAt = 0;
function onKeydown(e) {
  if (e.defaultPrevented || e.isComposing || !state.session) return;
  // the command menu and modal dialogs handle their own keys, and nothing fires while typing in a field
  if (isCommandMenuOpen() || document.querySelector('dialog[open]') || isTypingTarget(e.target)) return;
  const key = e.key.toLowerCase();
  if (isModEvent(e) && !e.shiftKey && !e.altKey) {
    if (key === 'k') { e.preventDefault(); openMenu(); return; }
    if (key === 'z') {
      const toast = currentToast();
      if (toast && toast.open) { e.preventDefault(); toast.undo(); }
    }
    return;
  }
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (pendingGoAt && Date.now() - pendingGoAt < SEQUENCE_MS) {
    pendingGoAt = 0;
    const route = ROUTE_FOR_KEY[key];
    if (route && canOpenRoute(state.session.user.role, route)) { e.preventDefault(); navigate(`#/${route}`); }
    return;
  }
  pendingGoAt = 0;
  if (key === 'g' && !e.shiftKey) { pendingGoAt = Date.now(); return; }
  if (e.key === '/') {
    const search = document.querySelector('#view [data-shortcut="search"]');
    if (search) { e.preventDefault(); search.focus(); if (typeof search.select === 'function') search.select(); }
  }
}

function startSessionWatch() {
  setInterval(async () => {
    if (!state.session) return;
    const expiresAt = state.session.expiresAt ? Date.parse(state.session.expiresAt) : NaN;
    const idle = Date.now() - lastActivity() > IDLE_TIMEOUT_MS + 5000;
    const absolute = Number.isFinite(expiresAt) && Date.now() > expiresAt;
    if (!idle && !absolute) return;
    // ask the server since a 401 means the session really ended
    try {
      const me = await api.me();
      setSession(me);
    } catch (err) {
      if (err && err.status === 401) sessionEnded('Your session has expired. Please sign in again.');
    }
  }, 30000);
}

async function boot() {
  onUnauthorized((code) => {
    sessionEnded(code === 'SESSION_EXPIRED'
      ? 'Your session has expired. Please sign in again.'
      : 'Please sign in to continue.');
  });
  $('nav-toggle').addEventListener('click', () => {
    const toggle = $('nav-toggle');
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(open));
    $('app-nav').classList.toggle('open', open);
  });
  try {
    setSession(await api.me());
  } catch (err) {
    setSession(null);
    if (err && err.code === 'SESSION_EXPIRED') state.loginNotice = 'Your session has expired. Please sign in again.';
    else if (err && err.status === 0) state.loginNotice = err.friendly;
  }
  renderShell();
  window.addEventListener('hashchange', render);
  window.addEventListener('waf:mode-changed', refreshMode);
  document.addEventListener('keydown', onKeydown);
  window.addEventListener('focus', revalidateView);
  window.addEventListener('online', revalidateView);
  document.addEventListener('visibilitychange', revalidateView);
  startSessionWatch();
  if (!location.hash || location.hash === '#' || location.hash === '#/') location.replace(state.session ? '#/dashboard' : '#/login');
  else render();
}

boot();
