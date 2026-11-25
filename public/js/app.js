import { h, mount, clear } from './dom.js';
import { api, setCsrfToken, onUnauthorized, lastActivity } from './api.js';
import { parseHash } from './lib/query.js';
import { navGroupsFor, canOpenRoute } from './lib/roles.js';
import { modeBadge, rolePanel, showStatus, clearStatus, loading, errorPanel } from './ui.js';
import { icon } from './icons.js';

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

const IDLE_TIMEOUT_MS = 30 * 60 * 1000;
const state = {
  session: null,
  loginNotice: null,
  flash: null,
  controller: null,
  cleanup: null,
  renderSeq: 0,
};

const $ = (id) => document.getElementById(id);

export function setSession(data) {
  if (!data || !data.user) {
    state.session = null;
    setCsrfToken(null);
    return;
  }
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
    h('a', { href: '#/account', class: 'user-link', 'aria-label': `Account settings for ${user.username} (${user.role})` },
      h('span', { class: 'monogram', 'aria-hidden': 'true' }, user.username.slice(0, 1).toUpperCase()),
      h('span', { class: 'user-name' }, user.username),
      h('span', { class: 'user-role' }, user.role)),
    h('button', { type: 'button', class: 'btn btn-small btn-plain', on: { click: logout } }, icon('log-out'), 'Log out'));
  mount(nav, ...navGroupsFor(user.role).map((group) => {
    const links = h('ul', { class: 'nav-list' }, ...group.items.map((item) => h('li', null,
      h('a', { href: `#/${item.route}`, class: 'nav-link', dataset: { route: item.route } },
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

  mount(view, loading());
  let mod;
  try {
    mod = await VIEWS[name]();
  } catch {
    mount(view, errorPanel({ friendly: 'This screen failed to load.' }, () => render()));
    return;
  }
  if (seq !== state.renderSeq) return;
  const container = h('div', { class: `view-${name}` });
  mount(view, container);
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
  };
  try {
    const cleanup = await mod.render(ctx);
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
  if (title && document.activeElement && document.activeElement.closest && !document.activeElement.closest('#view form')) {
    title.focus({ preventScroll: false });
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
  startSessionWatch();
  if (!location.hash || location.hash === '#' || location.hash === '#/') location.replace(state.session ? '#/dashboard' : '#/login');
  else render();
}

boot();
