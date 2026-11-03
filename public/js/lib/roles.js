// this only decides what to show and the server enforces every capability

export const ROLES = Object.freeze(['admin', 'operator', 'viewer']);

const STAFF = ['admin', 'operator'];
const ADMIN = ['admin'];
const ALL = ['admin', 'operator', 'viewer'];

export const CAPABILITIES = Object.freeze({
  'dashboard.view': ALL,
  'events.list': ALL,
  'events.detail': STAFF,
  'events.compare': STAFF,
  'events.replay': STAFF,
  'samples.submit': STAFF,
  'rules.read': STAFF,
  'rules.validate': STAFF,
  'rules.write': ADMIN,
  'config.read': STAFF,
  'config.write': ADMIN,
  'exceptions.request': STAFF,
  'exceptions.review': ADMIN,
  'audit.view': ADMIN,
  'reports.export': STAFF,
  'users.manage': ADMIN,
  'account.self': ALL,
});

export function can(role, capability) {
  const allowed = CAPABILITIES[capability];
  return Array.isArray(allowed) && allowed.includes(role);
}

export const NAV = Object.freeze([
  { route: 'dashboard', label: 'Overview', group: 'Activity', cap: 'dashboard.view' },
  { route: 'events', label: 'Events', group: 'Activity', cap: 'events.list' },
  { route: 'reports', label: 'Reports', group: 'Activity', cap: 'reports.export' },
  { route: 'analyze', label: 'Analyze request', group: 'Tools', cap: 'samples.submit' },
  { route: 'import', label: 'Import samples', group: 'Tools', cap: 'samples.submit' },
  { route: 'rules', label: 'Rules', group: 'Policy', cap: 'rules.read' },
  { route: 'config', label: 'Configuration', group: 'Policy', cap: 'config.read' },
  { route: 'exceptions', label: 'Exceptions', group: 'Policy', cap: 'exceptions.request' },
  { route: 'audit', label: 'Audit log', group: 'Administration', cap: 'audit.view' },
  { route: 'users', label: 'Users', group: 'Administration', cap: 'users.manage' },
]);

export const ROUTE_CAPS = Object.freeze({
  dashboard: 'dashboard.view',
  analyze: 'samples.submit',
  import: 'samples.submit',
  events: 'events.list',
  event: 'events.detail',
  compare: 'events.compare',
  rules: 'rules.read',
  config: 'config.read',
  exceptions: 'exceptions.request',
  audit: 'audit.view',
  reports: 'reports.export',
  users: 'users.manage',
  account: 'account.self',
});

export function navFor(role) {
  return NAV.filter((item) => can(role, item.cap));
}

export function navGroupsFor(role) {
  const entries = navFor(role);
  return ['Activity', 'Tools', 'Policy', 'Administration'].map((label) => ({
    label, collapsible: label === 'Policy' || label === 'Administration',
    items: entries.filter((item) => item.group === label),
  })).filter((group) => group.items.length);
}

export function canOpenRoute(role, route) {
  const cap = ROUTE_CAPS[route];
  return cap ? can(role, cap) : false;
}

export function rolesForRoute(route) {
  const cap = ROUTE_CAPS[route];
  return cap ? [...CAPABILITIES[cap]] : [];
}
