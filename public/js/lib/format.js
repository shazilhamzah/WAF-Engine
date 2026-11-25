const pad = (n) => String(n).padStart(2, '0');

export function formatTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatMs(ms) {
  if (ms === null || ms === undefined || !Number.isFinite(Number(ms))) return '—';
  const n = Number(ms);
  if (n < 10) return `${n.toFixed(2)} ms`;
  if (n < 1000) return `${n.toFixed(1)} ms`;
  return `${(n / 1000).toFixed(2)} s`;
}

export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes))) return '—';
  const n = Number(bytes);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function formatNumber(n) {
  if (n === null || n === undefined || !Number.isFinite(Number(n))) return '0';
  return Number(n).toLocaleString('en-US');
}

export function truncate(str, max = 80) {
  const s = str === null || str === undefined ? '' : String(str);
  return s.length > max ? `${s.slice(0, Math.max(0, max - 1))}…` : s;
}

export function shortHash(v, len = 12) {
  if (v === null || v === undefined || v === '') return '—';
  const s = String(v);
  return s.length > len ? `${s.slice(0, len)}…` : s;
}

// verdict and action get a label and symbol so colour is never the only signal
const VERDICTS = {
  allow: { icon: '✔', text: 'allow', tone: 'ok' },
  flag: { icon: '⚑', text: 'flag', tone: 'warn' },
  block: { icon: '⛔', text: 'block', tone: 'bad' },
};
const ACTIONS = {
  allowed: { icon: '→', text: 'allowed', tone: 'ok' },
  logged: { icon: '✎', text: 'logged (monitor)', tone: 'warn' },
  blocked: { icon: '■', text: 'blocked', tone: 'bad' },
};
const SEVERITIES = {
  critical: { icon: '‼', text: 'critical', tone: 'bad' },
  high: { icon: '!', text: 'high', tone: 'bad' },
  medium: { icon: '•', text: 'medium', tone: 'warn' },
  low: { icon: '·', text: 'low', tone: 'info' },
  info: { icon: 'i', text: 'info', tone: 'info' },
};
const STATUSES = {
  pending: { icon: '…', text: 'pending', tone: 'warn' },
  approved: { icon: '✔', text: 'approved', tone: 'ok' },
  rejected: { icon: '✕', text: 'rejected', tone: 'bad' },
  revoked: { icon: '↺', text: 'revoked', tone: 'muted' },
  success: { icon: '✔', text: 'success', tone: 'ok' },
  failure: { icon: '✕', text: 'failure', tone: 'bad' },
  denied: { icon: '⛔', text: 'denied', tone: 'bad' },
};

function lookup(table, key) {
  const k = key === null || key === undefined ? '' : String(key);
  return table[k] || { icon: '?', text: k || 'unknown', tone: 'muted' };
}
export const verdictInfo = (v) => lookup(VERDICTS, v);
export const actionInfo = (a) => lookup(ACTIONS, a);
export const severityInfo = (s) => lookup(SEVERITIES, s);
export const statusInfo = (s) => lookup(STATUSES, s);
export const modeInfo = (m) => (m === 'monitor'
  ? { icon: '◉', text: 'Monitoring only', tone: 'warn' }
  : m === 'block' ? { icon: '✓', text: 'Enabled', tone: 'ok' } : { icon: '?', text: 'Mode unknown', tone: 'muted' });

export function percent(value, max) {
  const v = Number(value) || 0;
  const m = Number(max) || 0;
  if (m <= 0) return 0;
  return Math.max(0, Math.min(100, (v / m) * 100));
}

export function scoreScaleMax(score) {
  const total = Number(score && score.total) || 0;
  const block = Number(score && score.blockThreshold) || 0;
  return Math.max(total, block + 2, 10);
}

export function dateInputToIso(value, endOfDay = false) {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return '';
  const [y, m, d] = value.split('-').map(Number);
  const date = endOfDay ? new Date(y, m - 1, d, 23, 59, 59, 999) : new Date(y, m - 1, d, 0, 0, 0, 0);
  return Number.isNaN(date.getTime()) ? '' : date.toISOString();
}

export function hourLabel(hour) {
  if (typeof hour === 'number') return pad(hour % 24);
  const d = new Date(hour);
  if (!Number.isNaN(d.getTime())) return pad(d.getHours());
  return String(hour).slice(-5);
}

export function prettyJson(value) {
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}
