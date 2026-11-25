export function summarizeOutcomes(totals = {}) {
  const count = (v) => Math.max(0, Number(v) || 0);
  return {
    total: count(totals.requests),
    blocked: count(totals.blocked),
    passed: count(totals.allowed) + count(totals.logged),
    flagged: count(totals.flagged),
    monitored: count(totals.logged),
  };
}

export function eventOutcome(event) {
  if (event.action === 'blocked') return { text: 'Blocked', icon: '■', tone: 'bad' };
  if (event.action === 'logged') return {
    text: event.verdict === 'block' ? 'Would block · monitor' : 'Logged · monitor', icon: '◉', tone: 'warn',
  };
  if (event.action === 'allowed') return event.verdict === 'flag'
    ? { text: 'Flagged · passed', icon: '⚑', tone: 'warn' }
    : { text: 'Passed', icon: '✓', tone: 'muted' };
  return { text: 'Unknown outcome', icon: '?', tone: 'muted' };
}

export const CATEGORY_NAMES = {
  sqli: 'SQL injection', xss: 'Cross-site scripting', traversal: 'Path traversal',
  cmdi: 'Command injection', scanner: 'Scanner activity', protocol: 'Protocol anomalies', anomaly: 'Request anomalies',
};

export const SOURCE_NAMES = { proxy: 'Proxy traffic', console: 'Manual analysis', import: 'Imported sample', replay: 'Replay' };

const REPLAYABLE_SOURCES = new Set(['console', 'import', 'replay']);

// why an event cannot be replayed, or null when it can; shown as text because a disabled button hides its tooltip from keyboard and touch users
export function replayUnavailableReason(event) {
  if (!event) return 'This event cannot be replayed.';
  if (event.source === 'proxy') return 'Proxy events cannot be replayed because their request bodies are not stored.';
  if (!REPLAYABLE_SOURCES.has(event.source)) return 'This event cannot be replayed.';
  if (event.sample === null) return 'This event has no stored sample to replay.';
  return null;
}
