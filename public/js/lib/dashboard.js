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
