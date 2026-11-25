'use strict';

const { describeVia } = require('./normalize');

const CATEGORY_TEXT = Object.freeze({
  sqli: 'SQL injection indicators',
  xss: 'cross-site scripting indicators',
  traversal: 'path traversal / local file inclusion indicators',
  cmdi: 'OS command injection indicators',
  protocol: 'HTTP protocol anomalies',
  scanner: 'automated scanner signatures',
  anomaly: 'parser anomalies (encoding / structure)',
});

const REJECT_TEXT = Object.freeze({
  MALFORMED_REQUEST: 'the request is malformed',
  BODY_TOO_LARGE: 'the body exceeds the configured maximum size',
});

function categoryText(cat) {
  return CATEGORY_TEXT[cat] || `${cat} indicators`;
}

function signed(points) {
  return points >= 0 ? `+${points}` : String(points);
}

function matchSentence(m) {
  const via = describeVia(m.decodedVia);
  const how = m.operator === 'not' ? ` (${m.location} absent or not matching)` : '';
  const where = m.operator === 'not' ? 'matched' : `matched ${m.location}`;
  const extra = Array.isArray(m.locations) && m.locations.length > 1 ? ` (also ${m.locations.slice(1, 4).join(', ')}${m.locations.length > 4 ? ', …' : ''})` : '';
  return `Rule ${m.ruleId} '${m.ruleName}' ${where}${how}${via ? ` after ${via}` : ''}${extra} (${signed(m.points)})`;
}

function buildExplanation(d) {
  const lines = [];
  const anomalies = d.anomalies || [];
  if (!d.parsedOk) {
    const a = anomalies[0];
    lines.push(`Request rejected by the parser before rule evaluation: ${a ? `${a.code} — ${a.message}` : 'malformed input'}`);
  }
  for (const m of d.matches) lines.push(matchSentence(m));
  for (const s of d.suppressed) {
    lines.push(`Rule ${s.ruleId} '${s.ruleName}' matched ${s.location} but is suppressed by approved exception ${s.suppressedBy} (+0)`);
  }
  for (const a of anomalies) {
    if (!d.parsedOk && a === anomalies[0]) continue;
    lines.push(`Parser anomaly ${a.code}: ${a.message} (${signed(a.points)})`);
  }
  if (d.parsedOk && d.matches.length === 0 && anomalies.length === 0) {
    lines.push(d.suppressed.length ? 'No unsuppressed rule matched and no parser anomaly was found' : 'No rule matched and no parser anomaly was found');
  }
  const s = d.score;
  const cmp = s.total >= s.blockThreshold
    ? `>= block threshold ${s.blockThreshold}`
    : (s.total >= s.flagThreshold ? `>= flag threshold ${s.flagThreshold} but < block threshold ${s.blockThreshold}` : `< flag threshold ${s.flagThreshold}`);
  lines.push(`Total score ${s.total} ${cmp} -> score verdict ${d.scoreVerdict}`);
  const rl = d.rateLimit;
  if (rl && rl.checked) {
    lines.push(rl.limited
      ? `Rate limit exceeded: ${rl.count} requests from this client in the last ${Math.round(rl.windowMs / 1000)} s (limit ${rl.limit})`
      : `Rate limit ok: ${rl.count}/${rl.limit} requests in the last ${Math.round(rl.windowMs / 1000)} s`);
  } else {
    lines.push('Rate limit not checked for this request');
  }
  if (d.wouldBlock) {
    const reason = d.blockReason;
    lines.push(d.mode === 'monitor'
      ? `Mode monitor: the request would have been blocked (${reason}) but was only logged and forwarded`
      : `Mode block: request blocked with HTTP ${d.statusCode} (${reason})`);
  } else {
    lines.push(`Mode ${d.mode}: request allowed (verdict ${d.verdict})`);
  }
  return { explanation: lines, recommendation: recommend(d) };
}

function recommend(d) {
  const suffix = d.mode === 'monitor' && d.wouldBlock ? ' (monitor mode: logged, not blocked).' : '.';
  if (d.blockReason === 'MALFORMED_REQUEST' || d.blockReason === 'BODY_TOO_LARGE') {
    const code = d.anomalies && d.anomalies[0] ? d.anomalies[0].code : d.blockReason;
    return `Reject: ${REJECT_TEXT[d.blockReason]} (${code}); fix the client, or raise the matching limit only if this traffic is legitimate${suffix}`;
  }
  const cats = Object.entries(d.score.byCategory || {})
    .sort((a, b) => b[1] - a[1])
    .map(([c]) => categoryText(c));
  const ruleIds = d.matches.map((m) => m.ruleId);
  if (d.blockReason === 'SCORE_THRESHOLD') {
    return `Block: input contains ${cats.slice(0, 3).join(' and ')} (rules ${ruleIds.slice(0, 5).join(', ') || 'none'}). `
      + `If this is legitimate traffic, request a scoped exception for the rule and location instead of disabling the rule${suffix}`;
  }
  if (d.blockReason === 'RATE_LIMITED') {
    return `Throttle: this client exceeded ${d.rateLimit.limit} requests per ${Math.round(d.rateLimit.windowMs / 1000)} s; `
      + `check for automation or raise rateLimit.maxRequests if the volume is expected${suffix}`;
  }
  if (d.verdict === 'flag') {
    return `Review: score ${d.score.total} reached the flag threshold (${cats.slice(0, 3).join(', ')}) but not the block threshold; check the evidence.`;
  }
  if (d.score.total > 0) {
    return `Allow: only low-confidence indicators (score ${d.score.total} < flag threshold ${d.score.flagThreshold}).`;
  }
  if (d.suppressed && d.suppressed.length) return 'Allow: all matching rules are covered by approved exceptions.';
  return 'Allow: no rule matched and no parser anomaly was found.';
}

module.exports = { CATEGORY_TEXT, buildExplanation, matchSentence };
