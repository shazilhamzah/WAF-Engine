'use strict';

const ANOMALY_CATEGORY = 'anomaly';

function verdictFor(total, thresholds) {
  if (total >= thresholds.block) return 'block';
  if (total >= thresholds.flag) return 'flag';
  return 'allow';
}

function computeScore(matches, anomalies, thresholds) {
  const byCategory = {};
  const contributions = [];
  let total = 0;
  for (const m of matches) {
    const points = Number.isFinite(m.points) ? m.points : 0;
    total += points;
    byCategory[m.category] = (byCategory[m.category] || 0) + points;
    contributions.push({ source: 'rule', id: String(m.ruleId), points, reason: `${m.ruleName} matched ${m.location}` });
  }
  for (const a of anomalies) {
    const points = Number.isFinite(a.points) ? a.points : 0;
    total += points;
    if (points > 0) byCategory[ANOMALY_CATEGORY] = (byCategory[ANOMALY_CATEGORY] || 0) + points;
    contributions.push({ source: 'anomaly', id: a.code, points, reason: a.message });
  }
  return {
    score: { total, flagThreshold: thresholds.flag, blockThreshold: thresholds.block, byCategory, contributions },
    verdict: verdictFor(total, thresholds),
  };
}

module.exports = { ANOMALY_CATEGORY, computeScore, verdictFor };
