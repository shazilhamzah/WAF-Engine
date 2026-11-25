// Diff helpers for the config confirmation dialog and the event compare view (pure).

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** { a: { b: 1 } } → { 'a.b': 1 }. Arrays are leaf values. */
export function flatten(obj, prefix = '', out = {}) {
  if (!isPlainObject(obj)) {
    if (prefix) out[prefix] = obj;
    return out;
  }
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (isPlainObject(v)) flatten(v, key, out);
    else out[key] = v;
  }
  return out;
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Leaf-level differences between two objects: [{ path, from, to }] sorted by path. */
export function diffObjects(before, after) {
  const a = flatten(before || {});
  const b = flatten(after || {});
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  const out = [];
  for (const k of keys) {
    if (!same(a[k], b[k])) out.push({ path: k, from: a[k], to: b[k] });
  }
  return out;
}

export function displayValue(v) {
  if (v === undefined) return '(unset)';
  if (v === null) return '—';
  if (Array.isArray(v)) return v.length ? v.join(', ') : '—';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function ruleIds(matches) {
  return [...new Set((matches || []).map((m) => m && m.ruleId).filter((x) => x !== undefined && x !== null))]
    .map(String).sort();
}

function dec(evt) {
  return (evt && evt.decision) || {};
}

/**
 * Rows for the side-by-side compare table:
 * [{ field, label, a, b, changed, informational }]
 * `informational` rows (ids, timestamps) always differ and are not counted as changes.
 */
export function compareEventRows(a, b) {
  const da = dec(a);
  const db = dec(b);
  const sa = da.score || {};
  const sb = db.score || {};
  const ea = da.engine || {};
  const eb = db.engine || {};
  const rows = [
    ['id', 'Event id', a && a.id, b && b.id, true],
    ['ts', 'Time', a && a.ts, b && b.ts, true],
    ['source', 'Source', a && a.source, b && b.source],
    ['label', 'Label', a && a.label, b && b.label],
    ['request', 'Request', a && `${a.method} ${a.path}`, b && `${b.method} ${b.path}`],
    ['verdict', 'Verdict', (a && a.verdict) || da.verdict, (b && b.verdict) || db.verdict],
    ['action', 'Action', (a && a.action) || da.action, (b && b.action) || db.action],
    ['wouldBlock', 'Would block', da.wouldBlock, db.wouldBlock],
    ['statusCode', 'Status code', da.statusCode, db.statusCode],
    ['blockReason', 'Block reason', da.blockReason, db.blockReason],
    ['score', 'Score', sa.total !== undefined ? sa.total : (a && a.score), sb.total !== undefined ? sb.total : (b && b.score)],
    ['thresholds', 'Thresholds (flag / block)', `${displayValue(sa.flagThreshold)} / ${displayValue(sa.blockThreshold)}`, `${displayValue(sb.flagThreshold)} / ${displayValue(sb.blockThreshold)}`],
    ['byCategory', 'Score by category', sa.byCategory || {}, sb.byCategory || {}],
    ['mode', 'Mode', da.mode || (a && a.mode), db.mode || (b && b.mode)],
    ['rules', 'Matched rules', ruleIds(da.matches), ruleIds(db.matches)],
    ['suppressed', 'Suppressed by exceptions', ruleIds(da.suppressed), ruleIds(db.suppressed)],
    ['anomalies', 'Anomalies', (da.anomalies || []).map((x) => x.code).sort(), (db.anomalies || []).map((x) => x.code).sort()],
    ['rulesetVersion', 'Ruleset version', (a && a.rulesetVersion) || ea.rulesetVersion, (b && b.rulesetVersion) || eb.rulesetVersion],
    ['configVersion', 'Config version', (a && a.configVersion) || ea.configVersion, (b && b.configVersion) || eb.configVersion],
    ['engineVersion', 'Engine version', ea.engineVersion, eb.engineVersion],
    ['replayOf', 'Replay of', a && a.replayOf, b && b.replayOf, true],
  ];
  return rows.map(([field, label, va, vb, informational]) => ({
    field, label, a: va, b: vb,
    informational: Boolean(informational),
    changed: !informational && !same(va === undefined ? null : va, vb === undefined ? null : vb),
  }));
}

/** Human-readable summary lines from the server's compare diff object. */
export function summarizeDiff(diff, a, b) {
  if (!diff) return [];
  const out = [];
  const va = (a && a.verdict) || '?';
  const vb = (b && b.verdict) || '?';
  out.push(diff.verdictChanged ? `Verdict changed: ${va} → ${vb}` : `Verdict unchanged (${va})`);
  if (diff.actionChanged) out.push(`Action changed: ${(a && a.action) || '?'} → ${(b && b.action) || '?'}`);
  const delta = Number(diff.scoreDelta) || 0;
  out.push(delta === 0 ? 'Score unchanged' : `Score ${delta > 0 ? '+' : ''}${delta}`);
  if (Array.isArray(diff.rulesAdded) && diff.rulesAdded.length) out.push(`Rules added in B: ${diff.rulesAdded.join(', ')}`);
  if (Array.isArray(diff.rulesRemoved) && diff.rulesRemoved.length) out.push(`Rules no longer matching in B: ${diff.rulesRemoved.join(', ')}`);
  out.push(diff.rulesetChanged ? 'Ruleset version changed' : 'Same ruleset version');
  out.push(diff.configChanged ? 'Configuration version changed' : 'Same configuration version');
  return out;
}
