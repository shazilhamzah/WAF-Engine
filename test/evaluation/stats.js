'use strict';
/** Small, dependency-free statistics + text-sanitising helpers for the evaluation harness. */

/** Nearest-rank percentile (p in 0..100) of a numeric array. */
function percentile(values, p) {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * s.length);
  return s[Math.min(s.length - 1, Math.max(0, rank - 1))];
}

function mean(values) {
  if (!values.length) return null;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function summarize(values) {
  return {
    n: values.length,
    mean: round(mean(values)),
    p50: round(percentile(values, 50)),
    p95: round(percentile(values, 95)),
    p99: round(percentile(values, 99)),
    min: round(values.length ? Math.min(...values) : null),
    max: round(values.length ? Math.max(...values) : null)
  };
}

function round(x, d = 3) {
  if (x === null || x === undefined || Number.isNaN(x)) return null;
  const f = 10 ** d;
  return Math.round(x * f) / f;
}

/**
 * Binary-classification metrics. tp/fp/tn/fn counts → precision, recall, F1, FPR, accuracy.
 */
function classification({ tp, fp, tn, fn }) {
  const div = (a, b) => (b === 0 ? null : round(a / b, 4));
  const precision = div(tp, tp + fp);
  const recall = div(tp, tp + fn);
  const f1 = precision !== null && recall !== null && precision + recall > 0 ? round((2 * precision * recall) / (precision + recall), 4) : null;
  return { tp, fp, tn, fn, precision, recall, f1, falsePositiveRate: div(fp, fp + tn), accuracy: div(tp + tn, tp + tn + fp + fn) };
}

/** Makes untrusted input safe & short for reports: escapes control chars, truncates. */
function sanitize(value, max = 120) {
  if (value === null || value === undefined) return '';
  let s = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  s = s.replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
  if (s.length > max) s = s.slice(0, max) + `… (+${s.length - max} chars)`;
  return s;
}

/** Escapes text for use inside a Markdown table cell rendered as inline HTML code. */
function mdCode(value, max = 80) {
  const s = sanitize(value, max)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\|/g, '&#124;').replace(/`/g, '&#96;').replace(/\*/g, '&#42;').replace(/_/g, '&#95;')
    .replace(/\[/g, '&#91;').replace(/\]/g, '&#93;');
  return s ? `<code>${s}</code>` : '';
}

/** Escapes plain text for a Markdown table cell. */
function mdText(value, max = 160) {
  return sanitize(value, max).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\|/g, '&#124;');
}

module.exports = { percentile, mean, summarize, round, classification, sanitize, mdCode, mdText };
