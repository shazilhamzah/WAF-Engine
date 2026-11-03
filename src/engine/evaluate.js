'use strict';

const { excerpt, isSensitiveLocation, maskSecretsInString, MASK } = require('./redact');
const { findSuppressingException } = require('./exceptions');

const MAX_EVIDENCE = 25;
const FALSE = Object.freeze({ ok: false, ev: [] });

function targetLocation(t) {
  switch (t.name) {
    case 'header': return `header.${t.header}`;
    case 'user_agent': return 'header.user-agent';
    case 'content_type': return 'header.content-type';
    case 'body_size': return 'body';
    case 'path_raw': return 'path';
    case 'cookies': return 'cookie';
    case 'arg_names': return 'query_names';
    default: return t.name;
  }
}

function getFields(env, t) {
  const key = t.name === 'header' ? `header:${t.header}` : t.name;
  if (env.cache.has(key)) return env.cache.get(key);
  const f = env.fields;
  let out;
  switch (t.name) {
    case 'path': out = [f.path]; break;
    case 'path_raw': out = [f.pathRaw]; break;
    case 'query': out = f.query; break;
    case 'args': out = f.query.concat(f.bodyFields.length ? f.bodyFields : (f.body ? [f.body] : [])); break;
    case 'arg_names': out = f.queryNames.concat(f.bodyNames); break;
    case 'body': out = f.body ? [f.body] : []; break;
    case 'headers': out = [...f.headers.values()].filter((h) => h.name !== 'cookie'); break;
    case 'header': out = f.headers.has(t.header) ? [f.headers.get(t.header)] : []; break;
    case 'cookies': out = f.cookies; break;
    case 'method': out = [f.method]; break;
    case 'user_agent': out = f.headers.has('user-agent') ? [f.headers.get('user-agent')] : []; break;
    case 'content_type': out = f.headers.has('content-type') ? [f.headers.get('content-type')] : []; break;
    default: out = [];
  }
  env.cache.set(key, out);
  return out;
}

function lc(variant) {
  if (variant.lc === undefined) variant.lc = variant.value.toLowerCase();
  return variant.lc;
}

function makeTester(cond) {
  switch (cond.op) {
    case 'matches': {
      const flags = (cond.flags || '').replace(/[gy]/g, '');
      const re = new RegExp(cond.pattern, flags);
      return (v) => {
        const m = re.exec(v.value);
        return m ? { index: m.index, length: m[0].length } : null;
      };
    }
    case 'contains': {
      const needle = cond.value.toLowerCase();
      return (v) => {
        const i = lc(v).indexOf(needle);
        return i === -1 ? null : { index: i, length: needle.length };
      };
    }
    case 'startswith': {
      const needle = cond.value.toLowerCase();
      return (v) => (lc(v).startsWith(needle) ? { index: 0, length: needle.length } : null);
    }
    case 'endswith': {
      const needle = cond.value.toLowerCase();
      return (v) => {
        const s = lc(v);
        return s.endsWith(needle) ? { index: s.length - needle.length, length: needle.length } : null;
      };
    }
    case 'equals': {
      const needle = String(cond.value).toLowerCase();
      return (v) => (lc(v) === needle ? { index: 0, length: v.value.length } : null);
    }
    case 'in': {
      const set = new Set(cond.values.map((x) => String(x).toLowerCase()));
      return (v) => (set.has(lc(v)) ? { index: 0, length: v.value.length } : null);
    }
    default:
      return null;
  }
}

const NUMERIC = {
  gt: (a, b) => a > b,
  lt: (a, b) => a < b,
  ge: (a, b) => a >= b,
  le: (a, b) => a <= b,
};

function compileCondition(cond) {
  const numericOp = NUMERIC[cond.op];
  const tester = numericOp ? null : makeTester(cond);
  return (env) => {
    const ev = [];
    for (const t of cond.targets) {
      if (t.name === 'body_size') {
        const size = env.request.bodyBytes;
        let ok;
        if (numericOp) ok = numericOp(size, cond.value);
        else if (cond.op === 'equals') ok = size === Number(cond.value);
        else if (cond.op === 'in') ok = cond.values.map(Number).includes(size);
        else ok = false;
        if (ok) ev.push({ location: 'body', via: [], value: String(size), index: 0, length: 0, context: true, operator: cond.op });
        continue;
      }
      const fields = getFields(env, t);
      for (const field of fields) {
        if (numericOp) {
          if (numericOp(field.rawLength, cond.value)) {
            ev.push({ location: field.location, via: [], value: field.variants[0].value, index: 0, length: 0, context: false, operator: cond.op, lengthCheck: true });
          }
        } else {
          for (const variant of field.variants) {
            const hit = tester(variant);
            if (hit) {
              ev.push({
                location: field.location,
                via: variant.via,
                value: variant.value,
                index: hit.index,
                length: hit.length,
                context: t.name === 'method',
                operator: cond.op,
              });
              break;
            }
          }
        }
        if (ev.length >= MAX_EVIDENCE) return { ok: true, ev };
      }
    }
    return ev.length ? { ok: true, ev } : FALSE;
  };
}

function firstTarget(node) {
  if (node.type === 'cond') return node.targets[0];
  if (node.type === 'not') return firstTarget(node.expr);
  return firstTarget(node.left);
}

function compileExpression(node) {
  if (!node) throw new Error('empty expression');
  switch (node.type) {
    case 'cond':
      return compileCondition(node);
    case 'and': {
      const l = compileExpression(node.left);
      const r = compileExpression(node.right);
      return (env) => {
        const a = l(env);
        if (!a.ok) return FALSE;
        const b = r(env);
        if (!b.ok) return FALSE;
        return { ok: true, ev: a.ev.concat(b.ev) };
      };
    }
    case 'or': {
      const l = compileExpression(node.left);
      const r = compileExpression(node.right);
      return (env) => {
        const a = l(env);
        const b = r(env);
        if (!a.ok && !b.ok) return FALSE;
        return { ok: true, ev: (a.ok ? a.ev : []).concat(b.ok ? b.ev : []) };
      };
    }
    case 'not': {
      const inner = compileExpression(node.expr);
      const location = targetLocation(firstTarget(node.expr));
      return (env) => {
        const a = inner(env);
        if (a.ok) return FALSE;
        return { ok: true, ev: [{ location, via: [], value: '', index: 0, length: 0, context: true, operator: 'not' }] };
      };
    }
    default:
      throw new Error(`unknown node ${node.type}`);
  }
}

function evidenceExcerpt(item) {
  if (isSensitiveLocation(item.location)) return MASK;
  if (item.context && item.value === '') return '';
  const masked = maskSecretsInString(item.value, true);
  return excerpt(masked, item.index, item.length);
}

function evaluateRules(rules, request, exceptions) {
  const env = { request, fields: request.fields, cache: new Map() };
  const matches = [];
  const suppressed = [];
  let errors = 0;
  const list = Array.isArray(rules) ? rules : [];
  for (const rule of list) {
    if (!rule || typeof rule.test !== 'function') continue;
    let res;
    try {
      res = rule.test(env);
    } catch {
      errors++;
      continue;
    }
    if (!res || !res.ok) continue;
    const ev = res.ev;
    const valueEv = ev.filter((e) => !e.context);
    const primary = valueEv[0] || ev[0];
    const locations = [...new Set((valueEv.length ? valueEv : ev).map((e) => e.location))];
    // suppressed only when every matched location is covered by an approved exception
    let suppressedBy = null;
    if (Array.isArray(exceptions) && exceptions.length) {
      let allCovered = true;
      let firstId = null;
      for (const loc of locations) {
        const exc = findSuppressingException(exceptions, rule.id, loc, request);
        if (!exc) {
          allCovered = false;
          break;
        }
        if (!firstId) firstId = exc;
      }
      if (allCovered) suppressedBy = firstId;
    }
    const match = {
      ruleId: rule.id,
      ruleName: rule.name,
      ruleVersion: rule.version,
      severity: rule.severity,
      points: rule.score,
      category: rule.category,
      tags: rule.tags.slice(),
      location: primary.location,
      operator: primary.operator,
      excerpt: evidenceExcerpt(primary),
      decodedVia: primary.via.slice(),
      suppressedBy,
      locations: locations.slice(0, 10),
    };
    if (suppressedBy) suppressed.push(match);
    else matches.push(match);
  }
  return { matches, suppressed, errors };
}

module.exports = { compileExpression, evaluateRules, targetLocation };
