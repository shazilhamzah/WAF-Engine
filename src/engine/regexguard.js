'use strict';
/**
 * Static ReDoS guard for rule regexes (FR-2 "unsafe regexes refused").
 *
 * The pattern is parsed into a small tree (groups, alternatives, atoms, quantifiers) and rejected when
 * it contains a construct known to cause catastrophic (exponential or high-polynomial) backtracking:
 *
 *   R1 pattern longer than MAX_PATTERN_LENGTH characters
 *   R2 nested quantifiers: a repeated group that contains a repeated element, e.g. (a+)+, (\w*)*,
 *      (a+){2,9}. Bounded inner + bounded outer is allowed: (\d{1,3}\.){3}
 *   R3 overlapping alternation inside a repeated group: alternatives that can start with the same
 *      atom, e.g. (a|a)*, (ab|ac)+, (.|x)*, or an empty alternative (a|)*
 *   R4 backreferences inside a repeated group or themselves repeated, e.g. (a)\1+, ((a)\2)*
 *   R5 adjacent unbounded quantifiers over overlapping atoms, e.g. .*.*, \w+\w*, .*\s*
 *
 * The analysis is conservative: it may refuse some safe patterns; the error message explains how to
 * rewrite them (use bounded quantifiers such as {0,100} and non-overlapping character classes).
 */

const MAX_PATTERN_LENGTH = 500;

class GuardError extends Error {
  constructor(message, offset) {
    super(message);
    this.offset = offset;
  }
}

function parsePattern(src) {
  let i = 0;
  const peek = () => src[i];

  function parseQuantifier() {
    const c = src[i];
    let q = null;
    if (c === '*') q = { min: 0, max: Infinity, len: 1 };
    else if (c === '+') q = { min: 1, max: Infinity, len: 1 };
    else if (c === '?') q = { min: 0, max: 1, len: 1 };
    else if (c === '{') {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i));
      if (m) {
        const min = Number(m[1]);
        const max = m[2] === undefined ? min : (m[3] === '' ? Infinity : Number(m[3]));
        q = { min, max, len: m[0].length };
      }
    }
    if (!q) return null;
    q.offset = i;
    i += q.len;
    if (src[i] === '?') i++; // lazy modifier
    return q;
  }

  function parseClass() {
    const start = i;
    i++; // [
    if (src[i] === '^') i++;
    if (src[i] === ']') i++;
    while (i < src.length && src[i] !== ']') {
      if (src[i] === '\\') i++;
      i++;
    }
    i++; // ]
    const text = src.slice(start, i);
    return { type: 'class', key: text, negated: text.startsWith('[^'), offset: start };
  }

  function parseEscape() {
    const start = i;
    i++; // backslash
    const c = src[i];
    if (c === undefined) return { type: 'char', key: '\\', offset: start };
    if (/[1-9]/.test(c)) {
      while (/[0-9]/.test(src[i] || '')) i++;
      return { type: 'backref', key: src.slice(start, i), offset: start };
    }
    if (c === 'k' && src[i + 1] === '<') {
      const end = src.indexOf('>', i);
      i = end === -1 ? src.length : end + 1;
      return { type: 'backref', key: src.slice(start, i), offset: start };
    }
    if ((c === 'p' || c === 'P') && src[i + 1] === '{') {
      const end = src.indexOf('}', i);
      i = end === -1 ? src.length : end + 1;
      return { type: 'char', key: src.slice(start, i), offset: start };
    }
    if (c === 'u' && src[i + 1] === '{') {
      const end = src.indexOf('}', i);
      i = end === -1 ? src.length : end + 1;
      return { type: 'char', key: src.slice(start, i), offset: start };
    }
    if (c === 'u') i += 5;
    else if (c === 'x') i += 3;
    else if (c === 'c') i += 2;
    else i += 1;
    const key = src.slice(start, i);
    if (key === '\\b' || key === '\\B') return { type: 'anchor', key, offset: start };
    return { type: 'char', key, offset: start };
  }

  function parseGroup() {
    const start = i;
    i++; // (
    let capture = true;
    let lookaround = false;
    if (src[i] === '?') {
      capture = false;
      if (src[i + 1] === ':') i += 2;
      else if (src[i + 1] === '=' || src[i + 1] === '!') {
        lookaround = true;
        i += 2;
      } else if (src[i + 1] === '<' && (src[i + 2] === '=' || src[i + 2] === '!')) {
        lookaround = true;
        i += 3;
      } else if (src[i + 1] === '<') {
        capture = true;
        const end = src.indexOf('>', i);
        i = end === -1 ? src.length : end + 1;
      } else i += 1;
    }
    const alts = parseAlternation();
    if (src[i] === ')') i++;
    return { type: 'group', alts, capture, lookaround, offset: start };
  }

  function parseAtom() {
    const c = peek();
    if (c === '(') return parseGroup();
    if (c === '[') return parseClass();
    if (c === '\\') return parseEscape();
    const start = i;
    i++;
    if (c === '.') return { type: 'any', key: '.', offset: start };
    if (c === '^' || c === '$') return { type: 'anchor', key: c, offset: start };
    return { type: 'char', key: c, offset: start };
  }

  function parseSequence() {
    const nodes = [];
    while (i < src.length && src[i] !== '|' && src[i] !== ')') {
      const atom = parseAtom();
      atom.quant = parseQuantifier();
      nodes.push(atom);
    }
    return nodes;
  }

  function parseAlternation() {
    const alts = [parseSequence()];
    while (src[i] === '|') {
      i++;
      alts.push(parseSequence());
    }
    return alts;
  }

  const alts = parseAlternation();
  return { type: 'group', alts, capture: false, offset: 0, quant: null };
}

/** Summary of the quantifiers inside a node: any repetition (max > 1), any unbounded repetition. */
function innerQuantifiers(node) {
  let repeated = false;
  let unbounded = false;
  const walk = (n) => {
    if (n.quant && n.quant.max > 1) {
      repeated = true;
      if (n.quant.max === Infinity) unbounded = true;
    }
    if (n.type === 'group') for (const alt of n.alts) for (const child of alt) walk(child);
  };
  if (node.type === 'group') for (const alt of node.alts) for (const child of alt) walk(child);
  return { repeated, unbounded };
}

function firstKey(seq) {
  for (const n of seq) {
    if (n.type === 'anchor') continue;
    if (n.type === 'group') {
      if (n.lookaround) continue;
      const keys = n.alts.map(firstKey);
      return keys.length === 1 ? keys[0] : `(${keys.join('|')})`;
    }
    return n.key;
  }
  return '';
}

function overlaps(a, b) {
  if (!a || !b) return false;
  if (a.type === 'any' || b.type === 'any') return true;
  if ((a.type === 'class' && a.negated) || (b.type === 'class' && b.negated)) return true;
  return a.key === b.key;
}

function check(node, repeatDepth) {
  const q = node.quant;
  const repeated = Boolean(q && q.max > 1);
  if (node.type === 'backref' && (repeatDepth > 0 || repeated)) {
    throw new GuardError('backreference inside a repetition is not allowed (exponential backtracking risk)', node.offset);
  }
  if (node.type !== 'group') return;
  if (repeated) {
    const inner = innerQuantifiers(node);
    if ((q.max === Infinity && inner.repeated) || inner.unbounded) {
      throw new GuardError('nested quantifiers such as (a+)+ are not allowed (catastrophic backtracking risk); use a single bounded quantifier', node.offset);
    }
    if (node.alts.length > 1) {
      const keys = node.alts.map(firstKey);
      const seen = new Set();
      for (const k of keys) {
        if (k === '' || k === '.' || seen.has(k)) {
          throw new GuardError('overlapping alternatives inside a repeated group such as (a|a)* are not allowed; make the alternatives start differently', node.offset);
        }
        seen.add(k);
      }
    }
  }
  for (const alt of node.alts) {
    for (let j = 0; j < alt.length; j++) {
      const cur = alt[j];
      const prev = alt[j - 1];
      if (prev && prev.quant && cur.quant && prev.quant.max === Infinity && cur.quant.max === Infinity
        && prev.type !== 'group' && cur.type !== 'group' && overlaps(prev, cur)) {
        throw new GuardError('adjacent unbounded quantifiers over overlapping characters (e.g. .*.* or \\w+\\w*) are not allowed', cur.offset);
      }
      check(cur, repeatDepth + (repeated ? 1 : 0));
    }
  }
}

/**
 * @param {string} source regex source (without slashes)
 * @returns {{ ok: boolean, message: string|null, offset: number }}
 */
function checkRegexSafety(source) {
  if (typeof source !== 'string') return { ok: false, message: 'pattern must be a string', offset: 0 };
  if (source.length > MAX_PATTERN_LENGTH) {
    return { ok: false, message: `pattern is longer than ${MAX_PATTERN_LENGTH} characters`, offset: MAX_PATTERN_LENGTH };
  }
  try {
    const tree = parsePattern(source);
    check(tree, 0);
    return { ok: true, message: null, offset: 0 };
  } catch (err) {
    if (err instanceof GuardError) return { ok: false, message: err.message, offset: err.offset || 0 };
    return { ok: false, message: 'pattern could not be analysed', offset: 0 };
  }
}

module.exports = { MAX_PATTERN_LENGTH, checkRegexSafety, parsePattern };
