'use strict';

const crypto = require('node:crypto');
const { checkRegexSafety, MAX_PATTERN_LENGTH } = require('./regexguard');
const { compileExpression } = require('./evaluate');

const MAX_RULE_SOURCE = 10000;
const MAX_FILE_SOURCE = 1048576;
const MAX_STRING = 1000;
const MAX_LIST = 200;
const MAX_DEPTH = 32;
const MAX_CONDITIONS = 64;
const MIN_ID = 1000;
const MAX_ID = 999999;

const SEVERITIES = ['low', 'medium', 'high', 'critical'];
const CLAUSES = ['when', 'severity', 'score', 'category', 'tags', 'description'];
const REQUIRED = ['when', 'severity', 'score', 'category'];
const TARGETS = Object.freeze({
  path: 'string', path_raw: 'string', query: 'string', args: 'string', arg_names: 'string', body: 'string',
  headers: 'string', header: 'string', cookies: 'string', method: 'string', user_agent: 'string',
  content_type: 'string', body_size: 'number',
});
const OPERATORS = Object.freeze({
  matches: 'regex', contains: 'string', equals: 'scalar', startswith: 'string', endswith: 'string',
  in: 'list', gt: 'number', lt: 'number', ge: 'number', le: 'number',
});
const KEYWORDS = new Set(['rule', 'and', 'or', 'not', ...CLAUSES, ...Object.keys(OPERATORS)]);

class DslError extends Error {
  constructor(message, line, col) {
    super(message);
    this.line = line;
    this.col = col;
  }
}

const IDENT_START = /[A-Za-z_]/;
const IDENT_PART = /[A-Za-z0-9_-]/;

function tokenize(src) {
  const tokens = [];
  let i = 0;
  let line = 1;
  let col = 1;
  const advance = (n = 1) => {
    for (let k = 0; k < n; k++) {
      if (src[i] === '\n') {
        line++;
        col = 1;
      } else col++;
      i++;
    }
  };
  const lastSignificant = () => tokens[tokens.length - 1];
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f' || c === '\v' || c === '﻿') {
      advance();
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') advance();
      continue;
    }
    const tok = { line, col, start: i };
    if (IDENT_START.test(c)) {
      let j = i;
      while (j < src.length && IDENT_PART.test(src[j])) j++;
      tok.type = 'ident';
      tok.value = src.slice(i, j);
      advance(j - i);
    } else if (/[0-9]/.test(c) || (c === '-' && /[0-9]/.test(src[i + 1] || ''))) {
      let j = i + 1;
      while (j < src.length && /[0-9]/.test(src[j])) j++;
      if (j < src.length && IDENT_PART.test(src[j]) && src[j] !== '-') {
        throw new DslError(`Invalid number '${src.slice(i, j + 1)}'`, line, col);
      }
      tok.type = 'number';
      tok.text = src.slice(i, j);
      tok.value = Number(tok.text);
      advance(j - i);
    } else if (c === '"') {
      let j = i + 1;
      let value = '';
      for (;;) {
        if (j >= src.length || src[j] === '\n' || src[j] === '\r') throw new DslError('Unterminated string (missing closing ")', line, col);
        const ch = src[j];
        if (ch === '"') break;
        if (ch === '\\') {
          const n = src[j + 1];
          const map = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\' };
          if (n === undefined || !(n in map)) {
            throw new DslError(`Unknown escape '\\${n || ''}' in string (allowed: \\" \\\\ \\n \\t \\r)`, line, col + (j - i));
          }
          value += map[n];
          j += 2;
          continue;
        }
        value += ch;
        j++;
      }
      tok.type = 'string';
      tok.value = value;
      advance(j + 1 - i);
    } else if (c === '/' && lastSignificant() && lastSignificant().type === 'ident') {
      // a regex after a word still lexes so the parser can report a misspelt operator
      let j = i + 1;
      let inClass = false;
      for (;;) {
        if (j >= src.length || src[j] === '\n' || src[j] === '\r') throw new DslError('Unterminated regular expression (missing closing /)', line, col);
        const ch = src[j];
        if (ch === '\\') {
          j += 2;
          continue;
        }
        if (ch === '[') inClass = true;
        else if (ch === ']') inClass = false;
        else if (ch === '/' && !inClass) break;
        j++;
      }
      const pattern = src.slice(i + 1, j);
      let k = j + 1;
      while (k < src.length && /[A-Za-z]/.test(src[k])) k++;
      tok.type = 'regex';
      tok.value = pattern;
      tok.flags = src.slice(j + 1, k);
      tok.patternCol = col + 1;
      advance(k - i);
    } else if ('{}()[],:'.includes(c)) {
      tok.type = 'punct';
      tok.value = c;
      advance();
    } else if (c === '/') {
      throw new DslError("Unexpected '/': a regular expression is only allowed after 'matches'", line, col);
    } else {
      const shown = c < ' ' ? `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}` : c;
      throw new DslError(`Unexpected character '${shown}'`, line, col);
    }
    tok.end = i;
    tokens.push(tok);
  }
  tokens.push({ type: 'eof', value: null, line, col, start: i, end: i });
  return tokens;
}

function describe(tok) {
  if (!tok || tok.type === 'eof') return 'end of input';
  if (tok.type === 'string') return 'a string';
  if (tok.type === 'regex') return 'a regular expression';
  if (tok.type === 'number') return `number ${tok.text}`;
  return `'${tok.value}'`;
}

function closest(word, options) {
  const w = String(word).toLowerCase();
  let best = null;
  let bestD = Infinity;
  for (const o of options) {
    const d = levenshtein(w, o);
    if (d < bestD) {
      bestD = d;
      best = o;
    }
  }
  return bestD <= 2 ? best : null;
}

function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 3) return 99;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

function hint(word, options) {
  const c = closest(word, options);
  return c ? ` — did you mean '${c}'?` : '';
}

function parseRuleAt(tokens, pos, errors) {
  let p = pos;
  const peek = () => tokens[p];
  const next = () => tokens[p++];
  const fail = (tok, msg) => {
    throw new DslError(msg, tok.line, tok.col);
  };
  const semantic = (tok, msg) => errors.push({ line: tok.line, col: tok.col, message: msg });
  const expectPunct = (ch, context) => {
    const t = next();
    if (t.type !== 'punct' || t.value !== ch) fail(t, `Expected '${ch}' ${context} but found ${describe(t)}`);
    return t;
  };

  const ruleTok = next();
  if (ruleTok.type !== 'ident' || ruleTok.value !== 'rule') {
    fail(ruleTok, `Expected 'rule' to start a rule but found ${describe(ruleTok)}${ruleTok.type === 'ident' ? hint(ruleTok.value, ['rule']) : ''}`);
  }
  const idTok = next();
  if (idTok.type !== 'number') fail(idTok, `Expected a numeric rule id after 'rule' but found ${describe(idTok)}`);
  if (!Number.isSafeInteger(idTok.value) || idTok.value < MIN_ID || idTok.value > MAX_ID) {
    semantic(idTok, `Rule id must be an integer between ${MIN_ID} and ${MAX_ID} (got ${idTok.text})`);
  }
  const nameTok = next();
  if (nameTok.type !== 'string') fail(nameTok, `Expected the rule name in double quotes after the id but found ${describe(nameTok)}`);
  const name = nameTok.value;
  if (name.trim().length === 0 || name.length > 100) semantic(nameTok, 'Rule name must be 1 to 100 characters');
  else if (/[\u0000-\u001f\u007f]/.test(name)) semantic(nameTok, 'Rule name must not contain control characters');
  const open = expectPunct('{', 'after the rule name');

  const rule = {
    id: idTok.value, name, severity: null, score: null, category: null, tags: [], description: '', when: null,
    positions: { rule: ruleTok, id: idTok, open },
  };
  const seen = new Map();
  let conditions = 0;

  function parseExpr(depth) {
    return parseOr(depth);
  }
  function parseOr(depth) {
    let left = parseAnd(depth);
    while (peek().type === 'ident' && peek().value === 'or') {
      next();
      left = { type: 'or', left, right: parseAnd(depth) };
    }
    return left;
  }
  function parseAnd(depth) {
    let left = parseNot(depth);
    while (peek().type === 'ident' && peek().value === 'and') {
      next();
      left = { type: 'and', left, right: parseNot(depth) };
    }
    return left;
  }
  function parseNot(depth) {
    if (depth > MAX_DEPTH) fail(peek(), `Expression is nested too deeply (more than ${MAX_DEPTH} levels)`);
    const t = peek();
    if (t.type === 'ident' && t.value === 'not') {
      next();
      return { type: 'not', expr: parseNot(depth + 1) };
    }
    if (t.type === 'punct' && t.value === '(') {
      next();
      const inner = parseExpr(depth + 1);
      expectPunct(')', 'to close the parenthesis');
      return inner;
    }
    return parseCondition();
  }
  function parseTarget() {
    const t = next();
    if (t.type !== 'ident') fail(t, `Expected a target (e.g. args, path, header:<name>) but found ${describe(t)}`);
    if (!Object.prototype.hasOwnProperty.call(TARGETS, t.value)) {
      fail(t, `Unknown target '${t.value}'${hint(t.value, Object.keys(TARGETS))} (targets: ${Object.keys(TARGETS).join(', ')})`);
    }
    const target = { name: t.value, type: TARGETS[t.value], tok: t };
    if (t.value === 'header') {
      const colon = peek();
      if (colon.type !== 'punct' || colon.value !== ':') fail(colon, "Expected ':' and a header name after 'header' (e.g. header:referer)");
      next();
      const h = next();
      if (h.type !== 'ident') fail(h, `Expected a header name after 'header:' but found ${describe(h)}`);
      target.header = h.value.toLowerCase();
    }
    return target;
  }
  function parseCondition() {
    const first = peek();
    const targets = [parseTarget()];
    while (peek().type === 'punct' && peek().value === ',') {
      next();
      targets.push(parseTarget());
    }
    const opTok = next();
    if (opTok.type !== 'ident' || !Object.prototype.hasOwnProperty.call(OPERATORS, opTok.value)) {
      const word = opTok.type === 'ident' ? opTok.value : '';
      fail(opTok, `Unknown operator ${describe(opTok)}${word ? hint(word, Object.keys(OPERATORS)) : ''} (operators: ${Object.keys(OPERATORS).join(', ')})`);
    }
    const op = opTok.value;
    const kind = OPERATORS[op];
    const cond = { type: 'cond', op, targets, line: first.line, col: first.col };
    conditions++;
    if (conditions > MAX_CONDITIONS) semantic(first, `A rule may contain at most ${MAX_CONDITIONS} conditions`);
    const numericTargets = targets.filter((t) => t.type === 'number');
    const stringTargets = targets.filter((t) => t.type === 'string');

    if (kind === 'regex') {
      const rt = next();
      if (rt.type !== 'regex') fail(rt, `Expected a regular expression like /pattern/i after 'matches' but found ${describe(rt)}`);
      cond.pattern = rt.value;
      cond.flags = rt.flags;
      cond.regexTok = rt;
      validateRegex(rt, semantic);
    } else if (kind === 'string') {
      const st = next();
      if (st.type !== 'string') fail(st, `Expected a string in double quotes after '${op}' but found ${describe(st)}`);
      if (st.value.length === 0) semantic(st, `The value for '${op}' must not be empty`);
      if (st.value.length > MAX_STRING) semantic(st, `String is longer than ${MAX_STRING} characters`);
      cond.value = st.value;
    } else if (kind === 'scalar') {
      const st = next();
      if (st.type !== 'string' && st.type !== 'number') fail(st, `Expected a string or number after 'equals' but found ${describe(st)}`);
      if (st.type === 'string' && st.value.length > MAX_STRING) semantic(st, `String is longer than ${MAX_STRING} characters`);
      if (st.type === 'number' && stringTargets.length) semantic(st, `'equals' with a number needs a numeric target (body_size); use "${st.text}" to compare text`);
      if (st.type === 'string' && numericTargets.length) semantic(st, "'equals' on body_size needs a number, not a string");
      cond.value = st.type === 'number' ? st.value : st.value;
      cond.valueType = st.type;
    } else if (kind === 'list') {
      const lb = next();
      if (lb.type !== 'punct' || lb.value !== '[') fail(lb, `Expected '[' after 'in' but found ${describe(lb)}`);
      const items = [];
      let itemType = null;
      for (;;) {
        const it = next();
        if (it.type === 'punct' && it.value === ']' && items.length === 0) fail(it, "The list after 'in' must not be empty");
        if (it.type !== 'string' && it.type !== 'number') fail(it, `Expected a string or number in the list but found ${describe(it)}`);
        if (itemType && it.type !== itemType) semantic(it, 'All list items must have the same type');
        itemType = it.type;
        items.push(it.value);
        const sep = next();
        if (sep.type === 'punct' && sep.value === ']') break;
        if (sep.type !== 'punct' || sep.value !== ',') fail(sep, `Expected ',' or ']' in the list but found ${describe(sep)}`);
      }
      if (items.length > MAX_LIST) semantic(lb, `A list may contain at most ${MAX_LIST} items`);
      if (itemType === 'number' && stringTargets.length) semantic(lb, 'A list of numbers needs a numeric target (body_size)');
      if (itemType === 'string' && numericTargets.length) semantic(lb, 'body_size can only be compared with numbers');
      cond.values = items;
      cond.valueType = itemType;
    } else if (kind === 'number') {
      const nt = next();
      if (nt.type !== 'number') fail(nt, `Expected a number after '${op}' but found ${describe(nt)}`);
      if (!Number.isSafeInteger(nt.value) || nt.value < 0) semantic(nt, `The value for '${op}' must be a non-negative integer`);
      cond.value = nt.value;
    }
    if (numericTargets.length && (kind === 'regex' || kind === 'string')) {
      semantic(opTok, `Operator '${op}' cannot be used with the numeric target body_size (use equals, in, gt, lt, ge or le)`);
    }
    return cond;
  }

  for (;;) {
    const t = next();
    if (t.type === 'punct' && t.value === '}') {
      rule.positions.close = t;
      break;
    }
    if (t.type === 'eof') fail(t, `Missing '}' to close rule ${idTok.text} (opened at line ${open.line}, column ${open.col})`);
    if (t.type !== 'ident' || !CLAUSES.includes(t.value)) {
      const word = t.type === 'ident' ? t.value : '';
      if (word === 'rule') fail(t, `Missing '}' before the next rule (rule ${idTok.text} opened at line ${open.line}, column ${open.col})`);
      fail(t, `Unknown keyword ${describe(t)}${word ? hint(word, CLAUSES) : ''} (expected one of: ${CLAUSES.join(', ')})`);
    }
    if (seen.has(t.value)) semantic(t, `Duplicate '${t.value}' clause (first given at line ${seen.get(t.value).line})`);
    seen.set(t.value, t);
    switch (t.value) {
      case 'when':
        rule.when = parseExpr(0);
        break;
      case 'severity': {
        const v = next();
        if (v.type !== 'ident') fail(v, `Expected a severity (${SEVERITIES.join(', ')}) but found ${describe(v)}`);
        if (!SEVERITIES.includes(v.value)) semantic(v, `Unknown severity '${v.value}'${hint(v.value, SEVERITIES)} (allowed: ${SEVERITIES.join(', ')})`);
        rule.severity = v.value;
        break;
      }
      case 'score': {
        const v = next();
        if (v.type !== 'number') fail(v, `Expected a score (integer 0-100) but found ${describe(v)}`);
        if (!Number.isInteger(v.value) || v.value < 0 || v.value > 100) semantic(v, `Score must be an integer between 0 and 100 (got ${v.text})`);
        rule.score = v.value;
        break;
      }
      case 'category': {
        const v = next();
        if (v.type !== 'ident') fail(v, `Expected a category word (e.g. sqli) but found ${describe(v)}`);
        if (!/^[a-z][a-z0-9_-]{0,31}$/.test(v.value)) semantic(v, 'Category must be lower-case letters, digits, _ or - (max 32 characters)');
        rule.category = v.value;
        break;
      }
      case 'tags': {
        for (;;) {
          const v = next();
          if (v.type !== 'ident' && v.type !== 'number') fail(v, `Expected a tag word but found ${describe(v)}`);
          const tag = String(v.type === 'number' ? v.text : v.value);
          if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/.test(tag)) semantic(v, 'Tags must be letters, digits, _ . or - (max 40 characters)');
          rule.tags.push(tag);
          if (peek().type === 'punct' && peek().value === ',') {
            next();
            continue;
          }
          break;
        }
        if (rule.tags.length > 16) semantic(t, 'A rule may have at most 16 tags');
        break;
      }
      case 'description': {
        const v = next();
        if (v.type !== 'string') fail(v, `Expected the description in double quotes but found ${describe(v)}`);
        if (v.value.length > 500) semantic(v, 'Description must be at most 500 characters');
        rule.description = v.value;
        break;
      }
      default:
        break;
    }
  }
  for (const req of REQUIRED) {
    if (!seen.has(req)) {
      const at = rule.positions.close;
      errors.push({ line: at.line, col: at.col, message: `Missing required '${req}' clause in rule ${idTok.text}` });
    }
  }
  return { rule, next: p };
}

function validateRegex(tok, semantic) {
  const flags = tok.flags || '';
  const at = { line: tok.line, col: tok.col };
  for (const f of flags) {
    if (!'imsu'.includes(f)) {
      semantic(at, `Regex flag '${f}' is not allowed (allowed flags: i, m, s, u)`);
      return;
    }
  }
  if (new Set(flags).size !== flags.length) {
    semantic(at, 'Regex flags must not repeat');
    return;
  }
  if (tok.value.length === 0) {
    semantic(at, 'Regular expression must not be empty');
    return;
  }
  if (tok.value.length > MAX_PATTERN_LENGTH) {
    semantic(at, `Regular expression is longer than ${MAX_PATTERN_LENGTH} characters`);
    return;
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(tok.value, flags);
  } catch (err) {
    const msg = String(err && err.message ? err.message : err).replace(/^Invalid regular expression: /, '');
    semantic(at, `Invalid regular expression: ${msg.slice(0, 200)}`);
    return;
  }
  const safety = checkRegexSafety(tok.value);
  if (!safety.ok) {
    semantic({ line: tok.line, col: (tok.patternCol || tok.col + 1) + safety.offset }, `Unsafe regular expression: ${safety.message}`);
  }
}

function collectMeta(rule) {
  const targets = new Set();
  const operators = new Set();
  const walk = (n) => {
    if (!n) return;
    if (n.type === 'cond') {
      for (const t of n.targets) targets.add(t.header ? `header:${t.header}` : t.name);
      operators.add(n.op);
    } else if (n.type === 'not') walk(n.expr);
    else {
      walk(n.left);
      walk(n.right);
    }
  };
  walk(rule.when);
  return {
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    score: rule.score,
    category: rule.category,
    tags: rule.tags.slice(),
    description: rule.description,
    targets: [...targets],
    operators: [...operators],
  };
}

function sortErrors(errors) {
  return errors.sort((a, b) => (a.line - b.line) || (a.col - b.col));
}

function validateRuleSource(src) {
  const res = parseOne(src);
  if (!res.ok) return { ok: false, rule: null, errors: res.errors };
  const rule = collectMeta(res.ast);
  Object.defineProperty(rule, 'ast', { value: res.ast, enumerable: false });
  return { ok: true, rule, errors: [] };
}

function parseOne(src) {
  if (typeof src !== 'string') return { ok: false, errors: [{ line: 1, col: 1, message: 'Rule source must be a string' }] };
  if (src.length > MAX_RULE_SOURCE) {
    return { ok: false, errors: [{ line: 1, col: 1, message: `Rule source is longer than ${MAX_RULE_SOURCE} characters` }] };
  }
  if (src.trim() === '') return { ok: false, errors: [{ line: 1, col: 1, message: 'Rule source is empty' }] };
  const errors = [];
  let ast = null;
  try {
    const tokens = tokenize(src);
    const { rule, next } = parseRuleAt(tokens, 0, errors);
    ast = rule;
    const after = tokens[next];
    if (after.type !== 'eof') {
      errors.push({ line: after.line, col: after.col, message: `Unexpected ${describe(after)} after the end of the rule (one rule per record; use a .rules file for several)` });
    }
  } catch (err) {
    if (err instanceof DslError) errors.push({ line: err.line, col: err.col, message: err.message });
    else errors.push({ line: 1, col: 1, message: 'Rule could not be parsed' });
  }
  if (errors.length) return { ok: false, errors: sortErrors(errors) };
  return { ok: true, ast, errors };
}

function parseRuleFile(text) {
  const rules = [];
  const errors = [];
  if (typeof text !== 'string') return { rules, errors: [{ ruleId: null, line: 1, col: 1, message: 'Rule file must be text' }] };
  if (text.length > MAX_FILE_SOURCE) return { rules, errors: [{ ruleId: null, line: 1, col: 1, message: `Rule file is larger than ${MAX_FILE_SOURCE} characters` }] };
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  const starts = [];
  lines.forEach((l, idx) => {
    if (/^\s*rule\b/.test(l)) starts.push(idx);
  });
  // text before the first rule may only be comments or blank lines
  const preambleEnd = starts.length ? starts[0] : lines.length;
  for (let k = 0; k < preambleEnd; k++) {
    const t = lines[k].trim();
    if (t && !t.startsWith('#')) {
      errors.push({ ruleId: null, line: k + 1, col: lines[k].indexOf(t[0]) + 1, message: "Expected 'rule' to start a rule (only comments may appear outside rules)" });
      break;
    }
  }
  const ids = new Map();
  starts.forEach((startLine, n) => {
    const endLine = n + 1 < starts.length ? starts[n + 1] : lines.length;
    let chunkLines = lines.slice(startLine, endLine);
    // drop trailing blank and comment lines since they usually introduce the next rule
    while (chunkLines.length > 1 && /^\s*(#.*)?$/.test(chunkLines[chunkLines.length - 1])) chunkLines.pop();
    const source = chunkLines.join('\n');
    const idMatch = /^\s*rule\s+(-?\d+)/.exec(source);
    const ruleId = idMatch ? Number(idMatch[1]) : null;
    const res = parseOne(source);
    if (!res.ok) {
      for (const e of res.errors) errors.push({ ruleId, line: e.line + startLine, col: e.col, message: e.message });
      return;
    }
    if (ids.has(res.ast.id)) {
      errors.push({ ruleId: res.ast.id, line: startLine + 1, col: 1, message: `Duplicate rule id ${res.ast.id} (first defined at line ${ids.get(res.ast.id)})` });
      return;
    }
    ids.set(res.ast.id, startLine + 1);
    rules.push({ id: res.ast.id, source });
  });
  if (!starts.length && !errors.length) errors.push({ ruleId: null, line: 1, col: 1, message: 'No rules found' });
  return { rules, errors };
}

function computeRulesetVersion(entries) {
  const h = crypto.createHash('sha256');
  const sorted = entries.slice().sort((a, b) => a.id - b.id);
  for (const e of sorted) h.update(`${e.id}\u0000${e.version}\u0000${e.source}\u0000`);
  return h.digest('hex').slice(0, 16);
}

function compileRules(records) {
  const rules = [];
  const errors = [];
  const ids = new Set();
  const list = Array.isArray(records) ? records : [];
  for (const rec of list) {
    if (!rec || typeof rec !== 'object') {
      errors.push({ ruleId: null, line: 1, col: 1, message: 'Rule record must be an object' });
      continue;
    }
    if (rec.enabled === false) continue;
    const recId = rec.id === undefined || rec.id === null ? null : Number(rec.id);
    const res = parseOne(rec.source);
    if (!res.ok) {
      for (const e of res.errors) errors.push({ ruleId: recId, line: e.line, col: e.col, message: e.message });
      continue;
    }
    const ast = res.ast;
    if (recId !== null && recId !== ast.id) {
      const t = ast.positions.id;
      errors.push({ ruleId: recId, line: t.line, col: t.col, message: `Rule id ${ast.id} in the source does not match the record id ${recId}` });
      continue;
    }
    if (ids.has(ast.id)) {
      errors.push({ ruleId: ast.id, line: 1, col: 1, message: `Duplicate rule id ${ast.id}` });
      continue;
    }
    let test;
    try {
      test = compileExpression(ast.when);
    } catch {
      errors.push({ ruleId: ast.id, line: 1, col: 1, message: 'Rule could not be compiled' });
      continue;
    }
    ids.add(ast.id);
    const version = Number.isInteger(rec.version) && rec.version > 0 ? rec.version : 1;
    const meta = collectMeta(ast);
    rules.push(Object.freeze({ ...meta, version, source: rec.source, test }));
  }
  rules.sort((a, b) => a.id - b.id);
  return { rules, errors, rulesetVersion: computeRulesetVersion(rules) };
}

module.exports = {
  SEVERITIES,
  TARGETS,
  OPERATORS,
  CLAUSES,
  KEYWORDS,
  MIN_ID,
  MAX_ID,
  MAX_RULE_SOURCE,
  tokenize,
  validateRuleSource,
  parseRuleFile,
  compileRules,
  computeRulesetVersion,
};
