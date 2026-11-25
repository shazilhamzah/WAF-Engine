'use strict';
/**
 * Normalization (FR-1, contract §1.2 step 1).
 *
 * Every inspected value is turned into a small list of *variants*. Variant 0 is always the raw value;
 * later variants are produced by decoding / canonicalization steps. Each variant records the steps that
 * were needed to produce it (`via`), which becomes the `decodedVia` evidence of a rule match.
 *
 * Decode chain (cumulative, a variant is emitted after every step that changed the value):
 *   url (repeated up to decodeRounds) -> unicode_escape (%uXXXX) -> html (entities) -> nfkc
 *   -> nullbyte (removal) -> invisible (zero-width / soft-hyphen removal)
 * Derived variants (each computed from the fully decoded value):
 *   sql_comment (comments dropped), sql_comment (comments -> space), whitespace (collapsed),
 *   lowercase, backslash (\ -> /), path (dot-segment canonicalization, path values only)
 *
 * All functions are pure and never throw on string input.
 */

const STEP_LABELS = Object.freeze({
  url: 'URL decoding',
  unicode_escape: '%u-escape decoding',
  html: 'HTML entity decoding',
  nfkc: 'Unicode NFKC folding',
  nullbyte: 'null-byte removal',
  invisible: 'invisible-character removal',
  sql_comment: 'SQL comment removal',
  whitespace: 'whitespace collapsing',
  lowercase: 'lower-casing',
  backslash: 'backslash normalization',
  path: 'path canonicalization',
});

function isHex(c) {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);
}

/**
 * One round of percent-decoding. Byte sequences are decoded as UTF-8 (invalid UTF-8 becomes U+FFFD).
 * `%uXXXX` is left untouched (handled by decodeUnicodeEscapes) and is not counted as invalid.
 * @returns {{ value: string, changed: boolean, invalid: boolean }}
 */
function percentDecodeOnce(input, plusAsSpace) {
  const hasPct = input.indexOf('%') !== -1;
  const hasPlus = plusAsSpace && input.indexOf('+') !== -1;
  if (!hasPct && !hasPlus) return { value: input, changed: false, invalid: false };
  let out = '';
  let invalid = false;
  let changed = false;
  let bytes = [];
  const flush = () => {
    if (bytes.length) {
      out += Buffer.from(bytes).toString('utf8');
      bytes = [];
    }
  };
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    if (ch === 37 /* % */) {
      if (i + 2 < input.length && isHex(input.charCodeAt(i + 1)) && isHex(input.charCodeAt(i + 2))) {
        bytes.push(parseInt(input.substr(i + 1, 2), 16));
        i += 2;
        changed = true;
        continue;
      }
      const isU = (input[i + 1] === 'u' || input[i + 1] === 'U') && i + 5 < input.length
        && isHex(input.charCodeAt(i + 2)) && isHex(input.charCodeAt(i + 3))
        && isHex(input.charCodeAt(i + 4)) && isHex(input.charCodeAt(i + 5));
      if (!isU) invalid = true;
      flush();
      out += '%';
      continue;
    }
    flush();
    if (ch === 43 /* + */ && plusAsSpace) {
      out += ' ';
      changed = true;
      continue;
    }
    out += input[i];
  }
  flush();
  return { value: out, changed: changed && out !== input, invalid };
}

/**
 * Multi-round URL decoding. `invalid` only reflects the first round (a literal '%' produced by a
 * legitimate single encoding such as "100%25" is not malformed).
 * @returns {{ value: string, rounds: number, invalid: boolean }}
 */
function urlDecode(value, maxRounds, plusAsSpace) {
  let cur = value;
  let rounds = 0;
  let invalid = false;
  const n = Math.max(1, Math.min(10, maxRounds | 0 || 1));
  for (let i = 0; i < n; i++) {
    const r = percentDecodeOnce(cur, plusAsSpace && i === 0);
    if (i === 0 && r.invalid) invalid = true;
    if (!r.changed) break;
    cur = r.value;
    rounds++;
  }
  return { value: cur, rounds, invalid };
}

const U_ESCAPE_RE = /%u([0-9a-fA-F]{4})/g;
function decodeUnicodeEscapes(value) {
  if (value.indexOf('%u') === -1 && value.indexOf('%U') === -1) return value;
  return value.replace(U_ESCAPE_RE, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

const NAMED_ENTITIES = Object.freeze({
  lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ', tab: '\t', newline: '\n',
  colon: ':', sol: '/', bsol: '\\', lpar: '(', rpar: ')', lsqb: '[', rsqb: ']', lbrack: '[', rbrack: ']',
  lcub: '{', rcub: '}', lbrace: '{', rbrace: '}', semi: ';', comma: ',', period: '.', excl: '!',
  quest: '?', equals: '=', plus: '+', num: '#', percnt: '%', dollar: '$', ast: '*', grave: '`',
  hyphen: '-', dash: '-', lowbar: '_', vert: '|', verbar: '|', copy: '©', reg: '®',
  hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’',
  ldquo: '“', rdquo: '”', commat: '@', Hat: '^', circ: '^', tilde: '~',
});
const ENTITY_RE = /&(?:#[xX]([0-9a-fA-F]{1,6})|#([0-9]{1,7})|([a-zA-Z][a-zA-Z0-9]{1,31}));?/g;

function codePointToString(cp) {
  if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '�';
  return String.fromCodePoint(cp);
}

/** Decodes named (common subset), decimal and hex HTML character references; two rounds (&amp;lt;). */
function decodeHtmlEntities(value) {
  if (value.indexOf('&') === -1) return value;
  let cur = value;
  for (let round = 0; round < 2; round++) {
    const next = cur.replace(ENTITY_RE, (m, hex, dec, name) => {
      if (hex !== undefined) return codePointToString(parseInt(hex, 16));
      if (dec !== undefined) return codePointToString(parseInt(dec, 10));
      if (Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, name)) return NAMED_ENTITIES[name];
      const lower = name.toLowerCase();
      if (lower !== name && Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, lower)) return NAMED_ENTITIES[lower];
      return m;
    });
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

function nfkc(value) {
  try {
    return value.normalize('NFKC');
  } catch {
    return value;
  }
}

const INVISIBLE_RE = /[­​-‏⁠-⁤﻿]/g;
const SQL_COMMENT_RE = /\/\*(!\d{0,6})?([\s\S]*?)\*\//g;
const WHITESPACE_RE = /[\s\u0085᠎]+/g;

/** Removes SQL block comments. MySQL versioned comments keep their content: /*!50000UNION*\/ -> UNION. */
function stripSqlComments(value, replacement) {
  if (value.indexOf('/*') === -1) return value;
  return value.replace(SQL_COMMENT_RE, (m, versioned, inner) => (versioned !== undefined ? inner : replacement));
}

/**
 * Canonicalizes a URL path: backslashes to slashes, duplicate slashes collapsed, '.' removed, '..'
 * resolved. Leading '..' that would escape the root are dropped (reported via `escapesRoot`).
 */
function canonicalizePath(value) {
  const s = String(value).replace(/\\/g, '/');
  const segments = s.split('/');
  const out = [];
  let escapesRoot = false;
  for (const seg of segments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (out.length) out.pop();
      else escapesRoot = true;
      continue;
    }
    out.push(seg);
  }
  const trailing = out.length > 0 && /\/\.{0,2}$/.test(s);
  return { value: '/' + out.join('/') + (trailing ? '/' : ''), escapesRoot };
}

/**
 * Builds the variant list for one value.
 * @param {string} raw
 * @param {{ decodeRounds?: number, plusAsSpace?: boolean, urlDecode?: boolean, isPath?: boolean }} opts
 * @returns {{ variants: {value: string, via: string[]}[], flags: { doubleEncoded: number, invalidEncoding: boolean,
 *            unicodeEscape: boolean, nullByte: boolean, escapesRoot: boolean } }}
 */
function buildVariants(raw, opts = {}) {
  const value = typeof raw === 'string' ? raw : String(raw ?? '');
  const flags = { doubleEncoded: 0, invalidEncoding: false, unicodeEscape: false, nullByte: false, escapesRoot: false };
  const variants = [{ value, via: [] }];
  const seen = new Set([value]);
  const push = (v, via) => {
    if (!seen.has(v)) {
      seen.add(v);
      variants.push({ value: v, via });
    }
  };

  let cur = value;
  let via = [];
  // --- decode chain ---
  if (opts.urlDecode !== false) {
    const r = urlDecode(cur, opts.decodeRounds ?? 3, Boolean(opts.plusAsSpace));
    if (r.invalid) flags.invalidEncoding = true;
    if (r.rounds > 1) flags.doubleEncoded = r.rounds;
    if (r.rounds > 0) {
      cur = r.value;
      via = via.concat(new Array(r.rounds).fill('url'));
      push(cur, via);
    }
  }
  const steps = [
    ['unicode_escape', (v) => {
      const d = decodeUnicodeEscapes(v);
      if (d !== v) flags.unicodeEscape = true;
      return d;
    }],
    ['html', decodeHtmlEntities],
    ['nfkc', nfkc],
    ['nullbyte', (v) => {
      if (v.indexOf('\u0000') === -1) return v;
      flags.nullByte = true;
      return v.replace(/\u0000/g, '');
    }],
    ['invisible', (v) => v.replace(INVISIBLE_RE, '')],
  ];
  for (const [name, fn] of steps) {
    const next = fn(cur);
    if (next !== cur) {
      cur = next;
      via = via.concat(name);
      push(cur, via);
    }
  }
  const decoded = cur;
  const decodedVia = via;

  // --- derived variants (independent, from the decoded value) ---
  const derive = (name, v) => {
    if (v !== decoded) push(v, decodedVia.concat(name));
  };
  if (decoded.indexOf('/*') !== -1) {
    derive('sql_comment', stripSqlComments(decoded, ' '));
    derive('sql_comment', stripSqlComments(decoded, ''));
  }
  derive('whitespace', decoded.replace(WHITESPACE_RE, ' '));
  derive('lowercase', decoded.toLowerCase());
  if (decoded.indexOf('\\') !== -1) derive('backslash', decoded.replace(/\\/g, '/'));
  if (opts.isPath) {
    const c = canonicalizePath(decoded);
    if (c.escapesRoot) flags.escapesRoot = true;
    derive('path', c.value);
  }
  return { variants, flags, decoded };
}

/** Human-readable description of a decodedVia list, e.g. ['url','url','html'] -> "2 rounds of URL decoding, HTML entity decoding". */
function describeVia(via) {
  if (!Array.isArray(via) || via.length === 0) return '';
  const parts = [];
  for (let i = 0; i < via.length; i++) {
    let n = 1;
    while (i + 1 < via.length && via[i + 1] === via[i]) {
      n++;
      i++;
    }
    const label = STEP_LABELS[via[i]] || String(via[i]);
    parts.push(n > 1 ? `${n} rounds of ${label}` : label);
  }
  return parts.join(', ');
}

module.exports = {
  STEP_LABELS,
  percentDecodeOnce,
  urlDecode,
  decodeUnicodeEscapes,
  decodeHtmlEntities,
  nfkc,
  stripSqlComments,
  canonicalizePath,
  buildVariants,
  describeVia,
};
