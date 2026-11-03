'use strict';

const { buildVariants, canonicalizePath } = require('./normalize');
const { DEFAULT_CONFIG } = require('./config');

// rejection codes carry 0 points
const ANOMALIES = Object.freeze({
  DOUBLE_ENCODING: [2, 'A value was URL-encoded more than once (possible filter evasion)'],
  NULL_BYTE: [3, 'A value contains a null byte (possible string-termination attack)'],
  INVALID_ENCODING: [1, 'Invalid percent-encoding (a % not followed by two hex digits)'],
  UNICODE_ESCAPE: [2, 'Non-standard %uXXXX escape used (IIS-style encoding, common in evasion)'],
  PATH_ESCAPES_ROOT: [2, 'Path contains more ../ segments than directories (tries to climb above the web root)'],
  BODY_PARTIALLY_INSPECTED: [1, 'Body is larger than the inspection window; only the first part was inspected'],
  MALFORMED_JSON: [2, 'Content-Type says JSON but the body is not valid JSON'],
  JSON_TOO_DEEP: [2, 'JSON body nesting exceeds the inspection depth limit'],
  MALFORMED_MULTIPART: [1, 'Multipart body could not be parsed (missing or invalid boundary)'],
  INVALID_REQUEST: [0, 'Request is not a valid request object'],
  INVALID_METHOD: [0, 'HTTP method is not a valid token'],
  INVALID_URL: [0, 'URL is missing, not origin-form, or contains control characters'],
  URL_TOO_LONG: [0, 'URL is longer than the configured maximum'],
  INVALID_HEADER: [0, 'Header name is not a valid token or a header value contains CR, LF or NUL'],
  HEADER_TOO_LONG: [0, 'A header value is longer than 16384 characters'],
  TOO_MANY_HEADERS: [0, 'Request has more headers than the configured maximum'],
  TOO_MANY_ARGS: [0, 'Request has more arguments (query + body fields) than the configured maximum'],
  BODY_TOO_LARGE: [0, 'Body is larger than the configured maximum'],
});

const METHOD_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,24}$/;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$/;
const MAX_HEADER_VALUE = 16384;
const MAX_JSON_DEPTH = 32;
const MAX_COOKIES = 100;
const MAX_NAME_LENGTH = 256;

class Rejection extends Error {
  constructor(anomalyCode, errorCode, detail) {
    super(anomalyCode);
    this.anomalyCode = anomalyCode;
    this.errorCode = errorCode;
    this.detail = detail;
  }
}

function makeAnomaly(code, detail) {
  const [points, message] = ANOMALIES[code] || [0, 'Anomaly'];
  return { code, message: detail ? `${message} (${detail})` : message, points };
}

// one entry per code so points count once per request
function createAnomalyList() {
  const list = [];
  const seen = new Set();
  return {
    list,
    add(code, detail) {
      if (seen.has(code)) return;
      seen.add(code);
      list.push(makeAnomaly(code, detail));
    },
  };
}

function resolveLimits(limits) {
  const out = { ...DEFAULT_CONFIG.limits };
  if (limits && typeof limits === 'object') {
    for (const k of Object.keys(out)) {
      const v = limits[k];
      if (Number.isInteger(v) && v > 0) out[k] = v;
    }
  }
  out.decodeRounds = Math.min(5, out.decodeRounds);
  return out;
}

function safeDecodeComponent(s, plusAsSpace) {
  const t = plusAsSpace ? s.replace(/\+/g, ' ') : s;
  try {
    return decodeURIComponent(t);
  } catch {
    return t;
  }
}

function clipName(name) {
  return name.length > MAX_NAME_LENGTH ? name.slice(0, MAX_NAME_LENGTH) : name;
}

// raw values are not decoded here since the variants do that
function parsePairs(str, separator = '&') {
  const out = [];
  if (!str) return out;
  for (const part of str.split(separator)) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    const rawName = eq === -1 ? part : part.slice(0, eq);
    const rawValue = eq === -1 ? '' : part.slice(eq + 1);
    out.push({ rawName, rawValue, name: clipName(safeDecodeComponent(rawName, true)) });
  }
  return out;
}

function parseCookies(header) {
  const out = [];
  if (!header) return out;
  for (const part of header.split(';')) {
    const p = part.trim();
    if (!p) continue;
    const eq = p.indexOf('=');
    const name = (eq === -1 ? p : p.slice(0, eq)).trim();
    let value = eq === -1 ? '' : p.slice(eq + 1).trim();
    if (value.length >= 2 && value[0] === '"' && value[value.length - 1] === '"') value = value.slice(1, -1);
    out.push({ name: clipName(name), value });
    if (out.length >= MAX_COOKIES) break;
  }
  return out;
}

function flattenJson(root, maxFields, anomalies) {
  const fields = [];
  const names = [];
  let tooDeep = false;
  const visit = (node, prefix, depth) => {
    if (fields.length > maxFields) return;
    if (depth > MAX_JSON_DEPTH) {
      tooDeep = true;
      return;
    }
    if (node !== null && typeof node === 'object') {
      const entries = Array.isArray(node) ? node.map((v, i) => [String(i), v]) : Object.keys(node).map((k) => [k, node[k]]);
      if (entries.length === 0 && prefix) fields.push({ name: prefix, value: '' });
      for (const [k, v] of entries) {
        const name = clipName(prefix ? `${prefix}.${k}` : k);
        if (!Array.isArray(node)) names.push(name);
        visit(v, name, depth + 1);
        if (fields.length > maxFields) return;
      }
      return;
    }
    fields.push({ name: prefix || '$', value: node === null ? '' : String(node) });
  };
  visit(root, '', 0);
  if (tooDeep) anomalies.add('JSON_TOO_DEEP', `depth > ${MAX_JSON_DEPTH}`);
  return { fields, names };
}

function parseMultipart(text, contentType, anomalies) {
  const m = /boundary=(?:"([^"]{1,200})"|([^;,\s]{1,200}))/i.exec(contentType);
  if (!m) {
    anomalies.add('MALFORMED_MULTIPART', 'no boundary');
    return null;
  }
  const boundary = `--${m[1] || m[2]}`;
  const chunks = text.split(boundary);
  const fields = [];
  for (let i = 1; i < chunks.length; i++) {
    let chunk = chunks[i];
    if (chunk.startsWith('--')) break;
    chunk = chunk.replace(/^\r?\n/, '');
    const sep = chunk.search(/\r?\n\r?\n/);
    if (sep === -1) continue;
    const head = chunk.slice(0, sep);
    let content = chunk.slice(sep).replace(/^\r?\n\r?\n/, '');
    content = content.replace(/\r?\n$/, '');
    const name = /\bname="([^"]*)"/i.exec(head);
    if (!name) continue;
    const fname = /\bfilename="([^"]*)"/i.exec(head);
    fields.push({ name: clipName(name[1]), value: content });
    if (fname) fields.push({ name: clipName(`${name[1]}.filename`), value: fname[1] });
  }
  if (chunks.length < 2) {
    anomalies.add('MALFORMED_MULTIPART', 'boundary not found in body');
    return null;
  }
  return fields;
}

function toBodyBuffer(body) {
  if (body === null || body === undefined) return null;
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (typeof body === 'object') return Buffer.from(JSON.stringify(body), 'utf8');
  return Buffer.from(String(body), 'utf8');
}

function makeField(location, name, kind, raw, opts, report, anomalies) {
  const value = typeof raw === 'string' ? raw : String(raw ?? '');
  const { variants, flags, decoded } = buildVariants(value, opts);
  if (flags.nullByte) anomalies.add('NULL_BYTE', `at ${location}`);
  if (report !== 'nul') {
    if (flags.doubleEncoded > 1) anomalies.add('DOUBLE_ENCODING', `${flags.doubleEncoded} rounds at ${location}`);
    if (flags.unicodeEscape) anomalies.add('UNICODE_ESCAPE', `at ${location}`);
    if (report === 'url' && flags.invalidEncoding) anomalies.add('INVALID_ENCODING', `at ${location}`);
    if (flags.escapesRoot) anomalies.add('PATH_ESCAPES_ROOT', `at ${location}`);
  }
  return { location, name, kind, variants, decoded, rawLength: value.length };
}

function rawField(location, name, kind, value) {
  const v = typeof value === 'string' ? value : String(value ?? '');
  return { location, name, kind, variants: [{ value: v, via: [] }], decoded: v, rawLength: v.length };
}

function parseRequest(raw, limits) {
  const L = resolveLimits(limits);
  const anomalies = createAnomalyList();
  const partial = { method: null, path: null, contentType: null, bodyBytes: 0, userAgent: null };
  try {
    return parseInner(raw, L, anomalies, partial);
  } catch (err) {
    const rej = err instanceof Rejection ? err : new Rejection('INVALID_REQUEST', 'MALFORMED_REQUEST');
    anomalies.add(rej.anomalyCode, rej.detail);
    const isBody = rej.errorCode === 'BODY_TOO_LARGE';
    return {
      ok: false,
      request: null,
      anomalies: anomalies.list,
      error: { code: rej.errorCode, message: ANOMALIES[rej.anomalyCode] ? ANOMALIES[rej.anomalyCode][1] : 'Malformed request' },
      statusCode: isBody ? 413 : 400,
      partial,
    };
  }
}

function parseInner(raw, L, anomalies, partial) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new Rejection('INVALID_REQUEST', 'MALFORMED_REQUEST');

  const method = typeof raw.method === 'string' ? raw.method : '';
  if (!METHOD_RE.test(method)) throw new Rejection('INVALID_METHOD', 'MALFORMED_REQUEST');
  partial.method = method.toUpperCase();

  let url = raw.url;
  if (typeof url !== 'string' || url.length === 0) throw new Rejection('INVALID_URL', 'MALFORMED_REQUEST', 'missing');
  if (url.length > L.maxUrlLength) throw new Rejection('URL_TOO_LONG', 'MALFORMED_REQUEST', `${url.length} > ${L.maxUrlLength}`);
  if (/[\u0000- \u007f]/.test(url)) throw new Rejection('INVALID_URL', 'MALFORMED_REQUEST', 'control character or space');
  const abs = /^https?:\/\/[^/?#]*/i.exec(url);
  if (abs) url = url.slice(abs[0].length) || '/';
  if (url === '*' && partial.method === 'OPTIONS') url = '/';
  if (url[0] !== '/') throw new Rejection('INVALID_URL', 'MALFORMED_REQUEST', 'not origin-form');
  const hash = url.indexOf('#');
  if (hash !== -1) url = url.slice(0, hash);
  const qpos = url.indexOf('?');
  const pathRaw = qpos === -1 ? url : url.slice(0, qpos);
  const queryString = qpos === -1 ? '' : url.slice(qpos + 1);
  partial.path = pathRaw;

  const headers = new Map();
  const rawHeaders = raw.headers;
  if (rawHeaders !== null && rawHeaders !== undefined) {
    if (typeof rawHeaders !== 'object' || Array.isArray(rawHeaders)) throw new Rejection('INVALID_HEADER', 'MALFORMED_REQUEST', 'headers must be an object');
    const names = Object.keys(rawHeaders);
    if (names.length > L.maxHeaderCount) throw new Rejection('TOO_MANY_HEADERS', 'MALFORMED_REQUEST', `${names.length} > ${L.maxHeaderCount}`);
    for (const n of names) {
      if (!HEADER_NAME_RE.test(n)) throw new Rejection('INVALID_HEADER', 'MALFORMED_REQUEST', 'invalid name');
      let v = rawHeaders[n];
      if (Array.isArray(v)) v = v.map((x) => String(x)).join(', ');
      else if (v === null || v === undefined) v = '';
      else v = String(v);
      if (/[\r\n\u0000]/.test(v)) throw new Rejection('INVALID_HEADER', 'MALFORMED_REQUEST', 'CR, LF or NUL in value');
      if (v.length > MAX_HEADER_VALUE) throw new Rejection('HEADER_TOO_LONG', 'MALFORMED_REQUEST');
      const lower = n.toLowerCase();
      headers.set(lower, headers.has(lower) ? `${headers.get(lower)}, ${v}` : v);
    }
  }
  const contentType = headers.has('content-type') ? headers.get('content-type') : null;
  partial.contentType = contentType ? contentType.slice(0, 100) : null;
  partial.userAgent = headers.has('user-agent') ? headers.get('user-agent') : null;

  const bodyBuf = toBodyBuffer(raw.body);
  const actual = bodyBuf ? bodyBuf.length : 0;
  const declared = Number.isFinite(Number(raw.bodyBytes)) && Number(raw.bodyBytes) >= 0 ? Math.floor(Number(raw.bodyBytes)) : 0;
  const bodyBytes = Math.max(actual, declared);
  partial.bodyBytes = bodyBytes;
  if (bodyBytes > L.maxBodyBytes) throw new Rejection('BODY_TOO_LARGE', 'BODY_TOO_LARGE', `${bodyBytes} > ${L.maxBodyBytes} bytes`);
  const inspectedBuf = bodyBuf ? bodyBuf.subarray(0, Math.min(bodyBuf.length, L.inspectBodyBytes)) : null;
  const inspectedBytes = inspectedBuf ? inspectedBuf.length : 0;
  const truncated = bodyBytes > inspectedBytes && bodyBytes > L.inspectBodyBytes;
  if (truncated) anomalies.add('BODY_PARTIALLY_INSPECTED', `${inspectedBytes} of ${bodyBytes} bytes inspected`);
  const bodyText = inspectedBuf ? inspectedBuf.toString('utf8') : '';

  const queryPairs = parsePairs(queryString);

  const mime = contentType ? contentType.split(';')[0].trim().toLowerCase() : '';
  let bodyKind = bodyText ? 'text' : 'none';
  let bodyPairs = [];
  let bodyNames = [];
  if (bodyText) {
    const trimmed = bodyText.trim();
    const looksJson = trimmed.startsWith('{') || trimmed.startsWith('[');
    const isJsonType = mime === 'application/json' || mime.endsWith('+json');
    if (mime === 'application/x-www-form-urlencoded' || (!mime && !looksJson && /^[^=&\s]+=[^\s]*$/.test(trimmed))) {
      bodyKind = 'form';
      bodyPairs = parsePairs(bodyText).map((p) => ({ name: p.name, value: p.rawValue, form: true }));
      bodyNames = bodyPairs.map((p) => p.name);
    } else if (isJsonType || (!mime && looksJson) || (mime === 'text/plain' && looksJson)) {
      let parsed;
      let parsedOk = false;
      try {
        parsed = JSON.parse(bodyText);
        parsedOk = true;
      } catch {
        if (isJsonType && !truncated) anomalies.add('MALFORMED_JSON');
      }
      if (parsedOk) {
        bodyKind = 'json';
        const flat = flattenJson(parsed, L.maxArgs, anomalies);
        bodyPairs = flat.fields.map((f) => ({ name: f.name, value: f.value, form: false }));
        bodyNames = flat.names.length ? flat.names : [];
      }
    } else if (mime === 'multipart/form-data') {
      const parts = parseMultipart(bodyText, contentType, anomalies);
      if (parts) {
        bodyKind = 'multipart';
        bodyPairs = parts.map((p) => ({ name: p.name, value: p.value, form: false }));
        bodyNames = bodyPairs.map((p) => p.name);
      }
    }
  }
  const argCount = queryPairs.length + bodyPairs.length;
  if (argCount > L.maxArgs) throw new Rejection('TOO_MANY_ARGS', 'MALFORMED_REQUEST', `${argCount} > ${L.maxArgs}`);

  const rounds = L.decodeRounds;
  const urlOpts = { decodeRounds: rounds, plusAsSpace: true };
  const fields = {
    method: rawField('method', null, 'method', method),
    path: makeField('path', null, 'path', pathRaw, { decodeRounds: rounds, plusAsSpace: false, isPath: true }, 'url', anomalies),
    pathRaw: rawField('path', null, 'path', pathRaw),
    query: queryPairs.map((p) => makeField(`query.${p.name}`, p.name, 'query', p.rawValue, urlOpts, 'url', anomalies)),
    queryNames: queryPairs.map((p) => makeField('query_names', p.name, 'name', p.rawName, urlOpts, 'url', anomalies)),
    body: bodyText ? makeField('body', null, 'body', bodyText, { decodeRounds: rounds, plusAsSpace: bodyKind === 'form' }, bodyKind === 'form' ? 'url' : 'decoded', anomalies) : null,
    bodyFields: bodyPairs.map((p) => makeField(`body.${p.name}`, p.name, 'body', p.value,
      { decodeRounds: rounds, plusAsSpace: p.form }, p.form ? 'url' : 'decoded', anomalies)),
    bodyNames: [...new Set(bodyNames)].map((n) => makeField('body_names', n, 'name', n, { decodeRounds: rounds }, 'decoded', anomalies)),
    headers: new Map(),
    cookies: [],
  };
  for (const [name, value] of headers) {
    fields.headers.set(name, makeField(`header.${name}`, name, 'header', value, { decodeRounds: rounds }, 'nul', anomalies));
  }
  const cookies = parseCookies(headers.get('cookie'));
  fields.cookies = cookies.map((c) => makeField(`cookie.${c.name}`, c.name, 'cookie', c.value, { decodeRounds: rounds }, 'decoded', anomalies));

  const canonical = canonicalizePath(fields.path.decoded).value;
  const uniq = (arr) => [...new Set(arr)];
  const request = {
    method: method.toUpperCase(),
    rawMethod: method,
    url,
    path: pathRaw,
    canonicalPath: canonical,
    queryString,
    query: queryPairs.map((p) => ({ name: p.name, value: p.rawValue })),
    queryNames: uniq(queryPairs.map((p) => p.name)),
    headers: Object.fromEntries([...headers].map(([k, v]) => [k, v])),
    headerCount: headers.size,
    cookies,
    contentType,
    bodyKind,
    bodyText,
    bodyFields: bodyPairs.map((p) => ({ name: p.name, value: p.value })),
    bodyNames: uniq(bodyNames),
    bodyBytes,
    inspectedBytes,
    truncated,
    userAgent: partial.userAgent,
    argCount,
  };
  Object.defineProperty(request, 'fields', { value: fields, enumerable: false });
  return { ok: true, request, anomalies: anomalies.list, error: null };
}

module.exports = { ANOMALIES, parseRequest, makeAnomaly, parsePairs, parseCookies, flattenJson, resolveLimits };
