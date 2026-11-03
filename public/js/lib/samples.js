export const METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
export const LIMITS = Object.freeze({
  pathMax: 4096,
  headerMax: 50,
  headerValueMax: 4096,
  bodyMaxBytes: 1024 * 1024,
  importFileMaxBytes: 256 * 1024,
  importMaxSamples: 100,
  labelMax: 120,
});
const HEADER_NAME = /^[A-Za-z0-9-]+$/;

// the attack strings are textbook indicators that only target the local lab app
export const EXAMPLES = Object.freeze([
  {
    key: 'benign-search', label: 'Benign search', kind: 'benign',
    sample: { method: 'GET', path: '/search?q=running+shoes', headers: { 'user-agent': 'waf-studio-lab' }, body: null },
  },
  {
    key: 'benign-apostrophe', label: "Benign name with apostrophe", kind: 'benign',
    sample: { method: 'GET', path: "/search?q=O%27Brien%27s+cafe", headers: { 'user-agent': 'waf-studio-lab' }, body: null },
  },
  {
    key: 'benign-comment', label: 'Benign JSON comment', kind: 'benign',
    sample: {
      method: 'POST', path: '/comments',
      headers: { 'content-type': 'application/json', 'user-agent': 'waf-studio-lab' },
      body: '{"author":"Sam","text":"Great article, I will select a few ideas for our union meeting."}',
    },
  },
  {
    key: 'sqli', label: 'SQL injection (tautology)', kind: 'attack',
    sample: { method: 'GET', path: '/search?q=%27%20OR%201%3D1--', headers: { 'user-agent': 'waf-studio-lab' }, body: null },
  },
  {
    key: 'xss', label: 'Cross-site scripting', kind: 'attack',
    sample: {
      method: 'POST', path: '/comments',
      headers: { 'content-type': 'application/json', 'user-agent': 'waf-studio-lab' },
      body: '{"author":"Eve","text":"<script>alert(1)</script>"}',
    },
  },
  {
    key: 'traversal', label: 'Path traversal', kind: 'attack',
    sample: { method: 'GET', path: '/files?name=../../etc/passwd', headers: { 'user-agent': 'waf-studio-lab' }, body: null },
  },
  {
    key: 'double-encoded', label: 'Double-encoded traversal', kind: 'attack',
    sample: { method: 'GET', path: '/files?name=%252e%252e%252f%252e%252e%252fetc%252fpasswd', headers: { 'user-agent': 'waf-studio-lab' }, body: null },
  },
]);

export function exampleByKey(key) {
  const ex = EXAMPLES.find((e) => e.key === key);
  return ex ? JSON.parse(JSON.stringify(ex.sample)) : null;
}

function byteLength(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str).length;
  return String(str).length;
}

export function validateSample(sample) {
  const errors = [];
  if (!sample || typeof sample !== 'object' || Array.isArray(sample)) {
    return [{ field: 'sample', message: 'must be an object' }];
  }
  if (!METHODS.includes(sample.method)) {
    errors.push({ field: 'method', message: `must be one of ${METHODS.join(', ')}` });
  }
  if (typeof sample.path !== 'string' || !sample.path.startsWith('/')) {
    errors.push({ field: 'path', message: "must start with '/'" });
  } else if (sample.path.length > LIMITS.pathMax) {
    errors.push({ field: 'path', message: `must be at most ${LIMITS.pathMax} characters` });
  } else if (/[\u0000-\u001f\u007f\s]/.test(sample.path)) {
    errors.push({ field: 'path', message: 'must not contain spaces or control characters (URL-encode them, e.g. %20)' });
  }
  const headers = sample.headers === undefined || sample.headers === null ? {} : sample.headers;
  if (typeof headers !== 'object' || Array.isArray(headers)) {
    errors.push({ field: 'headers', message: 'must be an object of name → value' });
  } else {
    const names = Object.keys(headers);
    if (names.length > LIMITS.headerMax) errors.push({ field: 'headers', message: `at most ${LIMITS.headerMax} headers` });
    for (const name of names) {
      if (!HEADER_NAME.test(name)) errors.push({ field: `headers.${name}`, message: 'name may only contain letters, digits and -' });
      const v = headers[name];
      if (typeof v !== 'string') errors.push({ field: `headers.${name}`, message: 'value must be a string' });
      else if (v.length > LIMITS.headerValueMax) errors.push({ field: `headers.${name}`, message: `value must be at most ${LIMITS.headerValueMax} characters` });
    }
  }
  if (sample.body !== undefined && sample.body !== null) {
    if (typeof sample.body !== 'string') errors.push({ field: 'body', message: 'must be a string or null' });
    else if (byteLength(sample.body) > LIMITS.bodyMaxBytes) errors.push({ field: 'body', message: 'must be at most 1 MiB' });
  }
  return errors;
}

export function normalizeSample(sample) {
  const headers = {};
  for (const [k, v] of Object.entries((sample && sample.headers) || {})) headers[String(k).toLowerCase()] = v;
  const body = sample && sample.body !== undefined && sample.body !== null && sample.body !== '' ? sample.body : null;
  return { method: sample.method, path: sample.path, headers, body };
}

export function rowsToHeaders(rows) {
  const headers = {};
  const errors = [];
  for (const row of rows || []) {
    const name = String((row && row.name) || '').trim().toLowerCase();
    const value = String((row && row.value) || '');
    if (!name && !value) continue;
    if (!name) { errors.push({ field: 'headers', message: 'a header value has no name' }); continue; }
    if (Object.prototype.hasOwnProperty.call(headers, name)) {
      errors.push({ field: `headers.${name}`, message: 'duplicate header name' });
      continue;
    }
    headers[name] = value;
  }
  return { headers, errors };
}

export function headersToRows(headers) {
  return Object.entries(headers || {}).map(([name, value]) => ({ name, value: String(value) }));
}

export function importPayload(parsed) {
  return parsed.samples.map((s, i) => (parsed.labels && parsed.labels[i] ? { label: parsed.labels[i], sample: s } : s));
}

export function parseImportText(text, sizeBytes, filename) {
  const result = { ok: false, error: null, samples: [], invalid: [], total: 0 };
  if (filename !== undefined && !/\.json$/i.test(String(filename))) {
    result.error = 'The file must have a .json extension.';
    return result;
  }
  if (filename !== undefined && !/^[A-Za-z0-9 _.()-]{1,123}\.json$/i.test(String(filename))) {
    result.error = 'Rename the file using only letters, digits, spaces and . _ - ( ) before importing.';
    return result;
  }
  const size = Number.isFinite(sizeBytes) ? sizeBytes : byteLength(String(text || ''));
  if (size > LIMITS.importFileMaxBytes) {
    result.error = `The file is too large (${Math.ceil(size / 1024)} KB). The limit is 256 KB.`;
    return result;
  }
  let data;
  try {
    data = JSON.parse(String(text || ''));
  } catch {
    result.error = 'The file is not valid JSON.';
    return result;
  }
  const list = Array.isArray(data) ? data : (data && typeof data === 'object' && Array.isArray(data.samples) ? data.samples : null);
  if (!list) {
    result.error = 'Expected a JSON array of samples or an object with a "samples" array.';
    return result;
  }
  if (list.length === 0) {
    result.error = 'The file contains no samples.';
    return result;
  }
  if (list.length > LIMITS.importMaxSamples) {
    result.error = `Too many samples (${list.length}). The limit is ${LIMITS.importMaxSamples} per import.`;
    return result;
  }
  result.total = list.length;
  result.labels = [];
  list.forEach((item, index) => {
    const wrapped = item && typeof item === 'object' && !Array.isArray(item) && item.sample && typeof item.sample === 'object';
    const inner = wrapped ? item.sample : item;
    const label = wrapped && typeof item.label === 'string' && item.label.trim() ? item.label.trim().slice(0, LIMITS.labelMax) : null;
    const errs = validateSample(inner);
    if (errs.length) {
      result.invalid.push({ index, message: errs.map((e) => `${e.field}: ${e.message}`).join('; ') });
    } else {
      result.samples.push(normalizeSample(inner));
      result.labels.push(label);
    }
  });
  result.ok = result.samples.length > 0;
  if (!result.ok) result.error = 'No valid samples were found in the file.';
  return result;
}
