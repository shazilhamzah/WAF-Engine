export function buildQuery(params) {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) usp.set(k, v.join(','));
    } else {
      usp.set(k, String(v));
    }
  }
  const s = usp.toString();
  return s ? `?${s}` : '';
}

export function parseHash(hash) {
  let raw = String(hash || '').replace(/^#/, '');
  if (!raw.startsWith('/')) raw = `/${raw}`;
  const qIndex = raw.indexOf('?');
  const path = qIndex >= 0 ? raw.slice(0, qIndex) : raw;
  const qs = qIndex >= 0 ? raw.slice(qIndex + 1) : '';
  const query = {};
  for (const [k, v] of new URLSearchParams(qs)) query[k] = v;
  const segs = path.split('/').filter(Boolean).map((p) => {
    try { return decodeURIComponent(p); } catch { return p; }
  });
  let route = segs[0] || 'dashboard';
  const params = {};
  if (route === 'events' && segs[1]) {
    route = 'event';
    params.id = segs[1];
  }
  return { route, params, query, path };
}

export function hashFor(path, query) {
  return `#${path}${buildQuery(query)}`;
}

export function parseIdList(text) {
  const out = [];
  for (const part of String(text || '').split(/[\s,;]+/)) {
    const t = part.trim();
    if (t && !out.includes(t)) out.push(t);
  }
  return out;
}
