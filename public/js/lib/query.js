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

// paging state for a list; an offset past the end (stale bookmark, data reset) points back to the last real page
export function pageInfo(total, limit, offset) {
  const count = Math.max(0, Math.floor(Number(total)) || 0);
  const size = Math.max(1, Math.floor(Number(limit)) || 1);
  const start = Math.max(0, Math.floor(Number(offset)) || 0);
  const pages = Math.max(1, Math.ceil(count / size));
  const lastOffset = (pages - 1) * size;
  const beyond = start > 0 && start >= count;
  return {
    pages,
    page: beyond ? null : Math.floor(start / size) + 1,
    from: beyond || !count ? 0 : start + 1,
    to: beyond ? 0 : Math.min(start + size, count),
    total: count,
    beyond,
    hasPrev: start > 0,
    prevOffset: beyond ? lastOffset : Math.max(0, start - size),
    hasNext: !beyond && start + size < count,
    nextOffset: start + size,
  };
}
