'use strict';

function isActive(exc, nowMs) {
  if (!exc || typeof exc !== 'object') return false;
  if (exc.status !== undefined && exc.status !== null && exc.status !== 'approved') return false;
  if (exc.expiresAt) {
    const t = Date.parse(exc.expiresAt);
    if (Number.isFinite(t) && t <= nowMs) return false;
  }
  return Number.isFinite(Number(exc.ruleId));
}

function prepareExceptions(list, nowMs) {
  if (!Array.isArray(list)) return [];
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const out = [];
  for (const exc of list) {
    if (!isActive(exc, now)) continue;
    const scope = exc.scope && typeof exc.scope === 'object' ? exc.scope : {};
    out.push({
      id: String(exc.id ?? ''),
      ruleId: Number(exc.ruleId),
      pathPrefix: typeof scope.pathPrefix === 'string' && scope.pathPrefix !== '' ? scope.pathPrefix : null,
      location: typeof scope.location === 'string' && scope.location !== '' ? scope.location : null,
      method: typeof scope.method === 'string' && scope.method !== '' ? scope.method.toUpperCase() : null,
    });
  }
  return out;
}

function findSuppressingException(prepared, ruleId, location, request) {
  for (const exc of prepared) {
    if (exc.ruleId !== Number(ruleId)) continue;
    if (exc.pathPrefix !== null && !String(request.canonicalPath || '').startsWith(exc.pathPrefix)) continue;
    if (exc.location !== null && exc.location !== location) continue;
    if (exc.method !== null && exc.method !== String(request.method || '').toUpperCase()) continue;
    return exc.id || 'exception';
  }
  return null;
}

module.exports = { prepareExceptions, findSuppressingException, isActive };
