'use strict';
/**
 * Exception (tuning) matching (FR-7, contract §3.4).
 *
 * An approved exception suppresses a rule match when its ruleId equals the match rule id AND every
 * non-null scope field matches:
 *   pathPrefix -> the request's canonical path (decoded, dot-segments resolved) starts with it
 *                 (canonical, so /search/../admin cannot borrow an exception scoped to /search)
 *   location   -> equals the match location exactly (e.g. 'query.q')
 *   method     -> equals the request method (case-insensitive)
 * The service layer passes only approved, unexpired exceptions; as defence in depth, entries whose
 * status is present and not 'approved', or whose expiresAt is in the past, are ignored here too.
 */

function isActive(exc, nowMs) {
  if (!exc || typeof exc !== 'object') return false;
  if (exc.status !== undefined && exc.status !== null && exc.status !== 'approved') return false;
  if (exc.expiresAt) {
    const t = Date.parse(exc.expiresAt);
    if (Number.isFinite(t) && t <= nowMs) return false;
  }
  return Number.isFinite(Number(exc.ruleId));
}

/** Filters and normalizes the exception list once per inspect() call. */
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

/** @returns {string|null} the id of the first exception that covers (ruleId, location) for this request */
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
