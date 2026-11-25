'use strict';
/**
 * Audit service: derives actor/client from the request and appends to the hash-chained audit log.
 * Never throws — a failed audit write is logged (the action itself already succeeded or failed).
 *
 *   const audit = createAuditor({ db, logger });
 *   audit(req, 'rule.update', { targetType: 'rule', targetId: 942100, outcome: 'success', details: {...} });
 *   audit.system('system.start', { details });
 *   audit.record({ actorName, action, ... })   // raw entry
 */
const { normalizeLogger } = require('./logger');

function createAuditor({ db, logger }) {
  const log = normalizeLogger(logger);

  function record(entry) {
    try {
      return db.audit.append(entry);
    } catch (err) {
      log.error('audit append failed', { action: entry && entry.action, err });
      return null;
    }
  }

  function audit(req, action, { targetType = null, targetId = null, outcome = 'success', details = {}, actor } = {}) {
    const user = actor !== undefined ? actor : (req && req.auth && req.auth.user) || null;
    return record({
      actorId: user ? user.id : null,
      actorName: user ? user.username : 'anonymous',
      actorRole: user ? user.role : null,
      action,
      targetType,
      targetId: targetId === null || targetId === undefined ? null : String(targetId),
      outcome,
      clientId: (req && req.clientId) || null,
      details: { ...(req && req.requestId ? { requestId: req.requestId } : {}), ...details },
    });
  }

  audit.record = record;
  audit.system = (action, { targetType = null, targetId = null, outcome = 'success', details = {}, clientId = null } = {}) => record({
    actorId: null, actorName: 'system', actorRole: null, action, targetType,
    targetId: targetId === null || targetId === undefined ? null : String(targetId), outcome, clientId, details,
  });
  return audit;
}

module.exports = { createAuditor };
