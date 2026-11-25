'use strict';
/**
 * Block / monitor modes (FR-4, pipeline step 4).
 *
 * The engine first decides whether the request *would* be blocked (score >= block threshold, parser
 * rejection, or rate-limit breach). The mode then decides what actually happens:
 *   block   -> action 'blocked', statusCode returned to the client (400/403/413/429)
 *   monitor -> action 'logged', wouldBlock true, statusCode null (request is forwarded)
 * Requests that would not be blocked are always 'allowed' (a 'flag' verdict is visible in the event).
 */

const MODES = Object.freeze(['block', 'monitor']);

/**
 * @param {'block'|'monitor'} mode
 * @param {boolean} wouldBlock
 * @param {number|null} statusCode status that blocking would use
 * @returns {{ action: 'allowed'|'blocked'|'logged', wouldBlock: boolean, statusCode: number|null }}
 */
function applyMode(mode, wouldBlock, statusCode) {
  if (!wouldBlock) return { action: 'allowed', wouldBlock: false, statusCode: null };
  if (mode === 'monitor') return { action: 'logged', wouldBlock: true, statusCode: null };
  return { action: 'blocked', wouldBlock: true, statusCode: statusCode || 403 };
}

module.exports = { MODES, applyMode };
