'use strict';

const MODES = Object.freeze(['block', 'monitor']);

function applyMode(mode, wouldBlock, statusCode) {
  if (!wouldBlock) return { action: 'allowed', wouldBlock: false, statusCode: null };
  if (mode === 'monitor') return { action: 'logged', wouldBlock: true, statusCode: null };
  return { action: 'blocked', wouldBlock: true, statusCode: statusCode || 403 };
}

module.exports = { MODES, applyMode };
