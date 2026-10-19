'use strict';
/**
 * Large-body fixture generator (evaluation case T4 "Large bodies").
 *
 *   const { makeLargeBody, makeLargeRequest } = require('./fixtures/large-body');
 *   makeLargeBody(70000)                                         // 70 000 bytes of benign filler
 *   makeLargeBody(70000, { payload: '<marker>', position: 'end' })   // marker in the last bytes
 *
 * The body is plain ASCII filler built from ordinary English sentences (it matches no default rule),
 * so the byte length is exact. An optional payload string is placed at the 'start', 'middle' or 'end'
 * (default 'end'), separated from the filler by spaces. This lets tests show that:
 *   - bodies up to limits.inspectBodyBytes are fully inspected (payload anywhere is seen);
 *   - beyond that only the first part is inspected (anomaly BODY_PARTIALLY_INSPECTED), so a payload at
 *     the end of a huge body is a documented blind spot;
 *   - bodies larger than limits.maxBodyBytes are rejected with 413 BODY_TOO_LARGE before any rule runs.
 * Payload strings for attack variants belong to the attack fixture sets, not this file.
 */

const FILLER = 'The delivery arrived on time and the packaging was neat. '
  + 'Customers often ask about sizes, colours and return windows. '
  + 'Our team answers every message within two working days. ';

const POSITIONS = new Set(['start', 'middle', 'end']);

function filler(n) {
  if (n <= 0) return '';
  const reps = Math.ceil(n / FILLER.length);
  return FILLER.repeat(reps).slice(0, n);
}

/**
 * @param {number} bytes total body size in bytes (UTF-8)
 * @param {{ payload?: string, position?: 'start'|'middle'|'end' }} [opts]
 * @returns {string} body of exactly `bytes` bytes
 */
function makeLargeBody(bytes, opts = {}) {
  if (!Number.isInteger(bytes) || bytes < 0) throw new RangeError('bytes must be a non-negative integer');
  const payload = opts.payload === undefined || opts.payload === null ? '' : String(opts.payload);
  const position = opts.position || 'end';
  if (!POSITIONS.has(position)) throw new RangeError("position must be 'start', 'middle' or 'end'");
  if (!payload) return filler(bytes);
  const block = ` ${payload} `;
  const payloadBytes = Buffer.byteLength(block, 'utf8');
  if (payloadBytes > bytes) throw new RangeError(`payload (${payloadBytes} bytes with separators) does not fit in ${bytes} bytes`);
  const rest = bytes - payloadBytes;
  if (position === 'start') return block + filler(rest);
  if (position === 'end') return filler(rest) + block;
  const half = Math.floor(rest / 2);
  return filler(half) + block + filler(rest - half);
}

/**
 * Raw request (engine contract §3.1) carrying a large text body, for engine-level tests.
 * @param {number} bytes
 * @param {{ payload?: string, position?: string, url?: string, contentType?: string }} [opts]
 */
function makeLargeRequest(bytes, opts = {}) {
  const body = makeLargeBody(bytes, opts);
  return {
    method: 'POST',
    url: opts.url || '/api/echo',
    headers: { 'user-agent': 'Mozilla/5.0 (fixture)', 'content-type': opts.contentType || 'text/plain' },
    body,
    bodyBytes: Buffer.byteLength(body, 'utf8'),
    remoteAddress: '127.0.0.1',
  };
}

module.exports = { makeLargeBody, makeLargeRequest, FILLER };
