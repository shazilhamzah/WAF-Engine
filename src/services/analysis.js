'use strict';
/**
 * Console analysis (contract §5.2 analyze/import/replay): turns a validated Sample into the engine's raw
 * request, inspects it with the current shared state (rate limiter skipped), and stores the event with the
 * redacted sample so it can be replayed later.
 */
const { redactSample } = require('./redact');

/** Sample -> raw request (contract §3.1). */
function sampleToRaw(sample, remoteAddress = '127.0.0.1') {
  const headers = {};
  for (const [k, v] of Object.entries(sample.headers || {})) headers[String(k).toLowerCase()] = String(v);
  const body = typeof sample.body === 'string' ? sample.body : null;
  const bodyBytes = body === null ? 0 : Buffer.byteLength(body, 'utf8');
  if (body !== null && !('content-length' in headers)) headers['content-length'] = String(bodyBytes);
  return { method: sample.method, url: sample.path, headers, body: body === null ? null : Buffer.from(body, 'utf8'), bodyBytes, remoteAddress };
}

/**
 * @param {{ db, engineState, sample, label?, source: 'console'|'import'|'replay', user?, clientId?, replayOf? }} p
 * @returns stored Event
 */
function analyzeSample({ db, engineState, sample, label = null, source = 'console', user = null, clientId = null, replayOf = null }) {
  const engine = engineState.engine;
  const raw = sampleToRaw(sample);
  const ctx = engineState.getContext({ clientKey: clientId, withRateLimit: false });
  const started = process.hrtime.bigint();
  const decision = engine.inspect(raw, ctx);
  const measured = Number(process.hrtime.bigint() - started) / 1e6;
  const latencyMs = decision && decision.timings && Number.isFinite(decision.timings.totalMs) ? decision.timings.totalMs : measured;
  return db.events.record({
    source,
    decision,
    label,
    clientId,
    sample: redactSample(sample),
    latencyMs,
    submittedBy: user ? user.id : null,
    replayOf,
    fallback: { method: sample.method, url: sample.path, rulesetVersion: ctx.rulesetVersion, configVersion: ctx.configVersion },
  });
}

module.exports = { analyzeSample, sampleToRaw };
