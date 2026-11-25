'use strict';
// http-proxy 1.18.1 (last release 2020, unmaintained) calls util._extend on every proxied request,
// which Node >= 22 reports once per process as `DEP0060 util._extend`. The call is equivalent to
// Object.assign, so the warning is noise for operators. This drops ONLY that one deprecation code;
// every other warning (including other deprecations) still reaches stderr as normal.
// Swapping to http-proxy-3 was tried first but pulls in follow-redirects with a high-severity advisory.
// Remove this file once http-proxy is replaced.

const CODE = 'DEP0060';
const MARK = Symbol.for('waf-studio.silenceDep0060');

function warningCode(warning, args) {
  if (warning && typeof warning === 'object' && warning.code) return warning.code;
  const [typeOrOptions, code] = args;
  if (typeOrOptions && typeof typeOrOptions === 'object') return typeOrOptions.code;
  return code;
}

function installDep0060Filter() {
  if (process.emitWarning[MARK]) return;
  const original = process.emitWarning;
  function emitWarning(warning, ...args) {
    if (warningCode(warning, args) === CODE) return undefined;
    return original.call(this, warning, ...args);
  }
  emitWarning[MARK] = true;
  process.emitWarning = emitWarning;
}

module.exports = { installDep0060Filter };
