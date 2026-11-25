'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SERVER = path.resolve(__dirname, '..', '..', '..', 'src', 'proxy', 'server.js');

// run in a child process so the test runner's own process.emitWarning is left untouched
function runChild(body) {
  const code = `require(${JSON.stringify(SERVER)});\n${body}`;
  return spawnSync(process.execPath, ['-e', code], { encoding: 'utf8', timeout: 20000 });
}

describe('http-proxy DEP0060 filter', () => {
  it('hides the util._extend deprecation that http-proxy triggers', () => {
    const r = runChild("require('node:util')._extend({}, { a: 1 });");
    assert.equal(r.status, 0, r.stderr);
    assert.doesNotMatch(r.stderr, /DEP0060/);
  });

  it('still prints other warnings and other deprecations', () => {
    const r = runChild([
      "process.emitWarning('plain warning stays visible');",
      "process.emitWarning('other deprecation stays visible', 'DeprecationWarning', 'DEP9999');",
      "process.emitWarning('options form stays visible', { type: 'DeprecationWarning', code: 'DEP9998' });",
      "process.emitWarning('options form DEP0060 is hidden', { type: 'DeprecationWarning', code: 'DEP0060' });",
    ].join('\n'));
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stderr, /plain warning stays visible/);
    assert.match(r.stderr, /DEP9999/);
    assert.match(r.stderr, /DEP9998/);
    assert.doesNotMatch(r.stderr, /DEP0060/);
  });

  it('installs only once when the module is loaded repeatedly', () => {
    const r = runChild([
      "const { installDep0060Filter } = require(" + JSON.stringify(path.join(path.dirname(SERVER), 'silenceDep0060.js')) + ');',
      'const first = process.emitWarning;',
      'installDep0060Filter();',
      "if (process.emitWarning !== first) { console.error('double wrapped'); process.exit(1); }",
    ].join('\n'));
    assert.equal(r.status, 0, r.stderr);
  });
});
