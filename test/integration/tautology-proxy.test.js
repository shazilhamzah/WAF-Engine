'use strict';
// End-to-end check for the hex-literal and || concatenation tautologies (T5-16, T5-17) that the
// engine learned on 2026-11-25: through the real proxy they must be blocked before reaching the
// Vulnerable Shop, while look-alike benign searches still pass.
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack } = require('../helpers/stack');

const q = (s) => encodeURIComponent(s);

describe('tautology variants through the WAF proxy', { skip: skipUnlessStack() }, () => {
  let stack;
  before(async () => { stack = await startStack(); });
  after(async () => { if (stack) await stack.stop(); });

  const attacks = [
    ['hex numeric tautology on /products', '/products?id=' + q('1 OR 0x31=0x31')],
    ['hex tautology with mixed case on /search', '/search?q=' + q("x' oR 0X1=0x1 -- ")],
    ['|| concatenation tautology on /search', '/search?q=' + q("' OR ('a'||'b')=('a'||'b')")],
  ];
  for (const [name, path] of attacks) {
    it(`blocks ${name}`, async () => {
      const r = await stack.proxy({ path, headers: { accept: 'text/html' } });
      assert.equal(r.status, 403, `${path} -> ${r.status}`);
      assert.equal(r.headers['x-waf-action'], 'blocked');
      assert.notEqual(r.headers['x-lab-target'], 'vulnerable-shop', 'request must not reach the target');
    });
  }

  const benign = [
    ['a hex colour code in a search', '/search?q=' + q('mug colour 0x31 or red')],
    ['a search containing ||', '/search?q=' + q('rock || roll t-shirt')],
    ['a plain product id', '/products?id=2'],
  ];
  for (const [name, path] of benign) {
    it(`allows ${name}`, async () => {
      const r = await stack.proxy({ path });
      assert.equal(r.status, 200, `${path} -> ${r.status}`);
      assert.equal(r.headers['x-waf-action'], 'allowed');
      assert.equal(r.headers['x-lab-target'], 'vulnerable-shop');
    });
  }
});
