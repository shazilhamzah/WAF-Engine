'use strict';
// Tests for public/js/dom.js using a tiny fake document: data must become text nodes, and
// inline handlers, style attributes and unsafe URLs must be refused.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

class FakeText {
  constructor(data) { this.nodeType = 3; this.data = data; }
}
class FakeElement {
  constructor(tag, ns) {
    this.nodeType = 1; this.tagName = tag.toUpperCase(); this.namespaceURI = ns || null;
    this.attributes = {}; this.childNodes = []; this.listeners = {}; this.dataset = {};
    this.value = ''; this.disabled = false; this.checked = false; this.hidden = false; this.required = false;
  }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  appendChild(c) { this.childNodes.push(c); return c; }
  removeChild(c) { this.childNodes = this.childNodes.filter((x) => x !== c); return c; }
  get firstChild() { return this.childNodes[0] || null; }
  addEventListener(evt, fn) { (this.listeners[evt] ||= []).push(fn); }
  set textContent(v) { this.childNodes = [new FakeText(String(v))]; }
  get textContent() { return this.childNodes.map((c) => (c.nodeType === 3 ? c.data : c.textContent)).join(''); }
}

let dom;
test.before(async () => {
  global.document = {
    createElement: (t) => new FakeElement(t),
    createElementNS: (ns, t) => new FakeElement(t, ns),
    createTextNode: (d) => new FakeText(d),
  };
  dom = await import(pathToFileURL(path.join(__dirname, '..', '..', '..', 'public', 'js', 'dom.js')).href);
});
test.after(() => { delete global.document; });

test('strings become text nodes, never markup', () => {
  const payload = '<script>alert(1)</script><img src=x onerror=alert(1)>';
  const el = dom.h('p', { class: 'x' }, payload, 42, null, false, ['a', ['b']]);
  assert.equal(el.childNodes[0].nodeType, 3);
  assert.equal(el.childNodes[0].data, payload);
  assert.equal(el.textContent, `${payload}42ab`);
  assert.equal(el.attributes.class, 'x');
  const c = dom.code(payload);
  assert.equal(c.tagName, 'CODE');
  assert.equal(c.textContent, payload);
});

test('inline event-handler, style and innerHTML attributes are refused', () => {
  assert.throws(() => dom.h('div', { onclick: 'alert(1)' }), /not allowed/);
  assert.throws(() => dom.h('div', { ONMOUSEOVER: 'x' }), /not allowed/);
  assert.throws(() => dom.h('div', { style: 'color:red' }), /not allowed/);
  assert.throws(() => dom.h('div', { innerHTML: '<b>x</b>' }), /not allowed/);
  assert.throws(() => dom.h('iframe', { srcdoc: '<script></script>' }), /not allowed/);
});

test('only same-origin, hash and blob URLs are accepted in links', () => {
  assert.throws(() => dom.h('a', { href: 'javascript:alert(1)' }), /unsafe URL/);
  assert.throws(() => dom.h('a', { href: ' JavaScript:alert(1)' }), /unsafe URL/);
  assert.throws(() => dom.h('a', { href: 'https://evil.example/' }), /unsafe URL/);
  assert.throws(() => dom.h('a', { href: '//evil.example/' }), /unsafe URL/);
  assert.throws(() => dom.h('img', { src: 'data:text/html,x' }), /unsafe URL/);
  assert.equal(dom.h('a', { href: '#/events/evt_1' }).attributes.href, '#/events/evt_1');
  assert.equal(dom.h('a', { href: '/css/app.css' }).attributes.href, '/css/app.css');
  assert.equal(dom.isSafeUrl('blob:http://127.0.0.1/abc'), true);
});

test('event listeners are attached with addEventListener and booleans map to properties', () => {
  const fn = () => {};
  const b = dom.h('button', { on: { click: fn }, disabled: true, 'aria-label': 'Go' }, 'Go');
  assert.deepEqual(b.listeners.click, [fn]);
  assert.equal(b.disabled, true);
  assert.equal(b.attributes['aria-label'], 'Go');
  assert.equal(b.attributes.onclick, undefined);
});

test('mount/clear replace children and svg helper uses the SVG namespace', () => {
  const root = dom.h('div', null, 'old');
  dom.mount(root, 'new', dom.h('span'));
  assert.equal(root.childNodes.length, 2);
  assert.equal(root.childNodes[0].data, 'new');
  dom.clear(root);
  assert.equal(root.childNodes.length, 0);
  const r = dom.s('rect', { width: 10 });
  assert.equal(r.namespaceURI, 'http://www.w3.org/2000/svg');
  assert.equal(r.attributes.width, '10');
  assert.notEqual(dom.uid(), dom.uid());
});
