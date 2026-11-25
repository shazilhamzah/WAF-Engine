'use strict';
// Static checks over public/**: the console must satisfy the strict CSP (script-src 'self'; style-src 'self')
// and must never turn data into markup. Fails on innerHTML/outerHTML/insertAdjacentHTML/document.write,
// eval/new Function/string timers, inline handlers (HTML attributes or el.onX = …), style attributes,
// inline <script>/<style> blocks and external URLs (CDNs, fonts).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const PUBLIC = path.join(__dirname, '..', '..', '..', 'public');
const SVG_NS = 'http://www.w3.org/2000/svg';

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const files = fs.existsSync(PUBLIC) ? walk(PUBLIC) : [];
const rel = (p) => path.relative(PUBLIC, p).split(path.sep).join('/');
const byExt = (ext) => files.filter((f) => f.endsWith(ext));

/** Removes // and /* *\/ comments (good enough for our own code; strings with // are rare and checked). */
function stripJsComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
}

function findAll(src, re) {
  const hits = [];
  const lines = src.split('\n');
  lines.forEach((line, i) => { if (re.test(line)) hits.push(`${i + 1}: ${line.trim().slice(0, 120)}`); });
  return hits;
}

test('public/ contains the SPA entry points', () => {
  for (const f of ['index.html', 'css/app.css', 'js/app.js', 'js/api.js', 'js/dom.js']) {
    assert.ok(fs.existsSync(path.join(PUBLIC, f)), `missing public/${f}`);
  }
});

test('JavaScript never builds HTML from strings or evaluates code', () => {
  const banned = [
    [/\.innerHTML\b/, 'innerHTML'],
    [/\.outerHTML\b/, 'outerHTML'],
    [/insertAdjacentHTML\s*\(/, 'insertAdjacentHTML'],
    [/document\.write(ln)?\s*\(/, 'document.write'],
    [/\beval\s*\(/, 'eval('],
    [/\bnew\s+Function\s*\(/, 'new Function'],
    [/\bset(Timeout|Interval)\s*\(\s*['"`]/, 'string timer'],
    [/createContextualFragment|DOMParser|\.srcdoc\s*=/, 'HTML parsing API'],
    [/\.on[a-z]+\s*=(?!=)/, 'inline handler property (el.onX = …)'],
    [/setAttribute\(\s*['"]on/i, 'setAttribute(on…)'],
    [/setAttribute\(\s*['"]style['"]/i, 'setAttribute(style)'],
    [/\.style\.cssText\s*=/, 'style.cssText'],
    [/\bimport\s*\(\s*['"]https?:/, 'remote import'],
  ];
  const problems = [];
  for (const file of byExt('.js')) {
    const src = stripJsComments(fs.readFileSync(file, 'utf8'));
    for (const [re, label] of banned) {
      for (const hit of findAll(src, re)) problems.push(`${rel(file)}:${hit}  [${label}]`);
    }
  }
  assert.deepEqual(problems, []);
});

test('no external URLs anywhere in public/ (no CDNs, no web fonts)', () => {
  const problems = [];
  for (const file of files.filter((f) => /\.(js|html|css|svg|json)$/.test(f))) {
    const src = fs.readFileSync(file, 'utf8').split(SVG_NS).join('');
    for (const hit of findAll(src, /\b(https?:)?\/\/[a-z0-9.-]+\.[a-z]{2,}/i)) problems.push(`${rel(file)}:${hit}`);
  }
  assert.deepEqual(problems, []);
});

test('HTML has no inline scripts, inline handlers, style attributes or <style> blocks', () => {
  const problems = [];
  for (const file of byExt('.html')) {
    const src = fs.readFileSync(file, 'utf8');
    for (const m of src.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      if (!/\bsrc\s*=/.test(m[1])) problems.push(`${rel(file)}: inline <script> without src`);
      if (m[2].trim()) problems.push(`${rel(file)}: <script> with inline content`);
    }
    for (const hit of findAll(src, /<[^>]+\son[a-z]+\s*=/i)) problems.push(`${rel(file)}:${hit} [inline handler]`);
    for (const hit of findAll(src, /<[^>]+\sstyle\s*=/i)) problems.push(`${rel(file)}:${hit} [style attribute]`);
    for (const hit of findAll(src, /<style\b/i)) problems.push(`${rel(file)}:${hit} [<style> block]`);
    for (const hit of findAll(src, /javascript:/i)) problems.push(`${rel(file)}:${hit} [javascript: URL]`);
  }
  assert.deepEqual(problems, []);
});

test('scripts are loaded as same-origin ES modules', () => {
  const html = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"[^>]*>/gi)];
  assert.ok(scripts.length >= 1);
  for (const [tag, src] of scripts) {
    assert.ok(src.startsWith('/') && !src.startsWith('//'), `script ${src} must be same-origin`);
    assert.match(tag, /type="module"/);
  }
  const links = [...html.matchAll(/<link\b[^>]*\bhref="([^"]+)"/gi)].map((m) => m[1]);
  for (const href of links) assert.ok(href.startsWith('/') && !href.startsWith('//'), `link ${href} must be same-origin`);
});

test('CSS does not import remote resources', () => {
  for (const file of byExt('.css')) {
    const src = fs.readFileSync(file, 'utf8');
    assert.ok(!/@import/i.test(src), `${rel(file)} uses @import`);
    assert.ok(!/url\(\s*['"]?(https?:|\/\/|data:text)/i.test(src), `${rel(file)} loads a remote url()`);
    assert.ok(!/expression\s*\(/i.test(src), `${rel(file)} uses CSS expression()`);
  }
});

// Attack examples are data (sent as JSON and shown via textContent), so the sample library is exempt.
const MARKUP_EXEMPT = new Set(['js/lib/samples.js']);

test('views render untrusted strings only through the DOM helper (no template-literal markup)', () => {
  const problems = [];
  for (const file of byExt('.js').filter((f) => !MARKUP_EXEMPT.has(rel(f)))) {
    const src = stripJsComments(fs.readFileSync(file, 'utf8'));
    // A template literal or string that starts with an HTML tag is a smell of string-built markup.
    for (const hit of findAll(src, /[`'"]\s*<(div|span|p|a|td|tr|table|li|ul|code|pre|img|svg|script|iframe|b|strong)\b[^`'"]*>/i)) {
      problems.push(`${rel(file)}:${hit}`);
    }
  }
  assert.deepEqual(problems, []);
});
