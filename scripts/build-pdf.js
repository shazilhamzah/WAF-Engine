#!/usr/bin/env node
'use strict';
/**
 * Markdown → print-styled HTML → PDF (owner: Nufil). No new dependencies: `marked` (dev) + a locally
 * installed Chromium browser (Microsoft Edge or Google Chrome) in headless mode.
 *
 *   npm run docs:pdf                                   docs/final-report.md → docs/final-report.pdf
 *   node scripts/build-pdf.js docs/01-requirements.md  → docs/01-requirements.pdf (next to the source)
 *   node scripts/build-pdf.js a.md b.md --out-dir docs/pdf
 *   node scripts/build-pdf.js --all                    every docs/**.md → docs/pdf/<name>.pdf (+ the default)
 *   options: --out <file.pdf> (single input) · --browser <path> · --html-only · --no-toc · --keep-html
 *
 * What it does
 *  - renders Markdown with `marked` (GFM tables, fenced code), gives every heading a stable id and builds
 *    a linked table of contents from the H2/H3 headings;
 *  - inlines LOCAL images (SVG diagrams, PNG, JPG, GIF, WebP) as data: URIs so the PDF is self-contained;
 *  - applies a print stylesheet: A4, running header with the document title, "Page X of Y" footer
 *    (CSS @page margin boxes), no page breaks inside table rows / code blocks / figures;
 *  - writes the HTML to .tmp/pdf/ and prints it with
 *      <browser> --headless=new --disable-gpu --no-pdf-header-footer --print-to-pdf=<out> <file-url>
 *    using a throw-away profile in .tmp/ so an already-open browser is never touched.
 *  - The HTML has a CSP of default-src 'none' so the browser fetches nothing from the network.
 */
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const TMP = path.join(ROOT, '.tmp', 'pdf');
const DEFAULT_INPUT = path.join(ROOT, 'docs', 'final-report.md');
const PROJECT_LINE = 'WAF Studio · Proposal 44 · Class 3, Group 12';

const MIME = { '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp' };

function parseArgs(argv) {
  const a = { inputs: [], all: false, outDir: null, out: null, browser: process.env.WAF_PDF_BROWSER || null, htmlOnly: false, toc: true, keepHtml: true };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--all') a.all = true;
    else if (k === '--out-dir') a.outDir = path.resolve(argv[++i]);
    else if (k === '--out') a.out = path.resolve(argv[++i]);
    else if (k === '--browser') a.browser = argv[++i];
    else if (k === '--html-only') a.htmlOnly = true;
    else if (k === '--no-toc') a.toc = false;
    else if (k === '--keep-html') a.keepHtml = true;
    else if (k === '--help' || k === '-h') { console.log(fs.readFileSync(__filename, 'utf8').split('\n').slice(2, 26).join('\n')); process.exit(0); }
    else a.inputs.push(path.resolve(k));
  }
  return a;
}

/** Finds Edge/Chrome/Chromium. */
function findBrowser(explicit) {
  const candidates = [];
  if (explicit) candidates.push(explicit);
  if (process.platform === 'win32') {
    const pf = [process.env['ProgramFiles(x86)'], process.env.ProgramFiles, process.env.LOCALAPPDATA].filter(Boolean);
    for (const base of pf) {
      candidates.push(path.join(base, 'Microsoft', 'Edge', 'Application', 'msedge.exe'));
      candidates.push(path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe'));
      candidates.push(path.join(base, 'Chromium', 'Application', 'chrome.exe'));
    }
  } else if (process.platform === 'darwin') {
    candidates.push('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Chromium.app/Contents/MacOS/Chromium');
  } else {
    for (const name of ['microsoft-edge', 'microsoft-edge-stable', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
      const r = spawnSync('which', [name], { encoding: 'utf8' });
      if (r.status === 0 && r.stdout.trim()) candidates.push(r.stdout.trim());
    }
  }
  return candidates.find((c) => c && fs.existsSync(c)) || null;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function cssString(s) {
  // Value for a CSS string literal in @page margin boxes (Chrome does not support string-set/attr() there).
  return String(s).replace(/[\\"]/g, (c) => '\\' + c).replace(/[\r\n]/g, ' ').slice(0, 90);
}

function slugify(text, used) {
  let base = String(text).toLowerCase().replace(/<[^>]+>/g, '').replace(/&[a-z#0-9]+;/g, '').replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s+/g, '-') || 'section';
  let slug = base;
  let n = 1;
  while (used.has(slug)) slug = `${base}-${n++}`;
  used.add(slug);
  return slug;
}

/** Inlines local images referenced from the generated HTML as data URIs. */
function inlineImages(html, baseDir) {
  return html.replace(/(<img\b[^>]*?\bsrc=")([^"]+)(")/gi, (all, pre, src, post) => {
    if (/^(data:|https?:|file:)/i.test(src)) {
      if (/^https?:/i.test(src)) return `${pre}data:,${post} data-external="${escapeHtml(src)}"`; // never fetched
      return all;
    }
    const clean = decodeURIComponent(src.split('#')[0].split('?')[0]);
    const file = path.resolve(baseDir, clean);
    const ext = path.extname(file).toLowerCase();
    if (!MIME[ext] || !fs.existsSync(file) || !file.startsWith(ROOT)) return all;
    const data = fs.readFileSync(file);
    return `${pre}data:${MIME[ext]};base64,${data.toString('base64')}${post}`;
  });
}

function renderMarkdown(md, baseDir) {
  const { Marked } = require('marked');
  const used = new Set();
  const headings = [];
  const marked = new Marked({ gfm: true, breaks: false });
  marked.use({
    renderer: {
      heading(token) {
        const inner = this.parser.parseInline(token.tokens);
        const id = slugify(token.text, used);
        headings.push({ depth: token.depth, id, html: inner });
        return `<h${token.depth} id="${id}">${inner}</h${token.depth}>\n`;
      },
      link(token) {
        const text = this.parser.parseInline(token.tokens);
        let href = token.href || '';
        // Links to other local Markdown docs cannot be followed inside a PDF: keep the text, show the target.
        if (/^(?!https?:|mailto:|#)[^:]+\.md(#.*)?$/i.test(href)) return `<span class="xref">${text} <span class="xref-target">(${escapeHtml(href)})</span></span>`;
        if (href.startsWith('#')) href = '#' + slugify(href.slice(1).replace(/-/g, ' '), new Set());
        const title = token.title ? ` title="${escapeHtml(token.title)}"` : '';
        return `<a href="${escapeHtml(href)}"${title}>${text}</a>`;
      }
    }
  });
  let body = marked.parse(md);
  body = inlineImages(body, baseDir);
  // Wide tables (7+ columns, e.g. the STRIDE table) get a compact style.
  body = body.replace(/<table>\s*<thead>\s*<tr>([\s\S]*?)<\/tr>/g, (m, head) => ((head.match(/<th[\s>]/g) || []).length >= 7 ? m.replace('<table>', '<table class="wide">') : m));
  // Let long paths inside table cells break after "/" and before "." instead of mid-word.
  body = body.replace(/<td>([\s\S]*?)<\/td>/g, (cell) => cell.replace(/<code>([^<]{14,})<\/code>/g, (c, inner) => '<code>' + inner.replace(/\//g, '/<wbr>').replace(/\.(?=[a-z])/g, '<wbr>.') + '</code>'));
  // Keep short identifiers such as FR-1, NFR-10, T-final, TB2 on one line in narrow table columns.
  body = body.replace(/(<td>)([A-Z]{1,5}-[A-Za-z0-9]{1,6})(<\/td>)/g, (m, a, id, b) => a + id.replace('-', '&#8209;') + b);
  return { body, headings };
}

function buildToc(headings) {
  const items = headings.filter((h) => h.depth === 2 || h.depth === 3);
  if (items.length < 3) return '';
  const lis = items.map((h) => `<li class="toc-l${h.depth}"><a href="#${h.id}">${h.html.replace(/<a\b[^>]*>|<\/a>/g, '')}</a></li>`).join('\n');
  return `<nav class="toc" aria-label="Table of contents"><h2 class="toc-title">Contents</h2><ol>${lis}</ol></nav>`;
}

const css = (title, generated) => `
@page { size: A4; margin: 22mm 16mm 20mm 16mm;
  @top-left { content: "${cssString(title)}"; font: 8pt "Segoe UI", Arial, sans-serif; color: #6b7280; }
  @top-right { content: "${PROJECT_LINE}"; font: 8pt "Segoe UI", Arial, sans-serif; color: #6b7280; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt "Segoe UI", Arial, sans-serif; color: #6b7280; }
  @bottom-left { content: "Generated ${cssString(generated)}"; font: 8pt "Segoe UI", Arial, sans-serif; color: #9ca3af; }
}
@page :first { @top-left { content: none; } @top-right { content: none; } @bottom-left { content: none; } }
:root { --ink: #1f2937; --muted: #6b7280; --accent: #1e3a5f; --accent2: #0f766e; --rule: #d1d5db; --code-bg: #f3f4f6; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font: 10.5pt/1.5 "Segoe UI", "Helvetica Neue", Arial, sans-serif; color: var(--ink); margin: 0; background: #fff; }
.cover { height: 240mm; display: flex; flex-direction: column; justify-content: center; break-after: page; border-left: 6px solid var(--accent); padding-left: 14mm; }
.cover .kicker { color: var(--accent2); font-weight: 600; letter-spacing: .06em; text-transform: uppercase; font-size: 10pt; }
.cover h1.cover-title { font-size: 28pt; line-height: 1.15; color: var(--accent); margin: 6mm 0 4mm; border: 0; }
.cover .meta { color: var(--muted); font-size: 10.5pt; }
.toc { break-after: page; }
.toc-title { margin-top: 0; }
.toc ol { list-style: none; padding: 0; margin: 0; }
.toc li { padding: 1.2mm 0; border-bottom: 1px dotted var(--rule); }
.toc li.toc-l3 { padding-left: 7mm; font-size: 9.5pt; color: var(--muted); }
.toc a { color: inherit; text-decoration: none; }
h1, h2, h3, h4 { color: var(--accent); line-height: 1.25; break-after: avoid; page-break-after: avoid; }
h1 { font-size: 20pt; border-bottom: 2px solid var(--accent2); padding-bottom: 2mm; margin: 0 0 5mm; }
main h1:not(:first-child) { break-before: page; }
h2 { font-size: 14.5pt; margin: 8mm 0 3mm; border-bottom: 1px solid var(--rule); padding-bottom: 1mm; }
h3 { font-size: 12pt; margin: 6mm 0 2mm; }
h4 { font-size: 10.5pt; margin: 5mm 0 2mm; }
p, li { orphans: 3; widows: 3; }
a { color: var(--accent2); }
code { font: 9pt/1.4 "Cascadia Mono", Consolas, "DejaVu Sans Mono", monospace; background: var(--code-bg); padding: .5px 3px; border-radius: 3px; overflow-wrap: break-word; }
pre { background: var(--code-bg); border: 1px solid var(--rule); border-radius: 4px; padding: 3mm; white-space: pre-wrap; word-break: break-word; break-inside: avoid; font-size: 8.5pt; }
pre code { background: none; padding: 0; font-size: 8.5pt; }
table { border-collapse: collapse; width: 100%; margin: 3mm 0 5mm; font-size: 9pt; }
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }
th, td { border: 1px solid var(--rule); padding: 1.4mm 2mm; vertical-align: top; text-align: left; }
th { background: #e8eef5; color: var(--accent); }
tbody tr:nth-child(even) td { background: #fafafa; }
td code, th code { font-size: 8pt; overflow-wrap: break-word; word-break: normal; }
table.wide { font-size: 8pt; }
table.wide td, table.wide th { padding: 1mm 1.4mm; }
table.wide td code { font-size: 7.2pt; }
blockquote { margin: 3mm 0; padding: 2mm 4mm; border-left: 4px solid var(--accent2); background: #f0fdfa; color: #134e4a; }
blockquote p { margin: 1mm 0; }
img { max-width: 100%; height: auto; display: block; margin: 3mm auto; break-inside: avoid; }
hr { border: 0; border-top: 1px solid var(--rule); margin: 6mm 0; }
.xref-target { color: var(--muted); font-size: 8.5pt; }
small { color: var(--muted); }
`;

function buildHtml({ title, body, toc, sourceRel, generated }) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:">
<title>${escapeHtml(title)}</title>
<style>${css(title, generated)}</style></head>
<body data-generated="${escapeHtml(generated)}">
<section class="cover">
  <div class="kicker">${escapeHtml(PROJECT_LINE)}</div>
  <h1 class="cover-title">${escapeHtml(title)}</h1>
  <div class="meta">Source: ${escapeHtml(sourceRel)}<br>Generated: ${escapeHtml(generated)}<br>Domain: Web and Infrastructure Security</div>
</section>
${toc}
<main>
${body}
</main>
</body></html>`;
}

function printPdf(browser, htmlFile, pdfFile) {
  // A reused profile can hand printing to an older Edge process and return before the file exists.
  // Isolate each invocation from both previous builds and the user's browser session.
  const profile = fs.mkdtempSync(path.join(ROOT, '.tmp', 'pdf-profile-'));
  fs.mkdirSync(path.dirname(pdfFile), { recursive: true });
  if (fs.existsSync(pdfFile)) fs.rmSync(pdfFile);
  const args = ['--headless=new', '--disable-gpu', '--no-pdf-header-footer', `--print-to-pdf=${pdfFile}`,
    `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-extensions',
    '--disable-background-networking', '--disable-sync', '--disable-component-update', '--run-all-compositor-stages-before-draw',
    pathToFileURL(htmlFile).href];
  const r = spawnSync(browser, args, { encoding: 'utf8', timeout: 180000, windowsHide: true });
  // Some Windows browser launchers exit before their renderer finishes writing. Only accept a
  // completed PDF, and allow a bounded grace period rather than reporting a false build failure.
  let complete = false;
  const deadline = Date.now() + 10000;
  do {
    if (fs.existsSync(pdfFile)) {
      try {
        const bytes = fs.readFileSync(pdfFile);
        complete = bytes.subarray(0, 5).toString() === '%PDF-' && bytes.subarray(-1024).toString().includes('%%EOF');
      } catch { /* renderer may still hold its output file */ }
    }
    if (!complete) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  } while (!complete && Date.now() < deadline);
  if (!complete) {
    throw new Error(`browser did not produce ${path.relative(ROOT, pdfFile)} (exit ${r.status}${r.error ? ', ' + r.error.code : ''}): ${(r.stderr || '').split('\n').slice(-3).join(' ').slice(0, 300)}`);
  }
  const buf = fs.readFileSync(pdfFile);
  const pages = (buf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length;
  return { bytes: buf.length, pages };
}

function convert(input, outPdf, opts) {
  if (!fs.existsSync(input)) throw new Error(`input not found: ${path.relative(ROOT, input)}`);
  const md = fs.readFileSync(input, 'utf8');
  const h1 = /^#\s+(.+)$/m.exec(md);
  const title = h1 ? h1[1].replace(/[`*_]/g, '').trim() : path.basename(input, '.md');
  // The cover page shows the title, so drop the first H1 from the body to avoid repeating it.
  const bodyMd = h1 ? md.replace(h1[0], '') : md;
  const { body, headings } = renderMarkdown(bodyMd, path.dirname(input));
  const generated = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const html = buildHtml({ title, body, toc: opts.toc ? buildToc(headings) : '', sourceRel: path.relative(ROOT, input).replace(/\\/g, '/'), generated });
  fs.mkdirSync(TMP, { recursive: true });
  const htmlFile = path.join(TMP, path.basename(outPdf, '.pdf') + '.html');
  fs.writeFileSync(htmlFile, html);
  if (opts.htmlOnly) return { htmlFile };
  const info = printPdf(opts.browser, htmlFile, outPdf);
  return { htmlFile, ...info };
}

function listDocs() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!['pdf', 'node_modules'].includes(e.name)) walk(p); } else if (e.name.endsWith('.md')) out.push(p);
    }
  };
  walk(path.join(ROOT, 'docs'));
  const readme = path.join(ROOT, 'README.md');
  if (fs.existsSync(readme)) out.unshift(readme);
  return out;
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  const browser = a.htmlOnly ? null : findBrowser(a.browser);
  if (!a.htmlOnly && !browser) {
    console.error('[pdf] No Chromium browser found. Install Microsoft Edge or Google Chrome, or pass --browser <path> / set WAF_PDF_BROWSER. (--html-only still works.)');
    process.exit(1);
  }
  const jobs = [];
  if (a.all) {
    for (const f of listDocs()) {
      const rel = path.relative(path.join(ROOT, 'docs'), f);
      const name = rel.startsWith('..') ? path.basename(f, '.md') : rel.replace(/\.md$/, '').replace(/[\\/]/g, '__');
      jobs.push([f, path.join(a.outDir || path.join(ROOT, 'docs', 'pdf'), name + '.pdf')]);
    }
    if (fs.existsSync(DEFAULT_INPUT)) jobs.push([DEFAULT_INPUT, DEFAULT_INPUT.replace(/\.md$/, '.pdf')]);
  } else {
    const inputs = a.inputs.length ? a.inputs : [DEFAULT_INPUT];
    for (const f of inputs) {
      const out = a.out && inputs.length === 1 ? a.out : a.outDir ? path.join(a.outDir, path.basename(f, '.md') + '.pdf') : f.replace(/\.md$/i, '') + '.pdf';
      jobs.push([f, out]);
    }
  }
  if (browser) console.log(`[pdf] browser: ${browser}`);
  let failed = 0;
  for (const [input, out] of jobs) {
    try {
      const r = convert(input, out, { ...a, browser });
      if (a.htmlOnly) console.log(`[pdf] ${path.relative(ROOT, input)} → ${path.relative(ROOT, r.htmlFile)}`);
      else console.log(`[pdf] ${path.relative(ROOT, input)} → ${path.relative(ROOT, out)}  (${r.pages} pages, ${Math.round(r.bytes / 1024)} KB)`);
    } catch (e) {
      failed++;
      console.error(`[pdf] FAILED ${path.relative(ROOT, input)}: ${e.message}`);
    }
  }
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main();

module.exports = { renderMarkdown, inlineImages, slugify, buildToc, findBrowser, convert };
