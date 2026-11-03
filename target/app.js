'use strict';
// lab only app that is deliberately vulnerable
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');

const FILES_ROOT = path.resolve(__dirname, 'files');
const PUBLIC_DIR = path.join(FILES_ROOT, 'public');
const MAX_COMMENTS = 100;
const MAX_COMMENT_CHARS = 2000;
const MAX_ECHO_BYTES = 5 * 1024 * 1024;

const FAKE_USERS = [
  { id: 1, username: 'alice', password: 'fake-pass-alice-001', role: 'customer', email: 'alice@shop.example' },
  { id: 2, username: 'bob', password: 'fake-pass-bob-002', role: 'customer', email: 'bob@shop.example' },
  { id: 3, username: 'carol', password: 'fake-pass-carol-003', role: 'customer', email: 'carol@shop.example' },
  { id: 4, username: 'shopadmin', password: 'FAKE-LAB-FLAG{sqli-admin-bypass}', role: 'admin', email: 'admin@shop.example' }
];

const FAKE_PRODUCTS = [
  { id: 1, name: 'Packet Sniffer Mug', price: 12.5, stock: 40 },
  { id: 2, name: 'Firewall Hoodie', price: 39.0, stock: 12 },
  { id: 3, name: 'Encrypted Sticker Pack', price: 4.99, stock: 300 },
  { id: 4, name: 'Zero-Day Notebook', price: 8.75, stock: 55 },
  { id: 5, name: 'Rubber Duck (debugging edition)', price: 6.0, stock: 77 }
];

function createLabDatabase() {
  const db = new DatabaseSync(':memory:', { allowExtension: false });
  db.exec(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL,
                        role TEXT NOT NULL, email TEXT NOT NULL);
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, price REAL NOT NULL, stock INTEGER NOT NULL);
  `);
  const insU = db.prepare('INSERT INTO users (id, username, password, role, email) VALUES (?, ?, ?, ?, ?)');
  for (const u of FAKE_USERS) insU.run(u.id, u.username, u.password, u.role, u.email);
  const insP = db.prepare('INSERT INTO products (id, name, price, stock) VALUES (?, ?, ?, ?)');
  for (const p of FAKE_PRODUCTS) insP.run(p.id, p.name, p.price, p.stock);
  return db;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function page(title, bodyHtml) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${esc(title)} — Vulnerable Shop (LAB)</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;color:#1d2433;background:#fafbfc}
 .lab{background:#b00020;color:#fff;padding:8px 16px;font-weight:700;letter-spacing:.02em}
 main{max-width:860px;margin:0 auto;padding:16px} a{color:#0b5cad} code{background:#eef1f5;padding:1px 4px}
 table{border-collapse:collapse} td,th{border:1px solid #ccd;padding:4px 8px} .muted{color:#667}
</style></head>
<body><div class="lab" role="alert">LAB ONLY — deliberately vulnerable test application. Use only behind WAF Studio on localhost. All data is fake.</div>
<main><h1>${esc(title)}</h1>${bodyHtml}
<p class="muted"><a href="/">Home</a> · Vulnerable Shop · WAF Studio lab target</p></main></body></html>`;
}

function countBody(req, limit) {
  return new Promise((resolve) => {
    let bytes = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      bytes += chunk.length;
      if (bytes > limit) {
        done = true;
        req.pause();
        resolve({ bytes, tooLarge: true });
      }
    });
    req.on('end', () => { if (!done) { done = true; resolve({ bytes, tooLarge: false }); } });
    req.on('error', () => { if (!done) { done = true; resolve({ bytes, tooLarge: false, error: true }); } });
  });
}

function resolveLabFile(name) {
  if (typeof name !== 'string' || name.length === 0) return { ok: false, status: 400, reason: 'name is required' };
  if (name.length > 512 || name.includes('\0')) return { ok: false, status: 400, reason: 'invalid name' };
  // vulnerable on purpose so dot dot paths escape the public folder
  const joined = path.join(PUBLIC_DIR, name);
  // sandbox guard keeps resolved paths inside the lab files folder
  const resolved = path.resolve(joined);
  if (!isInside(resolved, FILES_ROOT)) return { ok: false, status: 403, reason: 'outside lab sandbox' };
  let real;
  try { real = fs.realpathSync(resolved); } catch { return { ok: false, status: 404, reason: 'not found' }; }
  if (!isInside(real, fs.realpathSync(FILES_ROOT))) return { ok: false, status: 403, reason: 'outside lab sandbox' };
  let st;
  try { st = fs.statSync(real); } catch { return { ok: false, status: 404, reason: 'not found' }; }
  if (!st.isFile()) return { ok: false, status: 404, reason: 'not a file' };
  if (st.size > 64 * 1024) return { ok: false, status: 413, reason: 'file too large' };
  return { ok: true, file: real };
}

function isInside(p, root) {
  const rel = path.relative(root, p);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function createTargetApp(options = {}) {
  const app = express();
  const db = createLabDatabase();
  const comments = [
    { id: 1, author: 'alice', text: 'Great mug, my packets have never been warmer.', ts: new Date(0).toISOString() }
  ];
  let nextCommentId = 2;
  const log = options.logger || (() => {});

  app.disable('x-powered-by');
  app.set('etag', false);
  app.use((req, res, next) => { res.set('X-Lab-Target', 'vulnerable-shop'); next(); });

  app.get('/', (req, res) => {
    res.type('html').send(page('Vulnerable Shop', `
<p>This is a deliberately vulnerable shop used to demonstrate WAF Studio. Every link below is an
intentionally unsafe feature. Send attacks through the WAF proxy (default <code>http://127.0.0.1:8080</code>).</p>
<ul>
 <li><a href="/search?q=mug">Search</a> — reflected XSS via <code>q</code></li>
 <li><a href="/products?id=1">Products</a> — SQL injection via <code>id</code></li>
 <li><form method="post" action="/login" style="display:inline">Login — SQL injection:
   <input name="username" placeholder="username" aria-label="username">
   <input name="password" type="password" placeholder="password" aria-label="password">
   <button>Log in</button></form></li>
 <li><a href="/comments">Comments</a> — stored XSS</li>
 <li><a href="/files?name=welcome.txt">Files</a> — path traversal via <code>name</code> (sandboxed to <code>target/files/</code>)</li>
 <li><code>POST /api/echo</code> — returns the number of body bytes received (max 5 MB)</li>
 <li><a href="/health">Health</a></li>
</ul>`));
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok', app: 'vulnerable-shop', lab: true });
  });

  // reflected xss as q goes into the html without escaping
  app.get('/search', (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q : '';
    const hits = FAKE_PRODUCTS.filter((p) => q && p.name.toLowerCase().includes(q.toLowerCase()));
    const list = hits.map((p) => `<li>${esc(p.name)} — $${p.price.toFixed(2)}</li>`).join('');
    res.type('html').send(page('Search', `
<form><input name="q" aria-label="search" value=""> <button>Search</button></form>
<p>Results for: ${q}</p>
<ul>${list || '<li>No products found.</li>'}</ul>`));
  });

  app.get('/products', (req, res) => {
    const id = typeof req.query.id === 'string' ? req.query.id : '';
    let rows;
    let sql;
    try {
      if (id) {
        sql = 'SELECT id, name, price FROM products WHERE id = ' + id;
      } else {
        sql = 'SELECT id, name, price FROM products';
      }
      rows = db.prepare(sql).all();
    } catch (e) {
      return res.status(500).type('html').send(page('Products', `<p>Database error: ${esc(e.message)}</p>`));
    }
    const wantsJson = (req.get('accept') || '').includes('application/json');
    if (wantsJson) return res.json({ items: rows.map((r) => ({ ...r })) });
    const trs = rows.map((r) => `<tr><td>${esc(r.id)}</td><td>${esc(r.name)}</td><td>${esc(r.price)}</td></tr>`).join('');
    res.type('html').send(page('Products', `<table><tr><th>id</th><th>name</th><th>price</th></tr>${trs}</table>`));
  });

  // sql injection in login
  const parsers = [express.urlencoded({ extended: false, limit: '100kb' }), express.json({ limit: '100kb' })];
  app.post('/login', parsers, (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const username = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const wantsJson = req.is('application/json') || (req.get('accept') || '').includes('application/json');
    const sql = "SELECT id, username, role FROM users WHERE username = '" + username +
      "' AND password = '" + password + "'";
    let row;
    try {
      row = db.prepare(sql).get();
    } catch (e) {
      if (wantsJson) return res.status(500).json({ ok: false, error: 'Database error: ' + e.message });
      return res.status(500).type('html').send(page('Login', `<p>Database error: ${esc(e.message)}</p>`));
    }
    if (!row) {
      if (wantsJson) return res.status(401).json({ ok: false, error: 'Invalid username or password' });
      return res.status(401).type('html').send(page('Login', '<p>Invalid username or password.</p>'));
    }
    if (wantsJson) return res.json({ ok: true, user: { id: row.id, username: row.username, role: row.role } });
    res.type('html').send(page('Login', `<p>Welcome back, ${esc(row.username)} (role: ${esc(row.role)}).</p>`));
  });

  // stored xss as comments are rendered without escaping
  app.get('/comments', (req, res) => {
    const wantsJson = (req.get('accept') || '').includes('application/json');
    if (wantsJson) return res.json({ items: comments });
    const items = comments.map((c) => `<li><b>${c.author}</b>: ${c.text}</li>`).join('');
    res.type('html').send(page('Comments', `
<form method="post" action="/comments">
 <input name="author" placeholder="name" aria-label="name"> <input name="text" placeholder="comment" aria-label="comment">
 <button>Post</button></form>
<ul>${items}</ul>`));
  });

  app.post('/comments', parsers, (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const author = (typeof body.author === 'string' && body.author ? body.author : 'anonymous').slice(0, 100);
    const text = typeof body.text === 'string' ? body.text.slice(0, MAX_COMMENT_CHARS) : '';
    if (!text) return res.status(400).json({ ok: false, error: 'text is required' });
    const c = { id: nextCommentId++, author, text, ts: new Date().toISOString() };
    comments.push(c);
    while (comments.length > MAX_COMMENTS) comments.shift();
    if (req.is('application/json') || (req.get('accept') || '').includes('application/json')) {
      return res.status(201).json({ ok: true, comment: c, count: comments.length });
    }
    res.redirect(303, '/comments');
  });

  app.get('/files', (req, res) => {
    const name = typeof req.query.name === 'string' ? req.query.name : '';
    const r = resolveLabFile(name);
    if (!r.ok) return res.status(r.status).type('text').send(`Cannot read file: ${r.reason}`);
    res.type('text').send(fs.readFileSync(r.file, 'utf8'));
  });

  app.post('/api/echo', async (req, res) => {
    const r = await countBody(req, MAX_ECHO_BYTES);
    if (r.tooLarge) {
      res.set('Connection', 'close');
      return res.status(413).json({ ok: false, error: 'body exceeds 5 MB lab cap', bytes: r.bytes });
    }
    res.json({ ok: true, bytes: r.bytes, contentType: req.get('content-type') || null });
  });

  app.use((req, res) => res.status(404).type('text').send('Not found'));
  // never leak stack traces even in the lab app
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    log('target error', err && err.type);
    const status = err && Number.isInteger(err.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
    res.status(status).type('text').send(status === 413 ? 'Payload too large' : status === 400 ? 'Bad request' : 'Server error');
  });

  app.locals.labDb = db;
  return app;
}

module.exports = { createTargetApp, resolveLabFile, FILES_ROOT, FAKE_USERS, MAX_COMMENTS, MAX_ECHO_BYTES };
