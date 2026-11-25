#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const UA = { 'user-agent': 'Mozilla/5.0 (WAF Studio synthetic fixture)' };
const get = (value, route = '/search', name = 'q') => raw(`${route}?${name}=${encodeURIComponent(value)}`);
const raw = (url, headers = {}) => ({ method: 'GET', path: url, headers: { ...UA, ...headers }, body: null });
const post = (value, type = 'application/json', route = '/api/echo') => ({ method: 'POST', path: route, headers: { ...UA, 'content-type': type }, body: value });
const sample = (id, description, category, request, extra = {}) => ({ id, description, request, expected: { verdict: 'block', categories: [category] }, ...extra });
const file = (id, title, description, samples) => ({ case: id, title, description, samples });
const sql = [
  ['Numeric tautology', "' OR 1=1--"], ['String tautology', "' OR 'a'='a"],
  ['UNION SELECT', '1 UNION SELECT username,password FROM users'], ['UNION ALL SELECT', '1 UNION ALL SELECT 1,2'],
  ['Quote and comment', "admin'--"], ['Stacked statement (inert lab input)', '1; DROP TABLE fake_users'],
  ['Delay function signature (never executed)', '1 AND SLEEP(2)'], ['System catalog name', 'information_schema.tables'],
  ['ORDER BY column probe', "1' ORDER BY 3"], ['Database version variable', '@@version']
];
const xss = [
  ['Script tag', '<script>alert(1)</script>'], ['Image error handler', '<img src=x onerror=alert(1)>'],
  ['SVG load handler', '<svg/onload=alert(1)>'], ['JavaScript URI', 'javascript:alert(1)'],
  ['Data HTML URI', 'data:text/html,<script>alert(1)</script>'], ['Frame with JavaScript URI', '<iframe src="javascript:alert(1)"></iframe>'],
  ['Attribute break-out', '\"><img src=x onerror=alert(1)>'], ['Form focus handler', '<input autofocus onfocus=alert(1)>'],
  ['Object active content', '<object data="data:text/html,<script>alert(1)</script>"></object>'],
  ['Mixed-case script tag', '<ScRiPt>alert(1)</sCrIpT>']
];
const traversal = [
  ['Single parent segment to fake secret', '../secret/flag.txt'], ['Multiple parent segments', '../../etc/passwd'],
  ['Windows backslashes', '..\\..\\windows\\win.ini'], ['Relative path to fake config', '../config/settings.ini'],
  ['Current and parent segments', './public/../../secret/flag.txt'], ['Repeated slashes', '..//..//etc/passwd'],
  ['Absolute system file signature', '/etc/shadow'], ['File URI signature', 'file:///etc/passwd']
];

function buildFixtures() {
  const t1 = [
    ...sql.map(([d, p], i) => sample(`T1-SQLI-${String(i + 1).padStart(2, '0')}`, d, 'sqli', get(p))),
    ...xss.map(([d, p], i) => sample(`T1-XSS-${String(i + 1).padStart(2, '0')}`, d, 'xss', get(p))),
    ...traversal.map(([d, p], i) => sample(`T1-PATH-${String(i + 1).padStart(2, '0')}`, d, 'traversal', get(p, '/files', 'name')))
  ];
  const fullwidth = (s) => [...s].map((c) => c.charCodeAt(0) >= 33 && c.charCodeAt(0) <= 126 ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c).join('');
  const percentAll = (s) => [...Buffer.from(s)].map((b) => '%' + b.toString(16).padStart(2, '0')).join('');
  const t2defs = [
    ['Percent-encoded SQLi', 'sqli', get("' OR 1=1--")],
    ['Double URL encoding', 'xss', get(encodeURIComponent('<script>alert(1)</script>'))],
    ['Triple URL encoding', 'xss', get(encodeURIComponent(encodeURIComponent('<script>alert(1)</script>')))],
    ['IIS-style %u escapes', 'xss', raw('/search?q=%u003cscript%u003ealert(1)%u003c%u002fscript%u003e')],
    ['Named HTML entities', 'xss', get('&lt;script&gt;alert(1)&lt;/script&gt;')],
    ['Decimal HTML entities', 'xss', get('&#60;script&#62;alert(1)&#60;/script&#62;')],
    ['Hexadecimal HTML entities', 'xss', get('&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;')],
    ['Nested HTML entities', 'xss', get('&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;')],
    ['Mixed case SQL keywords', 'sqli', get('1 uNiOn SeLeCt 1,2')],
    ['Fullwidth NFKC script tag', 'xss', get(fullwidth('<script>alert(1)</script>'))],
    ['Null byte inside script token', 'xss', get('<scr\0ipt>alert(1)</scr\0ipt>')],
    ['Zero-width character inside token', 'xss', get('<scr\u200bipt>alert(1)</script>')],
    ['Tab-separated SQL keywords', 'sqli', get('1 UNION\tSELECT 1,2')],
    ['Newline-separated SQL keywords', 'sqli', get('1 UNION\nSELECT 1,2')],
    ['SQL comments inside keywords', 'sqli', get('1 UN/**/ION SEL/**/ECT 1,2')],
    ['URL-encoded traversal', 'traversal', raw('/files?name=%2e%2e%2fsecret%2fflag.txt')],
    ['Double URL-encoded traversal', 'traversal', get(encodeURIComponent('../secret/flag.txt'), '/files', 'name')],
    ['Encoded backslashes', 'traversal', raw('/files?name=..%5c..%5cwindows%5cwin.ini')],
    ['Overlong UTF-8 prefix plus traversal (anomaly + path evidence)', 'traversal', raw('/files?name=%c0%af../../etc/passwd')],
    ['Fully percent-encoded SQL keywords', 'sqli', raw('/search?q=' + percentAll('1 UNION SELECT 1,2'))]
  ];
  const t2 = t2defs.map(([d, c, r], i) => sample(`T2-${String(i + 1).padStart(2, '0')}`, d, c, r));
  const t5defs = [
    ['Comment-split UNION and SELECT', 'sqli', get('1 UN/**/ION SEL/**/ECT 1,2')],
    ['Mixed case and horizontal tabs', 'sqli', get('1 UnIoN\tSeLeCt 1,2')],
    ['SQL comments as spaces', 'sqli', get('1 UNION/**/SELECT 1,2')],
    ['Versioned SQL comments', 'sqli', get('1 /*!50000UNION*/ /*!50000SELECT*/ 1,2')],
    ['Nested JSON string', 'sqli', post(JSON.stringify({ search: { filter: "' OR 1=1--" } }))],
    ['JSON Unicode escapes decoded by JSON parser', 'xss', post('{"q":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}')],
    ['Duplicate parameter with complete adverse value', 'sqli', raw('/products?id=1&id=' + encodeURIComponent('1 UNION SELECT 1,2'))],
    ['Encoded dot segments', 'traversal', raw('/files?name=%252e%252e%252fsecret%252fflag.txt')],
    ['Whitespace-split JavaScript scheme', 'xss', get('j\ta\tv\ta\ts\tc\tr\ti\tp\tt:alert(1)')],
    ['Alternative SVG event vector', 'xss', get('<svg><g onload=alert(1)></g></svg>')],
    ['Form-encoded SQLi', 'sqli', post('q=' + encodeURIComponent("' OR 1=1--"), 'application/x-www-form-urlencoded')],
    ['Multipart field', 'xss', post('--waf-fixture\r\nContent-Disposition: form-data; name="q"\r\n\r\n<script>alert(1)</script>\r\n--waf-fixture--\r\n', 'multipart/form-data; boundary=waf-fixture')],
    ['Cross-parameter keyword reconstruction', 'sqli', raw('/search?a=UN&b=ION&c=SEL&d=ECT&e=1'), 'Values are matched separately; an application concatenating them could reconstruct SQL.'],
    ['Split JSON fields reconstructed by an application', 'sqli', post('{"a":"UN","b":"ION","c":"SEL","d":"ECT"}'), 'No cross-field data-flow analysis.'],
    ['Base64 payload inside an application-specific wrapper', 'xss', get(Buffer.from('<script>alert(1)</script>').toString('base64'), '/search', 'encoded'), 'The WAF does not decode arbitrary application-level base64.'],
    // T5-16 and T5-17 were documented misses until 942100/942110 learned hex literals and || concatenation
    ['Hexadecimal numeric boolean comparison', 'sqli', get('1 OR 0x31=0x31')],
    ['String-concatenated boolean comparison', 'sqli', get("' OR ('a'||'b')=('a'||'b')")],
    ['XSS split between duplicate parameters', 'xss', raw('/search?q=%3Cscr&q=ipt%3EdoSomething()%3C%2Fscr&q=ipt%3E'), 'An application joining duplicate values could reconstruct markup.']
  ];
  const t5 = t5defs.map(([d, c, r, limitation], i) => sample(`T5-${String(i + 1).padStart(2, '0')}`, d, c, r, limitation ? { knownLimitation: limitation } : {}));

  // this corpus is hand built so it is not a random sample or a holdout
  const corpus = [];
  const add = (d, c, r, extra) => corpus.push(sample(`CA-${String(corpus.length + 1).padStart(3, '0')}`, d, c, r, extra));
  for (const [d, p] of sql) { add(d + ' in query', 'sqli', get(p)); add(d + ' in JSON', 'sqli', post(JSON.stringify({ filter: p }))); }
  for (const [d, p] of sql.slice(0, 4)) add(d + ' in form', 'sqli', post('q=' + encodeURIComponent(p), 'application/x-www-form-urlencoded'));
  for (const [d, p] of xss) { add(d + ' in query', 'xss', get(p)); add(d + ' in JSON', 'xss', post(JSON.stringify({ comment: p }))); }
  for (const [d, p] of xss.slice(0, 4)) add(d + ' in form', 'xss', post('comment=' + encodeURIComponent(p), 'application/x-www-form-urlencoded'));
  for (const [d, p] of traversal) { add(d + ' in query', 'traversal', get(p, '/files', 'name')); add(d + ' double-encoded', 'traversal', get(encodeURIComponent(p), '/files', 'name')); }
  for (const p of ['127.0.0.1; cat /etc/passwd', '127.0.0.1 | whoami', '$(id)', '`whoami`']) { add('Command signature in query', 'cmdi', get(p)); add('Command signature in JSON', 'cmdi', post(JSON.stringify({ host: p }))); }
  for (const ua of ['sqlmap/1.8', 'nikto/2.5', 'Nmap Scripting Engine', 'masscan/1.3']) add('Scanner user-agent ' + ua, 'scanner', raw('/', { 'user-agent': ua }));
  // pinned by id so fixing a bypass changes the score, not which requests are in the corpus
  for (const s of t5.filter((s) => ['T5-13', 'T5-14', 'T5-15', 'T5-16'].includes(s.id))) add(s.description, s.expected.categories[0], s.request, s.knownLimitation ? { knownLimitation: s.knownLimitation } : {});
  return {
    't1-attacks.json': file('T1', 'SQLi, XSS and traversal strings', 'Synthetic signature examples, sent only to the local lab. Expected protection: block.', t1),
    't2-encoding.json': file('T2', 'Encoding and normalization variants', 'URL, repeated URL, %u, entities, case, NFKC, null/invisible characters, SQL comments, backslashes and malformed UTF-8.', t2),
    't5-bypass.json': file('T5', 'Evasion and bypass attempts', 'Expected verdict remains block even for documented misses. Cross-field/base64 examples are conditional on application interpretation, not confirmed exploits of Vulnerable Shop.', t5),
    'corpus-attack.json': file('corpus-attack', 'Controlled adverse corpus', '80 synthetic adverse requests across SQLi, XSS, traversal, command signatures, scanners and four T5 bypass classes (three still known limitations). Shares signature families with T1/T2/T5; not an independent holdout or a real-world accuracy estimate.', corpus)
  };
}

if (require.main === module) {
  for (const [name, data] of Object.entries(buildFixtures())) {
    fs.writeFileSync(path.join(__dirname, '..', 'fixtures', name), JSON.stringify(data, null, 2) + '\n');
    console.log(`${name}: ${data.samples.length} samples`);
  }
}
module.exports = { buildFixtures };
