'use strict';
// FR-1 request parser: validation, limits, body parsing and anomalies.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { engine, UA } = require('./helpers');

const L = engine.DEFAULT_CONFIG.limits;
const codes = (res) => res.anomalies.map((a) => a.code);
const field = (res, loc) => {
  const f = res.request.fields;
  return [f.path, ...f.query, ...f.bodyFields, ...f.cookies, ...f.headers.values()].find((x) => x.location === loc);
};

test('parses method, path, query and headers of a simple GET', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/search?q=hello&page=2', headers: { 'User-Agent': 'x', Accept: '*/*' } }, L);
  assert.equal(res.ok, true);
  assert.equal(res.error, null);
  assert.equal(res.request.method, 'GET');
  assert.equal(res.request.path, '/search');
  assert.deepEqual(res.request.queryNames, ['q', 'page']);
  assert.equal(res.request.headers['user-agent'], 'x', 'header names are lower-cased');
  assert.deepEqual(res.anomalies, []);
});

test('rejects an invalid method token as MALFORMED_REQUEST (400)', () => {
  for (const method of ['', 'GE T', 'G\r\nET', 'X'.repeat(30), 42]) {
    const res = engine.parseRequest({ method, url: '/' }, L);
    assert.equal(res.ok, false);
    assert.equal(res.error.code, 'MALFORMED_REQUEST');
    assert.equal(res.statusCode, 400);
    assert.deepEqual(codes(res), ['INVALID_METHOD']);
  }
});

test('rejects missing, non origin-form and control-character URLs', () => {
  for (const url of [undefined, '', 'search', '/a b', '/a\u0000b', '/x\ny']) {
    const res = engine.parseRequest({ method: 'GET', url }, L);
    assert.equal(res.ok, false, String(url));
    assert.deepEqual(codes(res), ['INVALID_URL']);
  }
  const abs = engine.parseRequest({ method: 'GET', url: 'http://127.0.0.1:8080/a?b=1' }, L);
  assert.equal(abs.ok, true, 'absolute-form is accepted');
  assert.equal(abs.request.path, '/a');
});

test('rejects URLs longer than maxUrlLength', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/' + 'a'.repeat(5000) }, L);
  assert.equal(res.ok, false);
  assert.deepEqual(codes(res), ['URL_TOO_LONG']);
  assert.equal(engine.parseRequest({ method: 'GET', url: '/' + 'a'.repeat(100) }, { ...L, maxUrlLength: 50 }).error.code, 'MALFORMED_REQUEST');
});

test('rejects too many headers, invalid header names and CR/LF in header values', () => {
  const many = {};
  for (let i = 0; i < 101; i++) many[`x-h${i}`] = 'v';
  assert.deepEqual(codes(engine.parseRequest({ method: 'GET', url: '/', headers: many }, L)), ['TOO_MANY_HEADERS']);
  assert.deepEqual(codes(engine.parseRequest({ method: 'GET', url: '/', headers: { 'bad name': 'v' } }, L)), ['INVALID_HEADER']);
  assert.deepEqual(codes(engine.parseRequest({ method: 'GET', url: '/', headers: { 'x-a': 'v\r\nSet-Cookie: a=b' } }, L)), ['INVALID_HEADER']);
  assert.deepEqual(codes(engine.parseRequest({ method: 'GET', url: '/', headers: { 'x-a': 'v'.repeat(20000) } }, L)), ['HEADER_TOO_LONG']);
});

test('rejects more arguments than maxArgs (query + body)', () => {
  const url = '/?' + Array.from({ length: 150 }, (_, i) => `a${i}=1`).join('&');
  const body = Array.from({ length: 60 }, (_, i) => `b${i}=1`).join('&');
  const res = engine.parseRequest({ method: 'POST', url, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }, L);
  assert.equal(res.ok, false);
  assert.deepEqual(codes(res), ['TOO_MANY_ARGS']);
});

test('body larger than maxBodyBytes is rejected with 413 BODY_TOO_LARGE (declared or actual size)', () => {
  const declared = engine.parseRequest({ method: 'POST', url: '/', body: 'small', bodyBytes: L.maxBodyBytes + 1 }, L);
  assert.equal(declared.ok, false);
  assert.equal(declared.error.code, 'BODY_TOO_LARGE');
  assert.equal(declared.statusCode, 413);
  const actual = engine.parseRequest({ method: 'POST', url: '/', body: Buffer.alloc(2048, 97) }, { ...L, maxBodyBytes: 1024, inspectBodyBytes: 512 });
  assert.equal(actual.error.code, 'BODY_TOO_LARGE');
  const exact = engine.parseRequest({ method: 'POST', url: '/', body: Buffer.alloc(1024, 97) }, { ...L, maxBodyBytes: 1024, inspectBodyBytes: 1024 });
  assert.equal(exact.ok, true, 'exactly maxBodyBytes is allowed');
});

test('body beyond inspectBodyBytes is partially inspected with an anomaly', () => {
  const res = engine.parseRequest({ method: 'POST', url: '/', headers: { 'content-type': 'text/plain' }, body: 'a'.repeat(3000) }, { ...L, inspectBodyBytes: 1000 });
  assert.equal(res.ok, true);
  assert.equal(res.request.truncated, true);
  assert.equal(res.request.inspectedBytes, 1000);
  assert.equal(res.request.bodyBytes, 3000);
  assert.deepEqual(codes(res), ['BODY_PARTIALLY_INSPECTED']);
});

test('urlencoded body fields become body.<name> with + decoded as space', () => {
  const res = engine.parseRequest({ method: 'POST', url: '/login', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'username=al+ice&password=p%40ss' }, L);
  assert.equal(res.request.bodyKind, 'form');
  assert.deepEqual(res.request.bodyNames, ['username', 'password']);
  const user = field(res, 'body.username');
  assert.ok(user.variants.some((v) => v.value === 'al ice'));
});

test('nested JSON is flattened into dotted locations', () => {
  const body = JSON.stringify({ user: { name: 'Ann', roles: ['a', 'b'] }, n: 5, ok: true, nil: null });
  const res = engine.parseRequest({ method: 'POST', url: '/api', headers: { 'content-type': 'application/json' }, body }, L);
  assert.equal(res.request.bodyKind, 'json');
  const locs = res.request.fields.bodyFields.map((f) => f.location);
  assert.deepEqual(locs, ['body.user.name', 'body.user.roles.0', 'body.user.roles.1', 'body.n', 'body.ok', 'body.nil']);
  assert.ok(res.request.bodyNames.includes('user.roles'));
});

test('invalid JSON with a JSON content type is an anomaly, body still inspected as text', () => {
  const res = engine.parseRequest({ method: 'POST', url: '/api', headers: { 'content-type': 'application/json' }, body: '{"a": ' }, L);
  assert.equal(res.ok, true);
  assert.deepEqual(codes(res), ['MALFORMED_JSON']);
  assert.equal(res.request.bodyKind, 'text');
  assert.ok(res.request.fields.body);
});

test('deeply nested JSON raises JSON_TOO_DEEP', () => {
  let body = '"x"';
  for (let i = 0; i < 40; i++) body = `{"a":${body}}`;
  const res = engine.parseRequest({ method: 'POST', url: '/api', headers: { 'content-type': 'application/json' }, body }, L);
  assert.ok(codes(res).includes('JSON_TOO_DEEP'));
});

test('multipart form fields and file names are parsed', () => {
  const body = '--B\r\nContent-Disposition: form-data; name="title"\r\n\r\nHello\r\n'
    + '--B\r\nContent-Disposition: form-data; name="file"; filename="notes.txt"\r\nContent-Type: text/plain\r\n\r\nline1\r\n--B--\r\n';
  const res = engine.parseRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'multipart/form-data; boundary=B' }, body }, L);
  assert.equal(res.request.bodyKind, 'multipart');
  assert.deepEqual(res.request.bodyFields.map((f) => [f.name, f.value]), [['title', 'Hello'], ['file', 'line1'], ['file.filename', 'notes.txt']]);
  const bad = engine.parseRequest({ method: 'POST', url: '/upload', headers: { 'content-type': 'multipart/form-data' }, body: 'x' }, L);
  assert.ok(codes(bad).includes('MALFORMED_MULTIPART'));
});

test('cookies are parsed into cookie.<name> fields', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/', headers: { cookie: 'theme=dark; lang="en"' } }, L);
  assert.deepEqual(res.request.cookies, [{ name: 'theme', value: 'dark' }, { name: 'lang', value: 'en' }]);
  assert.ok(field(res, 'cookie.theme'));
});

test('multi-round URL decoding records url steps and DOUBLE_ENCODING', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/s?q=%253Cscript%253E', headers: UA }, L);
  const q = field(res, 'query.q');
  const v = q.variants.find((x) => x.value === '<script>');
  assert.deepEqual(v.via, ['url', 'url']);
  assert.ok(codes(res).includes('DOUBLE_ENCODING'));
  const single = engine.parseRequest({ method: 'GET', url: '/s?q=100%25', headers: UA }, L);
  assert.deepEqual(codes(single), [], 'a single encoding of % is not double encoding');
});

test('decodeRounds limits how many URL decoding rounds run', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/s?q=%25253C', headers: UA }, { ...L, decodeRounds: 1 });
  const q = field(res, 'query.q');
  assert.ok(!q.variants.some((x) => x.value === '<'));
  const res3 = engine.parseRequest({ method: 'GET', url: '/s?q=%25253C', headers: UA }, { ...L, decodeRounds: 3 });
  assert.ok(field(res3, 'query.q').variants.some((x) => x.value === '<'));
});

test('%uXXXX escapes are decoded with an UNICODE_ESCAPE anomaly', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/s?q=%u003Cb%u003E', headers: UA }, L);
  const v = field(res, 'query.q').variants.find((x) => x.value === '<b>');
  assert.ok(v.via.includes('unicode_escape'));
  assert.ok(codes(res).includes('UNICODE_ESCAPE'));
});

test('HTML entities (named, decimal, hex) are decoded', () => {
  const res = engine.parseRequest({ method: 'GET', url: `/s?q=${encodeURIComponent('&lt;a&#62;&#x3C;/a&gt;&amp;amp;')}`, headers: UA }, L);
  const v = field(res, 'query.q').variants.find((x) => x.value === '<a></a>&');
  assert.ok(v, 'decoded variant present');
  assert.ok(v.via.includes('html'));
});

test('Unicode NFKC folds fullwidth characters', () => {
  const res = engine.parseRequest({ method: 'GET', url: `/s?q=${encodeURIComponent('＜script＞')}`, headers: UA }, L);
  const v = field(res, 'query.q').variants.find((x) => x.value === '<script>');
  assert.ok(v.via.includes('nfkc'));
});

test('null bytes are removed and reported as NULL_BYTE', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/f?name=a.php%00.png', headers: UA }, L);
  const v = field(res, 'query.name').variants.find((x) => x.value === 'a.php.png');
  assert.ok(v.via.includes('nullbyte'));
  const nb = res.anomalies.find((a) => a.code === 'NULL_BYTE');
  assert.equal(nb.points, 3);
});

test('invalid percent-encoding is reported as INVALID_ENCODING', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/s?q=50%zz', headers: UA }, L);
  assert.ok(codes(res).includes('INVALID_ENCODING'));
  const json = engine.parseRequest({ method: 'POST', url: '/', headers: { 'content-type': 'application/json' }, body: '{"t":"50% off"}' }, L);
  assert.deepEqual(codes(json), [], 'a literal % in JSON text is not an encoding error');
});

test('SQL comment, whitespace, lowercase and backslash variants are produced', () => {
  const res = engine.parseRequest({ method: 'GET', url: `/s?q=${encodeURIComponent('UN/**/ION\t\tSEL/*!ECT*/ a\\b')}`, headers: UA }, L);
  const vs = field(res, 'query.q').variants;
  assert.ok(vs.some((v) => v.value === 'UNION\t\tSELECT a\\b' && v.via.includes('sql_comment')));
  assert.ok(vs.some((v) => v.value === 'UN/**/ION SEL/*!ECT*/ a\\b' && v.via.includes('whitespace')));
  assert.ok(vs.some((v) => v.via.includes('lowercase') && v.value === v.value.toLowerCase()));
  assert.ok(vs.some((v) => v.via.includes('backslash') && v.value.endsWith('a/b')));
});

test('path canonicalization resolves dot segments and backslashes; escaping the root is an anomaly', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/a/./b/..%5C..%5C..%5Cetc/passwd', headers: UA }, L);
  assert.equal(res.request.canonicalPath, '/etc/passwd');
  const v = res.request.fields.path.variants.find((x) => x.via.includes('path'));
  assert.equal(v.value, '/etc/passwd');
  assert.ok(codes(res).includes('PATH_ESCAPES_ROOT'));
});

test('anomalies carry code, message and points and count once per code', () => {
  const res = engine.parseRequest({ method: 'GET', url: '/s?a=%00&b=%00', headers: UA }, L);
  const nbs = res.anomalies.filter((a) => a.code === 'NULL_BYTE');
  assert.equal(nbs.length, 1);
  for (const a of res.anomalies) {
    assert.equal(typeof a.code, 'string');
    assert.equal(typeof a.message, 'string');
    assert.equal(typeof a.points, 'number');
  }
});

test('Buffer bodies and string bodies are handled the same way', () => {
  const s = engine.parseRequest({ method: 'POST', url: '/', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'a=1' }, L);
  const b = engine.parseRequest({ method: 'POST', url: '/', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: Buffer.from('a=1') }, L);
  assert.deepEqual(s.request.bodyFields, b.request.bodyFields);
  assert.equal(b.request.bodyBytes, 3);
});

test('header named __proto__ does not pollute prototypes', () => {
  const headers = JSON.parse('{"__proto__": "x", "user-agent": "t"}');
  const res = engine.parseRequest({ method: 'GET', url: '/', headers }, L);
  assert.equal(res.ok, true);
  assert.equal(({}).polluted, undefined);
  assert.equal(Object.getPrototypeOf(res.request.headers), Object.prototype);
});
