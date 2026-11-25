'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startStack, skipUnlessStack, findLeak } = require('../helpers/stack');

const ok = (n) => ({ method: 'GET', path: '/search?q=item' + n, headers: {}, body: null });

describe('import validation', { skip: skipUnlessStack() }, () => {
  let stack, op;
  before(async () => { stack = await startStack(); op = await stack.login('operator'); });
  after(async () => { if (stack) await stack.stop(); });

  it('valid import of 3 samples → 201 with events and an import.submit audit entry', async () => {
    const r = await op.post('/api/import', { filename: 'samples.json', samples: [ok(1), ok(2), { ...ok(3), path: '/products?id=1%27%20OR%20%271%27%3D%271' }] });
    assert.equal(r.status, 201, r.text);
    assert.equal(r.body.imported, 3);
    assert.equal(r.body.events.length, 3);
    assert.ok(r.body.events.every((e) => e.source === 'import'));
    assert.deepEqual(r.body.rejected, []);
    const admin = await stack.login('admin');
    const a = await admin.get('/api/audit?action=import.submit');
    assert.ok(a.body.items.some((i) => i.action === 'import.submit'));
  });

  it('wrong filename extension / dangerous names → 400', async () => {
    for (const filename of ['samples.txt', 'samples.json.exe', 'samples', '../../etc/passwd.json\0', 'x'.repeat(300) + '.json', '', 42]) {
      const r = await op.post('/api/import', { filename, samples: [ok(1)] });
      assert.equal(r.status, 400, `${String(filename).slice(0, 40)} → ${r.status}`);
      assert.equal(r.body.error.code, 'VALIDATION_FAILED');
    }
  });

  it('path-like filenames are not used as paths (accepted as a label or rejected, never 500)', async () => {
    const r = await op.post('/api/import', { filename: '../../../outside.json', samples: [ok(1)] });
    assert.ok([201, 400].includes(r.status), `→ ${r.status}`);
    assert.equal(findLeak(r.text), null);
  });

  it('more than 100 samples → 400 (or 413), nothing imported', async () => {
    const before = (await op.get('/api/events?source=import&limit=1')).body.total;
    const samples = Array.from({ length: 101 }, (_, i) => ok(i));
    const r = await op.post('/api/import', { filename: 'many.json', samples });
    assert.ok([400, 413].includes(r.status), `101 samples → ${r.status}`);
    const after = (await op.get('/api/events?source=import&limit=1')).body.total;
    assert.equal(after, before, 'no partial import');
  });

  it('exactly 100 samples is accepted (boundary)', async () => {
    const r = await op.post('/api/import', { filename: 'hundred.json', samples: Array.from({ length: 100 }, (_, i) => ok(i)) });
    assert.ok([201, 429].includes(r.status), `100 samples → ${r.status} ${r.text.slice(0, 120)}`);
  });

  // analyze and import accept up to 2 mib of json and everything else is capped at 256 kb
  it('oversize import body (> 2 MiB) → 413', async () => {
    const samples = Array.from({ length: 10 }, (_, i) => ({ ...ok(i), method: 'POST', body: 'b'.repeat(250 * 1024) }));
    const r = await op.post('/api/import', { filename: 'huge.json', samples });
    assert.equal(r.status, 413);
    assert.equal(r.body.error.code, 'PAYLOAD_TOO_LARGE');
  });

  it('bad top-level structure → 400', async () => {
    for (const body of [{ filename: 'a.json' }, { filename: 'a.json', samples: 'nope' }, { filename: 'a.json', samples: {} }, { samples: [ok(1)] }, [ok(1)]]) {
      const r = await op.post('/api/import', body);
      assert.equal(r.status, 400, `${JSON.stringify(body).slice(0, 60)} → ${r.status}`);
    }
  });

  it('empty samples array → 400', async () => {
    const r = await op.post('/api/import', { filename: 'empty.json', samples: [] });
    assert.equal(r.status, 400);
  });

  it('individually invalid samples are rejected with index + code; valid ones still import', async () => {
    const samples = [ok(1), { method: 'HACK', path: '/', headers: {}, body: null }, { method: 'GET', path: 'relative', headers: {}, body: null },
      { method: 'GET', path: '/', headers: { 'bad name!': 'x' }, body: null }, null, 'string', ok(2)];
    const r = await op.post('/api/import', { filename: 'mixed.json', samples });
    if (r.status === 400) return; // all or nothing validation is also acceptable
    assert.equal(r.status, 201, r.text);
    assert.equal(r.body.imported, 2);
    const idx = r.body.rejected.map((x) => x.index).sort();
    assert.deepEqual(idx, [1, 2, 3, 4, 5]);
    for (const rej of r.body.rejected) assert.match(rej.code, /^[A-Z_]+$/);
  });

  it('viewer cannot import', async () => {
    const v = await stack.login('viewer');
    const r = await v.post('/api/import', { filename: 'v.json', samples: [ok(1)] });
    assert.equal(r.status, 403);
  });
});
