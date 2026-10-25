import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchJson, queryOsvOnline, fetchKevOnline, buildOsvQueries, createIndex, matchPackages, NetError, NET_LIMITS } from '../src/index.js';
import { main } from '../src/cli.js';
import { fixturePath, fixtureText } from './helpers.js';

// No test here touches the network: every request goes to an injected fake
// fetch that records what would have been sent.

function fakeResponse(body, { status = 200, headers = {} } = {}) {
  const bytes = typeof body === 'string' ? Buffer.from(body) : body;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Map(Object.entries(headers)),
    body: (async function* () {
      for (let i = 0; i < bytes.length; i += 65536) yield bytes.subarray(i, i + 65536);
    })()
  };
}

const pkgs = [
  { ecosystem: 'npm', name: 'fixture-left-pad', version: '1.2.0', source: 'npm-lock' },
  { ecosystem: 'PyPI', name: 'fixturelib', version: '2.4.1', source: 'pip' },
  { ecosystem: 'Debian', name: 'fixture-openssl', version: '3.0.11-1', source: 'dpkg' }
];

function fakeOsv(calls) {
  return async (url, init) => {
    calls.push({ url, init });
    if (url === 'https://api.osv.dev/v1/querybatch') {
      const body = JSON.parse(init.body);
      return fakeResponse(JSON.stringify({ results: body.queries.map((q) => (q.package.name === 'fixture-left-pad' ? { vulns: [{ id: 'FIXTURE-2026-0001' }, { id: '../../evil' }] } : {})) }));
    }
    if (url === 'https://api.osv.dev/v1/vulns/FIXTURE-2026-0001') return fakeResponse(fixtureText('osv/FIXTURE-2026-0001.json'));
    if (url.startsWith('https://www.cisa.gov/')) return fakeResponse(fixtureText('kev.json'));
    throw new Error('unexpected url ' + url);
  };
}

test('online: sends only name, ecosystem and version; https, no redirects, no credentials', async () => {
  const calls = [];
  const index = createIndex();
  const r = await queryOsvOnline(pkgs, index, { fetchImpl: fakeOsv(calls) });
  const batch = calls.find((c) => c.url.endsWith('/querybatch'));
  assert.deepEqual(JSON.parse(batch.init.body), {
    queries: [
      { package: { name: 'fixture-left-pad', ecosystem: 'npm' }, version: '1.2.0' },
      { package: { name: 'fixturelib', ecosystem: 'PyPI' }, version: '2.4.1' }
    ]
  });
  for (const c of calls) {
    assert.ok(c.url.startsWith('https://api.osv.dev/'));
    assert.equal(c.init.redirect, 'error');
    assert.equal(c.init.credentials, 'omit');
    assert.deepEqual(Object.keys(c.init.headers).sort(), c.init.body ? ['accept', 'content-type', 'user-agent'] : ['accept', 'user-agent']);
  }
  assert.ok(!calls.some((c) => c.url.includes('evil')), 'invalid ids are never put in a URL');
  assert.equal(r.ids, 1);
  assert.ok(r.warnings[0].includes('release unknown'));
  assert.equal(matchPackages(index, pkgs).length, 1);
});

test('online: refuses non-https and unexpected hosts before any request', async () => {
  let called = false;
  const f = async () => { called = true; };
  await assert.rejects(fetchJson('http://api.osv.dev/v1/querybatch', { fetchImpl: f, maxBytes: 10 }), NetError);
  await assert.rejects(fetchJson('https://evil.invalid/x', { fetchImpl: f, maxBytes: 10 }), NetError);
  await assert.rejects(fetchJson('https://user:pw@api.osv.dev/x', { fetchImpl: f, maxBytes: 10 }), NetError);
  await assert.rejects(fetchJson('https://api.osv.dev:8443/x', { fetchImpl: f, maxBytes: 10 }), NetError);
  assert.equal(called, false);
});

test('online: response size limits (header and streamed)', async () => {
  await assert.rejects(fetchJson('https://api.osv.dev/v1/vulns/X', { maxBytes: 100, fetchImpl: async () => fakeResponse('{}', { headers: { 'content-length': '1000000' } }) }), /too large/);
  await assert.rejects(fetchJson('https://api.osv.dev/v1/vulns/X', { maxBytes: 100000, fetchImpl: async () => fakeResponse(Buffer.alloc(300000, 0x20)) }), /over 100000 bytes/);
});

test('online: timeouts, HTTP errors and non-JSON become NetError', async () => {
  // AbortSignal.timeout() timers are unref'd; a real socket keeps the event
  // loop alive, so the fake hanging request holds a ref'd timer instead.
  const hang = (url, init) => new Promise((_, reject) => {
    const keep = setInterval(() => {}, 1000);
    init.signal.addEventListener('abort', () => {
      clearInterval(keep);
      reject(init.signal.reason);
    });
  });
  await assert.rejects(fetchJson('https://api.osv.dev/v1/vulns/X', { maxBytes: 100, timeoutMs: 50, fetchImpl: hang }), /timed out/);
  await assert.rejects(fetchJson('https://api.osv.dev/v1/vulns/X', { maxBytes: 100, fetchImpl: async () => fakeResponse('x', { status: 503 }) }), /HTTP 503/);
  await assert.rejects(fetchJson('https://api.osv.dev/v1/vulns/X', { maxBytes: 100, fetchImpl: async () => fakeResponse('<html>') }), /not JSON/);
});

test('online: malformed batch response shape is rejected', async () => {
  const f = async () => fakeResponse(JSON.stringify({ results: [] }));
  await assert.rejects(queryOsvOnline(pkgs, createIndex(), { fetchImpl: f }), /unexpected querybatch/);
});

test('online: pagination tokens are followed for the affected queries only, with a round limit', async () => {
  const bodies = [];
  const f = async (url, init) => {
    if (url.endsWith('/querybatch')) {
      const body = JSON.parse(init.body);
      bodies.push(body);
      return fakeResponse(JSON.stringify({ results: body.queries.map(() => ({ vulns: [], next_page_token: 't' })) }));
    }
    throw new Error('unexpected');
  };
  const r = await queryOsvOnline(pkgs.slice(0, 2), createIndex(), { fetchImpl: f });
  assert.equal(bodies.length, NET_LIMITS.maxPageRounds);
  assert.equal(bodies[1].queries[0].page_token, 't');
  assert.ok(r.warnings.some((w) => w.includes('pagination')));
});

test('online: batches are split at the batch size', () => {
  const many = Array.from({ length: NET_LIMITS.batchSize * 2 + 1 }, (_, i) => ({ ecosystem: 'npm', name: 'p' + i, version: '1.0.0' }));
  assert.equal(buildOsvQueries(many).queries.length, many.length);
});

test('online: KEV download parsed with the same validation', async () => {
  const kev = await fetchKevOnline({ fetchImpl: fakeOsv([]) });
  assert.equal(kev.entries.size, 1);
});

test('cli --online end to end with a fake network, including --save-osv', async () => {
  const calls = [];
  const { mkdtempSync, readFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const save = (await import('node:path')).join(mkdtempSync((await import('node:path')).join(tmpdir(), 'pn-')), 'saved.json');
  let out = '';
  const code = await main(['scan', '--npm-lock', fixturePath('package-lock.json'), '--online', '--format', 'json', '--save-osv', save],
    { stdout: (s) => { out += s; }, stderr: () => {} }, { fetchImpl: fakeOsv(calls) });
  assert.equal(code, 1);
  const rep = JSON.parse(out);
  assert.equal(rep.mode, 'online');
  assert.equal(rep.findings[0].id, 'FIXTURE-2026-0001');
  assert.ok(calls.some((c) => c.url.startsWith('https://www.cisa.gov/')));
  // saved as NDJSON, one record per line
  const lines = readFileSync(save, 'utf8').trim().split('\n');
  assert.ok(lines.map((l) => JSON.parse(l).id).includes('FIXTURE-2026-0001'));
  // an existing --save-osv file is refused before any network traffic
  const before = calls.length;
  const code2 = await main(['scan', '--npm-lock', fixturePath('package-lock.json'), '--online', '--save-osv', save],
    { stdout: () => {}, stderr: () => {} }, { fetchImpl: fakeOsv(calls) });
  assert.equal(code2, 2);
  assert.equal(calls.length, before);
});
