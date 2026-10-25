import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixturePath, RAW_UNSAFE } from './helpers.js';
import { main } from '../src/cli.js';
import { loadOsvPath, createIndex, InputError, readLimited } from '../src/index.js';

const BIN = new URL('../bin/patch-now.js', import.meta.url).pathname;
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', timeout: 30000 });

async function runMain(args, deps) {
  let out = '';
  let err = '';
  const code = await main(args, { stdout: (s) => { out += s; }, stderr: (s) => { err += s; } }, deps);
  return { code, out, err };
}

const ALL_INV = ['--dpkg', fixturePath('dpkg-status.txt'), '--os-release', fixturePath('os-release-debian12.txt'),
  '--npm-lock', fixturePath('package-lock.json'), '--pip', fixturePath('pip-freeze.txt'), '--list', fixturePath('list.txt')];

test('cli: offline scan over fixtures, prioritised JSON, exit 1 on findings', () => {
  const r = run('scan', ...ALL_INV, '--osv', fixturePath('osv'), '--kev', fixturePath('kev.json'), '--format', 'json');
  assert.equal(r.status, 1, r.stderr);
  const rep = JSON.parse(r.stdout);
  assert.equal(rep.mode, 'offline');
  assert.deepEqual(rep.findings.map((f) => f.id), ['FIXTURE-2026-0002', 'MAL-2099-0001', 'FIXTURE-2026-0001', 'FIXTURE-2026-0003', 'FIXTURE-2026-0006']);
  assert.equal(rep.findings[0].known_exploited.cve, 'CVE-2099-0002');
  assert.equal(rep.summary.known_exploited, 1);
  assert.equal(rep.summary.malicious_packages, 1);
  assert.ok(rep.attribution.some((a) => a.includes('OSV')));
});

test('cli: text output, no findings gives exit 0 and a clear caveat', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  writeFileSync(join(dir, 'l.txt'), 'npm fixture-safe 1.0.0\n');
  const r = run('scan', '--list', join(dir, 'l.txt'), '--osv', fixturePath('osv'));
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /NOT proof/);
  assert.match(r.stdout, /no KEV catalog loaded/);
});

test('cli: refuses to run without advisory data and never goes online by default', async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
    throw new Error('network used');
  };
  const r = await runMain(['scan', '--list', fixturePath('list.txt')], { fetchImpl });
  assert.equal(r.code, 2);
  assert.match(r.err, /--online/);
  const r2 = await runMain(['scan', '--list', fixturePath('list.txt'), '--osv', fixturePath('osv')], { fetchImpl });
  assert.equal(r2.code, 1);
  assert.equal(called, false);
});

test('cli: show-query prints only name/ecosystem/version and sends nothing', async () => {
  let called = false;
  const r = await runMain(['show-query', ...ALL_INV], { fetchImpl: async () => { called = true; } });
  assert.equal(r.code, 0);
  assert.equal(called, false);
  const q = JSON.parse(r.out);
  for (const item of q.queries) {
    assert.deepEqual(Object.keys(item).sort(), ['package', 'version']);
    assert.deepEqual(Object.keys(item.package).sort(), ['ecosystem', 'name']);
  }
  assert.ok(!r.out.includes(fixturePath('')), 'no local paths in the query');
});

test('cli: inventory command and usage errors', () => {
  const r = run('inventory', '--pip', fixturePath('requirements.txt'));
  assert.equal(r.status, 0);
  assert.match(r.stdout, /PyPI\tfixturelib\t2.4.1\tpip/);
  assert.equal(run('scan').status, 2);
  assert.equal(run('bogus', '--list', fixturePath('list.txt')).status, 2);
  assert.equal(run('--nope').status, 2);
  assert.equal(run('scan', '--list', fixturePath('list.txt'), '--osv', fixturePath('osv'), '--format', 'html').status, 2);
  assert.equal(run('scan', '--list', fixturePath('list.txt'), '--online', '--timeout-ms', '5').status, 2);
  assert.equal(run('--help').status, 0);
  assert.match(run('--version').stdout, /patch-now 0\.1\.0/);
});

test('cli: --out refuses to overwrite without --force', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  const out = join(dir, 'r.json');
  writeFileSync(out, 'keep me');
  const args = ['scan', '--list', fixturePath('list.txt'), '--osv', fixturePath('osv'), '--format', 'json', '--out', out];
  const r = run(...args);
  assert.equal(r.status, 2);
  assert.equal(readFileSync(out, 'utf8'), 'keep me');
  const r2 = run(...args, '--force');
  assert.equal(r2.status, 1);
  assert.ok(JSON.parse(readFileSync(out, 'utf8')).findings.length > 0);
});

test('cli: missing files, directories and devices are input errors (exit 2)', () => {
  assert.equal(run('scan', '--list', '/nonexistent/x', '--osv', fixturePath('osv')).status, 2);
  assert.equal(run('scan', '--list', tmpdir(), '--osv', fixturePath('osv')).status, 2);
  if (existsSync('/dev/zero')) {
    const r = run('scan', '--list', '/dev/zero', '--osv', fixturePath('osv'));
    assert.equal(r.status, 2);
    assert.match(r.stderr, /not a regular file/);
  }
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  writeFileSync(join(dir, 'bad.json'), '{not json');
  assert.equal(run('scan', '--npm-lock', join(dir, 'bad.json'), '--osv', fixturePath('osv')).status, 2);
  assert.equal(run('scan', '--npm-lock', fixturePath('list.txt'), '--osv', fixturePath('osv')).status, 2);
});

test('cli: hostile file names and contents are echoed escaped', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  const evil = join(dir, 'x\u001b[31m\u202e.txt');
  const r = run('scan', '--list', evil, '--osv', fixturePath('osv'));
  assert.equal(r.status, 2);
  assert.ok(!RAW_UNSAFE.test(r.stderr), JSON.stringify(r.stderr));
});

test('size limit: readLimited rejects files over the limit', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  const p = join(dir, 'big');
  writeFileSync(p, Buffer.alloc(2048, 0x61));
  await assert.rejects(readLimited(p, 1024), InputError);
  assert.equal((await readLimited(p, 4096)).length, 2048);
});

test('OSV directory walk: symlinks not followed, depth and per-file size limits', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  const outside = mkdtempSync(join(tmpdir(), 'pn-out-'));
  writeFileSync(join(outside, 'secret.json'), JSON.stringify({ id: 'FIXTURE-OUTSIDE', affected: [{ package: { ecosystem: 'npm', name: 'o' }, versions: ['1.0.0'] }] }));
  symlinkSync(join(outside, 'secret.json'), join(dir, 'link.json'));
  symlinkSync(outside, join(dir, 'linkdir'));
  let deep = dir;
  for (let i = 0; i < 8; i++) {
    deep = join(deep, 'd' + i);
    mkdirSync(deep);
  }
  writeFileSync(join(deep, 'deep.json'), JSON.stringify({ id: 'FIXTURE-DEEP', affected: [{ package: { ecosystem: 'npm', name: 'o' }, versions: ['1.0.0'] }] }));
  writeFileSync(join(dir, 'big.json'), JSON.stringify({ id: 'FIXTURE-BIG', summary: 'x'.repeat(5000), affected: [{ package: { ecosystem: 'npm', name: 'o' }, versions: ['1.0.0'] }] }));
  writeFileSync(join(dir, 'ok.json'), JSON.stringify({ id: 'FIXTURE-OK', affected: [{ package: { ecosystem: 'npm', name: 'o' }, versions: ['1.0.0'] }] }));
  writeFileSync(join(dir, 'garbage.json'), '\u0000\u0001 not json');
  writeFileSync(join(dir, 'notes.txt'), 'ignored');
  const index = createIndex();
  await loadOsvPath(dir, index, null, { osvDirFileBytes: 1024, osvDirFiles: 100, osvDirDepth: 4, osvFileBytes: 1e6 });
  assert.deepEqual([...index.ids], ['FIXTURE-OK']);
  assert.equal(index.dropped.get('file over size limit or unreadable'), 1);
  assert.equal(index.dropped.get('unparseable file'), 1);
  rmSync(dir, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
});

test('OSV input formats: array file, NDJSON, API-style wrapper', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  const rec = (id) => ({ id, affected: [{ package: { ecosystem: 'npm', name: 'o' }, versions: ['1.0.0'] }] });
  writeFileSync(join(dir, 'a.json'), JSON.stringify([rec('FIXTURE-A1'), rec('FIXTURE-A2')]));
  writeFileSync(join(dir, 'b.ndjson'), JSON.stringify(rec('FIXTURE-B1')) + '\n\n' + JSON.stringify(rec('FIXTURE-B2')) + '\n{broken\n');
  writeFileSync(join(dir, 'c.json'), JSON.stringify({ vulns: [rec('FIXTURE-C1')] }));
  writeFileSync(join(dir, 'd.txt'), 'nothing useful here');
  for (const [f, want] of [['a.json', 2], ['b.ndjson', 2], ['c.json', 1]]) {
    const idx = createIndex();
    await loadOsvPath(join(dir, f), idx, null);
    assert.equal(idx.count, want, f);
  }
  await assert.rejects(loadOsvPath(join(dir, 'd.txt'), createIndex(), null), InputError);
});

test('a FIFO given as input is refused instead of hanging', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  const fifo = join(dir, 'pipe');
  if (spawnSync('mkfifo', [fifo]).status !== 0) {
    t.skip('mkfifo not available');
    return;
  }
  const started = Date.now();
  const r = run('inventory', '--pip', fifo);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /not a regular file/);
  assert.ok(Date.now() - started < 5000);
  // a FIFO inside an OSV directory is skipped, not opened
  writeFileSync(join(dir, 'ok.json'), JSON.stringify({ id: 'FIXTURE-OK', affected: [{ package: { ecosystem: 'npm', name: 'o' }, versions: ['1.0.0'] }] }));
  const index = createIndex();
  await loadOsvPath(dir, index, null);
  assert.deepEqual([...index.ids], ['FIXTURE-OK']);
  rmSync(dir, { recursive: true, force: true });
});

test('OSV directory walk: total entry limit', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'pn-'));
  for (let i = 0; i < 20; i++) writeFileSync(join(dir, 'n' + i + '.txt'), '');
  await assert.rejects(loadOsvPath(dir, createIndex(), null, { osvDirFileBytes: 1024, osvDirFiles: 100, osvDirDepth: 4, osvDirEntries: 10, osvFileBytes: 1e6 }), InputError);
  rmSync(dir, { recursive: true, force: true });
});
