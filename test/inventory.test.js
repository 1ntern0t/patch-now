import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDpkgStatus, parsePipList, parseNpmLock, parseNpmLs, parsePlainList, osvEcosystemFromOsRelease, INVENTORY_LIMITS, FormatError } from '../src/index.js';
import { fixtureText, fixtureJson } from './helpers.js';

const names = (inv) => inv.packages.map((p) => `${p.ecosystem} ${p.name} ${p.version}`).sort();

test('dpkg: installed only, source package name and source version (fixture)', () => {
  const inv = parseDpkgStatus(fixtureText('dpkg-status.txt'), 'Debian:12');
  assert.deepEqual(names(inv), [
    'Debian:12 fixture-curl 7.88.1-10+deb12u5',
    'Debian:12 fixture-openssl 3.0.11-1~deb12u1',
    'Debian:12 fixture-zlib 1:1.2.13.dfsg-1'
  ]);
});

test('dpkg: CRLF, missing trailing newline, junk lines', () => {
  const text = 'garbage line\r\nPackage: a\r\nStatus: install ok installed\r\nVersion: 1.0-1\r\n\r\n:\r\nPackage: b\r\nStatus: install ok installed';
  const inv = parseDpkgStatus(text, 'Debian:12');
  assert.deepEqual(names(inv), ['Debian:12 a 1.0-1']);
  assert.equal(inv.skippedCount, 1); // b has no version
});

test('os-release mapping (fixture + Ubuntu LTS + unknown)', () => {
  assert.equal(osvEcosystemFromOsRelease(fixtureText('os-release-debian12.txt')), 'Debian:12');
  assert.equal(osvEcosystemFromOsRelease('ID=ubuntu\nVERSION_ID="22.04"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n'), 'Ubuntu:22.04:LTS');
  assert.equal(osvEcosystemFromOsRelease('ID=ubuntu\nVERSION_ID="23.10"\nVERSION="23.10 (Mantic)"\n'), 'Ubuntu:23.10');
  assert.equal(osvEcosystemFromOsRelease('ID=arch\n'), null);
  assert.equal(osvEcosystemFromOsRelease('ID=debian\nVERSION_ID="12; rm -rf /"\n'), null);
});

test('pip freeze: pins kept, editable and URL installs skipped (fixture)', () => {
  const inv = parsePipList(fixtureText('pip-freeze.txt'));
  assert.deepEqual(names(inv), ['PyPI fixture-ok 3.0', 'PyPI fixture-other-lib 1.0rc1', 'PyPI fixturelib 2.4.1']);
  assert.equal(inv.skippedCount, 2);
});

test('requirements.txt: markers, extras, hashes, continuations, ranges (fixture)', () => {
  const inv = parsePipList(fixtureText('requirements.txt'));
  assert.deepEqual(names(inv), ['PyPI fixture-extra 1.0.0', 'PyPI fixturelib 2.4.1']);
  const reasons = inv.skipped.map((s) => s.name + ': ' + s.reason);
  assert.ok(reasons.some((r) => r.startsWith('fixture-range:')));
  assert.ok(reasons.some((r) => r.startsWith('fixture-wild:') && r.includes('wildcard')));
  assert.ok(reasons.some((r) => r.includes('include not followed')));
  assert.equal(inv.skippedCount, 3);
});

test('package-lock v3: nested copies, scoped names, links skipped (fixture)', () => {
  const inv = parseNpmLock(fixtureJson('package-lock.json'));
  assert.deepEqual(names(inv), [
    'npm @fixture/scoped 2.0.0-beta.3',
    'npm fixture-evil-pkg 0.0.1',
    'npm fixture-left-pad 1.2.0',
    'npm fixture-left-pad 1.3.0',
    'npm fixture-parent 0.1.0'
  ]);
});

test('package-lock v1 nested dependencies', () => {
  const inv = parseNpmLock({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } } });
  assert.deepEqual(names(inv), ['npm a 1.0.0', 'npm b 2.0.0']);
});

test('npm ls --json: nested tree, missing deps ignored (fixture)', () => {
  const inv = parseNpmLs(fixtureJson('npm-ls.json'));
  assert.deepEqual(names(inv), ['npm fixture-deep 3.1.4', 'npm fixture-left-pad 1.2.0']);
});

test('plain list: 3 columns, default ecosystem, PyPI name normalisation (fixture)', () => {
  const inv = parsePlainList(fixtureText('list.txt'), null);
  assert.deepEqual(names(inv), ['Go example.invalid/fixture/mod v1.4.0', 'PyPI fixture-lib 2.4.1', 'crates.io fixture-crate 0.9.0']);
  assert.equal(inv.skippedCount, 1);
  const inv2 = parsePlainList('a 1.0\nb 2.0', 'npm');
  assert.deepEqual(names(inv2), ['npm a 1.0', 'npm b 2.0']);
});

test('hostile: wrong JSON shapes throw FormatError, never crash', () => {
  for (const bad of [null, [], 'str', 42]) {
    assert.throws(() => parseNpmLock(bad), FormatError);
    assert.throws(() => parseNpmLs(bad), FormatError);
  }
  assert.throws(() => parseDpkgStatus(Buffer.from('x')), FormatError);
  // wrong inner types are skipped quietly
  const inv = parseNpmLock({ packages: { 'node_modules/a': 'nope', 'node_modules/b': { version: 7 }, 'node_modules/c': null } });
  assert.equal(inv.packages.length, 0);
});

test('hostile: deep npm tree is bounded and does not overflow the stack', () => {
  let tree = { version: '1.0.0' };
  for (let i = 0; i < 5000; i++) tree = { version: '1.0.0', dependencies: { ['p' + i]: tree } };
  const inv = parseNpmLs({ dependencies: { root: tree } });
  assert.ok(inv.packages.length <= INVENTORY_LIMITS.maxNpmDepth + 2);
  assert.ok(inv.warnings.some((w) => w.includes('depth')));
});

test('hostile: __proto__ / constructor package names are plain data', () => {
  const lock = JSON.parse('{"packages":{"node_modules/__proto__":{"version":"1.0.0"},"node_modules/constructor":{"version":"2.0.0"}}}');
  const inv = parseNpmLock(lock);
  assert.deepEqual(names(inv), ['npm __proto__ 1.0.0', 'npm constructor 2.0.0']);
  assert.equal({}.version, undefined);
  const inv2 = parsePlainList('npm __proto__ 1.0.0\nnpm hasOwnProperty 1.0.0', null);
  assert.equal(inv2.packages.length, 2);
});

test('hostile: control and bidi characters in names/versions are rejected', () => {
  const inv = parsePlainList('npm evil\u202epkg 1.0.0\nnpm ok 1.0\u001b[31m\nnpm zw\u200b 1.0', null);
  assert.equal(inv.packages.length, 0);
  assert.equal(inv.skippedCount, 3);
});

test('limits: very long lines skipped, skipped list capped, counts kept', () => {
  const long = 'x'.repeat(INVENTORY_LIMITS.maxLineLength + 1);
  const lines = [long];
  for (let i = 0; i < INVENTORY_LIMITS.maxSkipped + 100; i++) lines.push('four columns here ' + i);
  const inv = parsePlainList(lines.join('\n'), null);
  assert.equal(inv.skipped.length, INVENTORY_LIMITS.maxSkipped);
  assert.equal(inv.skippedCount, INVENTORY_LIMITS.maxSkipped + 101);
});

test('limits: package count is capped with a warning', () => {
  const n = INVENTORY_LIMITS.maxPackages + 10;
  const text = Array.from({ length: n }, (_, i) => 'p' + i + ' 1.0').join('\n');
  const inv = parsePlainList(text, 'npm');
  assert.equal(inv.packages.length, INVENTORY_LIMITS.maxPackages);
  assert.ok(inv.warnings.some((w) => w.includes('limit')));
});

test('ReDoS: whitespace-heavy and pathological pip lines parse quickly', () => {
  const evil = [
    'a' + ' '.repeat(8000) + '=',
    'a[' + ','.repeat(190) + '!',
    'a' + '='.repeat(8000),
    'a==' + '1'.repeat(8000),
    'a' + '\t \t'.repeat(2000) + '==1;' + ' '.repeat(2000)
  ].join('\n');
  const start = Date.now();
  for (let i = 0; i < 20; i++) parsePipList(evil);
  assert.ok(Date.now() - start < 1000);
});
