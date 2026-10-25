import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { createIndex, addRecord, addJsonValue, matchPackages, matchEntry, normalizeRecord, wantedKeys, cvss3BaseScore, severityOf, parseKev, FormatError, OSV_LIMITS } from '../src/index.js';
import { fixtureJson } from './helpers.js';

function loadFixtures() {
  const index = createIndex();
  for (const f of readdirSync(new URL('./fixtures/osv/', import.meta.url))) addRecord(index, fixtureJson('osv/' + f));
  return index;
}

const pkg = (ecosystem, name, version) => ({ ecosystem, name, version, source: 'test' });

function verdicts(index, packages) {
  return matchPackages(index, packages).map((f) => `${f.pkg.name}@${f.pkg.version} ${f.record.id} ${f.match.status}`).sort();
}

test('fixtures: semver range, introduced 0 / fixed', () => {
  const idx = loadFixtures();
  assert.deepEqual(verdicts(idx, [pkg('npm', 'fixture-left-pad', '1.2.0')]), ['fixture-left-pad@1.2.0 FIXTURE-2026-0001 affected']);
  assert.deepEqual(verdicts(idx, [pkg('npm', 'fixture-left-pad', '1.2.5')]), []);
  assert.deepEqual(verdicts(idx, [pkg('npm', 'fixture-left-pad', '1.2.5-rc.1')]), ['fixture-left-pad@1.2.5-rc.1 FIXTURE-2026-0001 affected']);
});

test('fixtures: withdrawn records are ignored', () => {
  const idx = loadFixtures();
  assert.equal(idx.dropped.get('withdrawn'), 1);
  assert.ok(!idx.ids.has('FIXTURE-2026-0005'));
});

test('fixtures: PEP 440 multi-interval range and name normalisation', () => {
  const idx = loadFixtures();
  const r = (v) => verdicts(idx, [pkg('PyPI', 'fixturelib', v)]).length;
  assert.equal(r('1.9'), 0);
  assert.equal(r('2.0'), 1);
  assert.equal(r('2.4.1'), 1);
  assert.equal(r('2.4.2'), 0);
  assert.equal(r('2.9.post1'), 0);
  assert.equal(r('3.0a1'), 1);
  assert.equal(r('3.0.0'), 1);
  assert.equal(r('3.0.1'), 0);
  assert.equal(verdicts(idx, [pkg('PyPI', 'fixture-lib', '2.4.1')]).length, 0); // different normalised name
});

test('fixtures: Debian release must match; unknown release is approximate', () => {
  const idx = loadFixtures();
  assert.equal(verdicts(idx, [pkg('Debian:12', 'fixture-openssl', '3.0.11-1~deb12u1')]).length, 1);
  assert.equal(verdicts(idx, [pkg('Debian:12', 'fixture-openssl', '3.0.11-1~deb12u2')]).length, 0);
  assert.equal(verdicts(idx, [pkg('Debian:13', 'fixture-openssl', '3.0.11-1~deb12u1')]).length, 0);
  assert.equal(verdicts(idx, [pkg('Ubuntu:22.04:LTS', 'fixture-openssl', '3.0.11-1~deb12u1')]).length, 0);
  const f = matchPackages(idx, [pkg('Debian', 'fixture-openssl', '1.1.1n-0+deb11u5')]);
  assert.equal(f.length, 1);
  assert.equal(f[0].match.approximate, true);
  assert.ok(f[0].match.notes[0].includes('release unknown'));
  assert.deepEqual(verdicts(idx, [pkg('Debian:12', 'fixture-curl', '7.88.1-10+deb12u5')]), []);
});

test('fixtures: last_affected is inclusive; explicit versions list', () => {
  const idx = loadFixtures();
  assert.equal(verdicts(idx, [pkg('crates.io', 'fixture-crate', '0.9.0')]).length, 1);
  assert.equal(verdicts(idx, [pkg('crates.io', 'fixture-crate', '0.9.1')]).length, 0);
  assert.equal(verdicts(idx, [pkg('crates.io', 'fixture-crate', '0.4.9')]).length, 0);
  assert.equal(verdicts(idx, [pkg('npm', 'fixture-evil-pkg', '0.0.2')]).length, 1);
  assert.equal(verdicts(idx, [pkg('npm', 'fixture-evil-pkg', '0.0.3')]).length, 0);
});

test('unparseable versions give "unknown", never a silent "not affected"', () => {
  const idx = loadFixtures();
  assert.deepEqual(verdicts(idx, [pkg('npm', 'fixture-left-pad', 'git+https://x')]), ['fixture-left-pad@git+https://x FIXTURE-2026-0001 unknown']);
  const idx2 = createIndex();
  addRecord(idx2, { id: 'FIXTURE-X', affected: [{ package: { ecosystem: 'PyPI', name: 'p' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: 'not a version' }] }] }] });
  assert.equal(matchPackages(idx2, [pkg('PyPI', 'p', '1.0')])[0].match.status, 'unknown');
});

test('generic ecosystems are matched but marked approximate', () => {
  const idx = createIndex();
  addRecord(idx, { id: 'FIXTURE-M', affected: [{ package: { ecosystem: 'Maven', name: 'org.fixture:lib' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.17.1' }] }] }] });
  const f = matchPackages(idx, [pkg('Maven', 'org.fixture:lib', '2.14.0')]);
  assert.equal(f.length, 1);
  assert.equal(f[0].match.approximate, true);
  assert.ok(f[0].match.notes.some((n) => n.includes('generic')));
});

test('GIT-only ranges do not produce matches; record with no version data is "unknown"', () => {
  const idx = createIndex();
  addRecord(idx, { id: 'FIXTURE-G', affected: [{ package: { ecosystem: 'npm', name: 'g' }, ranges: [{ type: 'GIT', repo: 'x', events: [{ introduced: 'abc' }] }], versions: ['9.9.9'] }] });
  addRecord(idx, { id: 'FIXTURE-N', affected: [{ package: { ecosystem: 'npm', name: 'g' } }] });
  assert.deepEqual(verdicts(idx, [pkg('npm', 'g', '1.0.0')]), ['g@1.0.0 FIXTURE-N unknown']);
});

test('unsorted events are evaluated correctly', () => {
  const entry = normalizeRecord({ id: 'FIXTURE-U', affected: [{ package: { ecosystem: 'npm', name: 'u' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '2.3.0' }, { introduced: '2.0.0' }, { fixed: '1.5.0' }, { introduced: '1.0.0' }] }] }] }).record.affected[0];
  const st = (v) => matchEntry(pkg('npm', 'u', v), entry)?.status ?? 'no';
  assert.equal(st('0.9.0'), 'no');
  assert.equal(st('1.2.0'), 'affected');
  assert.equal(st('1.7.0'), 'no');
  assert.equal(st('2.1.0'), 'affected');
  assert.equal(st('2.3.0'), 'no');
});

test('fix versions only list fixes newer than the installed version', () => {
  const idx = loadFixtures();
  const f = matchPackages(idx, [pkg('PyPI', 'fixturelib', '3.0.0')]);
  assert.deepEqual(f[0].match.fixed, ['3.0.1']);
});

test('malformed records are dropped with a reason, never throw', () => {
  const idx = createIndex();
  const bad = [null, 1, 'x', [], {}, { id: '' }, { id: '../../etc/passwd' }, { id: 'A B' }, { id: 'X'.repeat(200) },
    { id: 'FIXTURE-OK', affected: 'nope' }, { id: 'FIXTURE-OK2', affected: [{ package: null }, { package: { ecosystem: 1, name: 'x' } }] },
    { id: 'FIXTURE-OK3', affected: [{ package: { ecosystem: 'npm', name: 'x' }, ranges: [{ type: 'SEMVER', events: 'bad' }, null, { events: [] }] }] }];
  for (const b of bad) assert.doesNotThrow(() => addRecord(idx, b));
  assert.equal(idx.dropped.get('not an object'), 4);
  assert.equal(idx.dropped.get('missing or invalid id'), 5);
  assert.doesNotThrow(() => addJsonValue(idx, { results: [null, { vulns: 'x' }, { vulns: [null] }] }));
  assert.doesNotThrow(() => matchPackages(idx, [pkg('npm', 'x', '1.0.0')]));
});

test('duplicate ids are only indexed once', () => {
  const idx = createIndex();
  const rec = { id: 'FIXTURE-D', affected: [{ package: { ecosystem: 'npm', name: 'd' }, versions: ['1.0.0'] }] };
  addRecord(idx, rec);
  addRecord(idx, rec);
  assert.equal(matchPackages(idx, [pkg('npm', 'd', '1.0.0')]).length, 1);
});

test('wanted filter keeps memory bounded to inventory packages', () => {
  const idx = createIndex();
  const wanted = wantedKeys([pkg('PyPI', 'Fixture_Lib', '1.0')]);
  addRecord(idx, { id: 'FIXTURE-W1', affected: [{ package: { ecosystem: 'PyPI', name: 'fixture.lib' }, versions: ['1.0'] }] }, wanted);
  addRecord(idx, { id: 'FIXTURE-W2', affected: [{ package: { ecosystem: 'PyPI', name: 'other' }, versions: ['1.0'] }] }, wanted);
  assert.equal(idx.count, 1);
  assert.equal(idx.byPackage.size, 1);
});

test('size caps: oversized arrays in a record are truncated, not processed in full', () => {
  const versions = Array.from({ length: OSV_LIMITS.maxVersions + 1000 }, (_, i) => '0.0.' + i);
  const events = Array.from({ length: OSV_LIMITS.maxEvents + 100 }, (_, i) => ({ introduced: '1.0.' + i }));
  const r = normalizeRecord({ id: 'FIXTURE-BIG', summary: 'x'.repeat(10 ** 6), affected: [{ package: { ecosystem: 'npm', name: 'b' }, versions, ranges: [{ type: 'SEMVER', events }] }] }).record;
  assert.equal(r.affected[0].versions.size, OSV_LIMITS.maxVersions);
  assert.equal(r.affected[0].ranges[0].events.length, OSV_LIMITS.maxEvents);
  assert.equal(r.summary.length, OSV_LIMITS.maxSummary);
});

test('CVSS v3 base scores match the FIRST calculator', () => {
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N'), 5.9);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'), 3.3);
  assert.equal(cvss3BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  for (const bad of ['', 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CVSS:4.0/AV:N', 'AV:N/AC:L', null]) {
    assert.equal(cvss3BaseScore(bad), null, String(bad));
  }
});

test('severity fallbacks: text labels, v4 not scored, unknown', () => {
  assert.equal(severityOf({ severity: [], database_specific: { severity: 'MODERATE' } }).rating, 'MEDIUM');
  assert.equal(severityOf({ severity: [{ type: 'Ubuntu', score: 'high' }] }).rating, 'HIGH');
  const v4 = severityOf({ severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }] });
  assert.equal(v4.rating, 'UNKNOWN');
  assert.ok(v4.basis.includes('v4'));
});

test('KEV parsing keeps only validated CVE ids (fixture)', () => {
  const kev = parseKev(fixtureJson('kev.json'));
  assert.equal(kev.entries.size, 1);
  assert.equal(kev.dropped, 1);
  assert.equal(kev.entries.get('CVE-2099-0002').dateAdded, '2099-01-01');
  assert.throws(() => parseKev({}), FormatError);
  assert.throws(() => parseKev(null), FormatError);
});
