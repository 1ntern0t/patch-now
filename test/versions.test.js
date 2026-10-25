import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareSemver, compareDebian, comparePep440, compareGeneric, parsePep440, normalizePyName } from '../src/index.js';

function ascending(cmp, list) {
  for (let i = 0; i < list.length; i++) {
    for (let j = 0; j < list.length; j++) {
      const want = Math.sign(i - j);
      assert.equal(cmp(list[i], list[j]), want, `${list[i]} vs ${list[j]} should be ${want}`);
    }
  }
}

test('semver: spec precedence example (semver.org item 11)', () => {
  ascending(compareSemver, ['1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta', '1.0.0-beta', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0', '1.0.1', '1.1.0', '2.0.0', '10.0.0']);
});

test('semver: build metadata ignored, leading v accepted, missing parts padded', () => {
  assert.equal(compareSemver('1.0.0+build.1', '1.0.0+build.2'), 0);
  assert.equal(compareSemver('v1.2.3', '1.2.3'), 0);
  assert.equal(compareSemver('1.2', '1.2.0'), 0);
  assert.equal(compareSemver('1', '1.0.0'), 0);
  assert.equal(compareSemver('1.0.0-rc.1', '1.0.0-rc.01x'), -1); // numeric < alphanumeric
});

test('semver: huge numbers compare exactly (BigInt)', () => {
  assert.equal(compareSemver('9007199254740993.0.0', '9007199254740992.0.0'), 1);
});

test('semver: invalid input returns null, never a guess', () => {
  for (const bad of ['', 'abc', '1.2.3.4', '1.2.3-', '1..2', '1.2.3-a..b', ' ', null, undefined, 42, '1.2.3-é', 'x'.repeat(300)]) {
    assert.equal(compareSemver(bad, '1.0.0'), null, String(bad));
  }
});

test('debian: deb-version(7) ordering', () => {
  ascending(compareDebian, ['1.0~~', '1.0~~a', '1.0~', '1.0', '1.0-1', '1.0-1+deb12u1', '1.0-2', '1.0a', '1.0+', '1.0.', '1.0.1', '1.1~rc1', '1.1', '1:0.1', '2:0.0.1']);
});

test('debian: absent revision equals revision 0; leading zeros ignored', () => {
  assert.equal(compareDebian('1.0', '1.0-0'), 0);
  assert.equal(compareDebian('1.002', '1.2'), 0);
  assert.equal(compareDebian('0:1.0', '1.0'), 0);
});

test('debian: security-update style versions', () => {
  assert.equal(compareDebian('3.0.11-1~deb12u1', '3.0.11-1~deb12u2'), -1);
  assert.equal(compareDebian('3.0.11-1~deb12u2', '3.0.11-1'), -1);
  assert.equal(compareDebian('7.88.1-10+deb12u5', '7.88.1-10+deb12u12'), -1);
  assert.equal(compareDebian('2.36-9+deb12u4', '2.36-9'), 1);
  assert.equal(compareDebian('1.2.13.dfsg-1', '1:1.2.11'), -1);
});

test('debian: invalid versions return null', () => {
  for (const bad of ['', 'a1.0', 'x:1.0', '1.0-', '1.0 1', '1.0_1', '-1', '1:2:3', '1.0\u202e', 'é']) {
    assert.equal(compareDebian(bad, '1.0'), null, JSON.stringify(bad));
  }
});

test('pep440: ordering of dev/pre/post/local', () => {
  ascending(comparePep440, ['1.0.dev0', '1.0a1.dev1', '1.0a1', '1.0a2', '1.0b1', '1.0rc1', '1.0', '1.0+local.1', '1.0+local.2', '1.0.post1.dev0', '1.0.post1', '1.0.1', '1.1.dev1', '1!0.1']);
});

test('pep440: normalisation equivalences', () => {
  const eq = [['1.0', '1.0.0'], ['1.0-alpha1', '1.0a1'], ['1.0.RC1', '1.0rc1'], ['v1.0', '1.0'], ['1.0-1', '1.0.post1'], ['1.0c1', '1.0rc1'],
    ['1.0.preview2', '1.0rc2'], ['1.0-r4', '1.0.post4'], ['1.0.post', '1.0.post0'], ['1.0-dev', '1.0.dev0'], ['1.0a', '1.0a0'], ['0!1.0', '1.0']];
  for (const [a, b] of eq) assert.equal(comparePep440(a, b), 0, `${a} == ${b}`);
  assert.equal(normalizePyName('Fixture_Other.Lib'), 'fixture-other-lib');
});

test('pep440: local version segments (numeric > alphanumeric)', () => {
  assert.equal(comparePep440('1.0+abc', '1.0+1'), -1);
  assert.equal(comparePep440('1.0+1.a', '1.0+1'), 1);
});

test('pep440: legacy / invalid versions return null', () => {
  for (const bad of ['', 'dev', '1.0-beta-2-final', 'latest', '1.0.', '1..0', '1.0+', '1.0+a..b', 'x'.repeat(300), '1.0\u0000']) {
    assert.equal(parsePep440(bad), null, JSON.stringify(bad));
  }
});

test('generic comparator (approximate) basic ordering', () => {
  ascending(compareGeneric, ['0.9', '1.0rc1', '1.0', '1.0.1', '1.10', 'v2.0']);
  assert.equal(compareGeneric('', '1'), null);
  assert.equal(compareGeneric('...', '1'), null);
});

test('ReDoS: pathological version strings are handled quickly', () => {
  const evil = [
    '1.' + '1.'.repeat(120) + 'x',
    '1' + '0'.repeat(250) + '!',
    '1.0' + '-'.repeat(250),
    '1.0a' + '1'.repeat(200) + '!',
    'v' + '1.'.repeat(127) + '+',
    '1.0+' + 'a.'.repeat(120) + '!',
    '1:' + '~'.repeat(250),
    'CVSS:3.1/' + 'AV:N'.repeat(50)
  ];
  const start = process.hrtime.bigint();
  for (const s of evil) {
    for (let i = 0; i < 50; i++) {
      compareSemver(s, '1.0.0');
      comparePep440(s, '1.0');
      compareDebian(s, '1.0');
      compareGeneric(s, '1.0');
    }
  }
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.ok(ms < 1000, `took ${ms} ms`);
});
