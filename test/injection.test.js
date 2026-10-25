import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIndex, addRecord, matchPackages, buildReport, renderText, renderJson, newInventory, parseKev, safeText, safeJson, compareFindings, mergeAliases } from '../src/index.js';
import { INJECTIONS, RAW_UNSAFE } from './helpers.js';

function hostileReport() {
  const idx = createIndex();
  const inv = newInventory();
  INJECTIONS.forEach((text, i) => {
    const name = 'fixture-inj-' + i;
    inv.packages.push({ ecosystem: 'npm', name, version: '1.0.0', source: 'test' });
    addRecord(idx, {
      id: 'FIXTURE-INJ-' + i,
      aliases: ['CVE-2099-' + String(1000 + i), text],
      summary: text,
      details: text,
      severity: [{ type: 'CVSS_V3', score: text }, { type: text, score: 'high' }],
      database_specific: { severity: text },
      affected: [{ package: { ecosystem: 'npm', name }, versions: ['1.0.0'], ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: text }] }] }]
    });
  });
  const kev = parseKev({ catalogVersion: INJECTIONS[2], vulnerabilities: [{ cveID: 'CVE-2099-1000', dateAdded: INJECTIONS[0], knownRansomwareCampaignUse: INJECTIONS[3] }] });
  return buildReport({ inventory: inv, findings: matchPackages(idx, inv.packages), kev, mode: 'offline', osvInfo: {} });
}

test('text report contains no raw control, ANSI or bidi characters', () => {
  const out = renderText(hostileReport());
  assert.ok(!RAW_UNSAFE.test(out), 'raw unsafe character found');
  assert.ok(!out.includes('\u001b'));
  assert.ok(out.includes('\\u001b[2J'), 'ESC shown escaped');
  assert.ok(out.includes('\\u202e'), 'bidi override shown escaped');
});

test('JSON report round-trips the original strings but its bytes are inert', () => {
  const report = hostileReport();
  const json = renderJson(report);
  assert.ok(!RAW_UNSAFE.test(json));
  const back = JSON.parse(json);
  const summaries = back.findings.map((f) => f.summary);
  for (const s of INJECTIONS) assert.ok(summaries.includes(s), 'lossless: ' + JSON.stringify(s));
});

test('invalid aliases and bogus severities from hostile records are dropped', () => {
  const report = hostileReport();
  for (const f of report.findings) {
    assert.ok(f.aliases.every((a) => /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(a)));
    assert.equal(f.severity.rating, 'HIGH'); // from the valid "high" label only
    assert.equal(f.severity.score, null);
    assert.match(f.severity.basis, /^source severity label \([A-Za-z0-9_]{1,20}\)$/);
    assert.ok(f.url.startsWith('https://osv.dev/vulnerability/FIXTURE-INJ-'));
  }
});

test('KEV fields from hostile input are validated or clamped', () => {
  const report = hostileReport();
  const k = report.findings.find((f) => f.known_exploited);
  assert.equal(k.known_exploited.dateAdded, null);
  assert.ok(k.known_exploited.ransomware.length <= 20);
});

test('nothing in the hostile report is executed or pollutes prototypes', () => {
  hostileReport();
  assert.equal(globalThis.__pwned, undefined);
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal({}.version, undefined);
});

test('safeText truncates before escaping and handles non-strings', () => {
  assert.equal(safeText('a'.repeat(10), 3), 'aaa…[truncated]');
  assert.equal(safeText(null), '');
  assert.equal(safeText({ toString: () => '\u001bX' }), '\\u001bX');
  assert.equal(safeJson({ a: '\u202e' }, 0), '{"a":"\\u202e"}');
});

test('ordering: KEV first, then malicious, then severity, then name', () => {
  const mk = (pkg, rating, score, kev, mal) => ({ package: pkg, id: 'X', severity: { rating, score }, known_exploited: kev ? {} : null, malicious_package: mal });
  const list = [mk('a', 'CRITICAL', 9.8, false, false), mk('b', 'LOW', 2, true, false), mk('c', 'UNKNOWN', null, false, true), mk('d', 'HIGH', 7.5, false, false), mk('e', 'CRITICAL', 10, false, false), mk('f', 'UNKNOWN', null, false, false), mk('g', 'LOW', 3, false, false)];
  assert.deepEqual(list.sort(compareFindings).map((f) => f.package), ['b', 'c', 'e', 'a', 'd', 'f', 'g']);
});

test('aliases: GHSA/PYSEC duplicates merge into one finding, keeping KEV and all fixes', () => {
  const base = { package: 'p', ecosystem: 'PyPI', installed: '1.0', match: { status: 'affected', approximate: false }, malicious_package: false };
  const list = [
    { ...base, id: 'GHSA-aaaa', aliases: ['CVE-2099-1'], severity: { rating: 'HIGH', score: 7.5 }, known_exploited: null, fixed_versions: ['1.1'] },
    { ...base, id: 'PYSEC-1', aliases: ['CVE-2099-1'], severity: { rating: 'UNKNOWN', score: null }, known_exploited: { cve: 'CVE-2099-1' }, fixed_versions: ['2.0'] },
    { ...base, id: 'PYSEC-2', aliases: ['CVE-2099-2'], severity: { rating: 'LOW', score: 2 }, known_exploited: null, fixed_versions: [] },
    { ...base, installed: '2.0', id: 'PYSEC-3', aliases: ['CVE-2099-1'], severity: { rating: 'LOW', score: 2 }, known_exploited: null, fixed_versions: [] }
  ];
  const merged = mergeAliases(list);
  assert.equal(merged.length, 3);
  const m = merged.find((f) => f.also_known_as.includes('GHSA-aaaa') || f.id === 'GHSA-aaaa');
  assert.ok(m.known_exploited);
  assert.deepEqual(m.fixed_versions.sort(), ['1.1', '2.0']);
  // a record that links two groups merges them
  const bridged = mergeAliases([
    { ...base, id: 'A', aliases: [], severity: { rating: 'LOW', score: 1 }, known_exploited: null, fixed_versions: [] },
    { ...base, id: 'B', aliases: [], severity: { rating: 'LOW', score: 1 }, known_exploited: null, fixed_versions: [] },
    { ...base, id: 'C', aliases: ['A', 'B'], severity: { rating: 'LOW', score: 1 }, known_exploited: null, fixed_versions: [] }
  ]);
  assert.equal(bridged.length, 1);
  assert.deepEqual(bridged[0].also_known_as.length, 2);
});

test('fuzz: hostile strings never make a parser slow (ReDoS guard)', async () => {
  const P = await import('../src/index.js');
  const fns = [
    (s) => P.parsePep440(s), (s) => P.parseSemver(s), (s) => P.parseDebianVersion(s),
    (s) => P.parsePipList(s), (s) => P.parsePlainList(s, 'npm'),
    (s) => P.parseDpkgStatus('Package: a\nStatus: install ok installed\nVersion: ' + s + '\nSource: ' + s + '\n'),
    (s) => P.osvEcosystemFromOsRelease('ID=debian\nVERSION_ID=' + s + '\n'),
    (s) => P.compareGeneric(s, s + 'x'), (s) => P.safeText(s, 1e6)
  ];
  const alpha = ['1', '.', '-', '_', 'a', 'rc', 'post', 'dev', '+', '0', ' ', '"', '\t', '=', '==', ';', '#', '~', ':', 'AV:N/', '/', 'x', '!'];
  const cands = [];
  for (const a of alpha) for (const b of alpha) cands.push(a.repeat(4000) + b, (a + b).repeat(2000) + '!');
  let worst = 0;
  for (const f of fns) {
    for (const s of cands) {
      const t = Date.now();
      try {
        f(s);
      } catch (e) {
        if (!(e instanceof P.FormatError)) throw e;
      }
      worst = Math.max(worst, Date.now() - t);
    }
  }
  // generous bound so slow CI machines do not flake; real worst case measured ~5 ms
  assert.ok(worst < 1000, `slowest call took ${worst} ms`);
});
