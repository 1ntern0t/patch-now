import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { buildBundle } from '../scripts/build-docs.js';

const read = (p) => readFileSync(new URL('../docs/' + p, import.meta.url), 'utf8');

test('docs/core.js is up to date with src/core (run: node scripts/build-docs.js)', () => {
  assert.equal(read('core.js'), buildBundle());
});

test('docs page has a strict CSP that blocks all network access', () => {
  const html = read('index.html');
  const m = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html);
  assert.ok(m);
  const csp = m[1];
  for (const d of ["default-src 'none'", "connect-src 'none'", "script-src 'self'", "form-action 'none'", "base-uri 'none'", "img-src 'none'", "frame-src 'none'"]) {
    assert.ok(csp.includes(d), d);
  }
  assert.ok(!/unsafe-inline|unsafe-eval|https?:/.test(csp));
  assert.ok(!/<script>[^<]/.test(html), 'no inline scripts');
  assert.ok(!/ on[a-z]+=/i.test(html), 'no inline event handlers');
});

test('docs scripts never use HTML sinks, eval or network APIs', () => {
  for (const f of ['app.js', 'core.js', 'demo.js']) {
    const src = read(f);
    for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'fetch(', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'importScripts']) {
      assert.ok(!src.includes(bad), `${f} contains ${bad}`);
    }
  }
});

test('bundle runs in a bare JS context and matches the Node modules', () => {
  const ctx = vm.createContext({});
  vm.runInContext(read('core.js') + '\n;globalThis.P = PatchNow;', ctx);
  const P = ctx.P;
  assert.equal(P.compareDebian('1.0~rc1', '1.0'), -1);
  assert.equal(P.comparePep440('1.0.dev0', '1.0a1'), -1);
  const inv = P.parsePlainList('npm fixture-left-pad 1.2.0', null);
  const idx = P.createIndex();
  P.addJsonValue(idx, JSON.parse(readFileSync(new URL('./fixtures/osv/FIXTURE-2026-0001.json', import.meta.url), 'utf8')), P.wantedKeys(inv.packages));
  const report = P.buildReport({ inventory: inv, findings: P.matchPackages(idx, inv.packages), kev: null, mode: 'browser', osvInfo: {} });
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].severity.score, 9.8);
});
