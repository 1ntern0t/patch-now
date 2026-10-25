// Differential check against the reference implementations, when installed:
//   dpkg --compare-versions   (Debian ordering)
//   python3 + packaging       (PEP 440 ordering)
// Not part of `npm test` because it needs those tools. Usage:
//   node scripts/cross-check.mjs [pairs-per-ecosystem]
import { spawnSync } from 'node:child_process';
import { compareDebian, comparePep440 } from '../src/index.js';

const N = Number(process.argv[2] || 2000);
let seed = 12345;
const rnd = (n) => {
  seed = (seed * 1103515245 + 12345) % 2147483648;
  return seed % n;
};
const pick = (arr) => arr[rnd(arr.length)];

function debVersion() {
  const parts = [];
  if (rnd(5) === 0) parts.push(rnd(3) + ':');
  parts.push(String(rnd(4)));
  for (let i = rnd(4); i > 0; i--) parts.push(pick(['.', '.', '+', '~']) + pick(['0', '1', '2', '10', 'a', 'b', 'rc1', 'dfsg', '']));
  if (rnd(3)) parts.push('-' + pick(['0', '1', '2', '1~deb12u1', '1+deb12u2', '10+deb12u5', '1ubuntu0.1', '0+b1', '1.1']));
  return parts.join('').replace(/^(\d+:)?([^0-9])/, '$10$2');
}

function pepVersion() {
  let v = String(rnd(3));
  for (let i = rnd(3); i > 0; i--) v += '.' + rnd(12);
  if (rnd(3) === 0) v += pick(['a', 'b', 'rc', '.alpha', '-beta', 'c', '.pre']) + pick(['', '0', '1', '2']);
  if (rnd(4) === 0) v += pick(['.post', '-', '.r', 'post']) + pick(['1', '2']);
  if (rnd(4) === 0) v += pick(['.dev', 'dev', '-dev']) + pick(['', '0', '3']);
  if (rnd(6) === 0) v += '+' + pick(['1', 'abc', 'ubuntu.1', '1.a', 'a.1']);
  if (rnd(8) === 0) v = pick(['v', '1!', 'V']) + v;
  return v;
}

let mismatches = 0;
const dpkg = spawnSync('dpkg', ['--version']);
if (dpkg.status === 0) {
  let checked = 0;
  for (let i = 0; i < N; i++) {
    const a = debVersion();
    const b = debVersion();
    const ours = compareDebian(a, b);
    if (ours === null) continue;
    const lt = spawnSync('dpkg', ['--compare-versions', a, 'lt', b]).status === 0;
    const eq = spawnSync('dpkg', ['--compare-versions', a, 'eq', b]).status === 0;
    const ref = lt ? -1 : eq ? 0 : 1;
    checked++;
    if (ref !== ours) {
      mismatches++;
      console.log(`dpkg mismatch: ${a} vs ${b}: dpkg ${ref}, ours ${ours}`);
    }
  }
  console.log(`dpkg: ${checked} pairs compared`);
} else {
  console.log('dpkg not found; skipped');
}

const pairs = [];
for (let i = 0; i < N; i++) pairs.push([pepVersion(), pepVersion()]);
const py = spawnSync('python3', ['-c', `
import sys, json
from packaging.version import Version, InvalidVersion
out = []
for a, b in json.load(sys.stdin):
    try:
        va, vb = Version(a), Version(b)
        out.append(-1 if va < vb else (1 if va > vb else 0))
    except InvalidVersion:
        out.append(None)
print(json.dumps(out))
`], { input: JSON.stringify(pairs) });
if (py.status === 0) {
  const ref = JSON.parse(py.stdout.toString());
  let checked = 0;
  pairs.forEach(([a, b], i) => {
    const ours = comparePep440(a, b);
    if (ref[i] === null && ours === null) return;
    checked++;
    if (ref[i] !== ours) {
      mismatches++;
      console.log(`pep440 mismatch: ${a} vs ${b}: packaging ${ref[i]}, ours ${ours}`);
    }
  });
  console.log(`pep440: ${checked} pairs compared`);
} else {
  console.log('python3 packaging not available; skipped');
}
console.log(`mismatches: ${mismatches}`);
process.exitCode = mismatches ? 1 : 0;
