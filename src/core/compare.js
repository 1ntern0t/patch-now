import { compareSemver } from './semver.js';
import { compareDebian } from './debian.js';
import { comparePep440 } from './pep440.js';

// Fallback for ecosystems without a dedicated implementation: splits into
// digit and non-digit runs and compares runs pairwise (digits numerically).
// This is APPROXIMATE and every match made with it is labelled as such.
const TOKEN_RE = /\d{1,32}|[^\d.\-_+]{1,64}/g;
const MAX_VERSION_LEN = 256;

function tokens(v) {
  return v.toLowerCase().replace(/^v(?=\d)/, '').match(TOKEN_RE) || [];
}

export function compareGeneric(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return null;
  if (!a || !b || a.length > MAX_VERSION_LEN || b.length > MAX_VERSION_LEN) return null;
  const x = tokens(a);
  const y = tokens(b);
  if (x.length === 0 || y.length === 0) return null;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const p = x[i];
    const q = y[i];
    if (p === undefined) return /^\d/.test(q) ? -1 : 1; // 1.0 < 1.0.1, 1.0 > 1.0rc1
    if (q === undefined) return /^\d/.test(p) ? 1 : -1;
    const pn = /^\d/.test(p);
    const qn = /^\d/.test(q);
    if (pn && qn) {
      const c = BigInt(p) < BigInt(q) ? -1 : BigInt(p) > BigInt(q) ? 1 : 0;
      if (c) return c;
    } else if (pn !== qn) {
      return pn ? 1 : -1;
    } else if (p !== q) {
      return p < q ? -1 : 1;
    }
  }
  return 0;
}

// Ecosystem names follow the OSV schema ("npm", "PyPI", "Debian:12",
// "Ubuntu:22.04:LTS", ...). Returns { compare, exact } where exact=false
// means results are approximate.
export function comparatorFor(ecosystem, rangeType) {
  const base = String(ecosystem || '').split(':')[0].toLowerCase();
  if (rangeType === 'SEMVER') return { compare: compareSemver, kind: 'semver', exact: true };
  if (base === 'npm') return { compare: compareSemver, kind: 'semver', exact: true };
  if (base === 'pypi') return { compare: comparePep440, kind: 'pep440', exact: true };
  if (base === 'debian' || base === 'ubuntu') return { compare: compareDebian, kind: 'dpkg', exact: true };
  return { compare: compareGeneric, kind: 'generic', exact: false };
}

export function ecosystemBase(ecosystem) {
  return String(ecosystem || '').split(':')[0];
}
