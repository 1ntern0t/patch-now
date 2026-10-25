// PEP 440 version parsing and ordering (as far as reasonable).
// Supported: epoch, release, a/b/rc pre-releases (with the usual alternate
// spellings), post-releases (incl. implicit "-1"), dev releases, local
// versions, normalisation of case, separators and a leading "v".
// Not supported: legacy (non-PEP 440) versions; they return null and are
// reported as "could not compare" rather than silently matched.

const MAX_VERSION_LEN = 256;
// Linear: each optional group starts with a distinct literal or class and no
// quantified group can match the empty string.
const PEP440_RE = /^v?(?:(\d{1,9})!)?(\d{1,16}(?:\.\d{1,16}){0,30})(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d{0,16}))?(?:-(\d{1,16})|[-_.]?(post|rev|r)[-_.]?(\d{0,16}))?(?:[-_.]?(dev)[-_.]?(\d{0,16}))?(?:\+([a-z0-9]{1,50}(?:[-_.][a-z0-9]{1,50}){0,20}))?$/;

const PRE_MAP = new Map([['a', 0], ['alpha', 0], ['b', 1], ['beta', 1], ['c', 2], ['rc', 2], ['pre', 2], ['preview', 2]]);

export function parsePep440(input) {
  if (typeof input !== 'string') return null;
  const s = input.trim().toLowerCase();
  if (s.length === 0 || s.length > MAX_VERSION_LEN) return null;
  const m = PEP440_RE.exec(s);
  if (!m) return null;
  const release = m[2].split('.').map((x) => BigInt(x));
  while (release.length > 1 && release[release.length - 1] === 0n) release.pop();
  const v = {
    epoch: BigInt(m[1] ?? '0'),
    release,
    pre: m[3] ? [PRE_MAP.get(m[3]), BigInt(m[4] || '0')] : null,
    post: m[5] !== undefined ? BigInt(m[5]) : m[6] ? BigInt(m[7] || '0') : null,
    dev: m[8] ? BigInt(m[9] || '0') : null,
    local: m[10] ? m[10].split(/[-_.]/).map((x) => (/^\d+$/.test(x) ? BigInt(x) : x)) : null
  };
  return v;
}

function cmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

// Keys follow the sort order used by the "packaging" library:
// dev-only releases sort before pre-releases, which sort before the final
// release; post-releases sort after; dev versions sort before their parent.
const NEG_INF = -1n;

function preKey(v) {
  if (v.pre === null && v.post === null && v.dev !== null) return [-1n, NEG_INF]; // 1.0.dev0 < 1.0a0
  if (v.pre === null) return [3n, 0n]; // no pre-release: after all pre-releases
  return [BigInt(v.pre[0]), v.pre[1]];
}

function cmpRelease(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const c = cmp(a[i] ?? 0n, b[i] ?? 0n);
    if (c) return c;
  }
  return 0;
}

function cmpLocal(a, b) {
  if (a === null && b === null) return 0;
  if (a === null) return -1; // 1.0 < 1.0+anything
  if (b === null) return 1;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i];
    const y = b[i];
    const xn = typeof x === 'bigint';
    const yn = typeof y === 'bigint';
    if (xn && yn) {
      const c = cmp(x, y);
      if (c) return c;
    } else if (xn) {
      return 1; // numeric segments sort after alphanumeric ones
    } else if (yn) {
      return -1;
    } else {
      const c = cmp(x, y);
      if (c) return c;
    }
  }
  return cmp(a.length, b.length);
}

export function comparePep440(a, b) {
  const x = parsePep440(a);
  const y = parsePep440(b);
  if (!x || !y) return null;
  let c = cmp(x.epoch, y.epoch) || cmpRelease(x.release, y.release);
  if (c) return c;
  const px = preKey(x);
  const py = preKey(y);
  c = cmp(px[0], py[0]) || cmp(px[1], py[1]);
  if (c) return c;
  // no post-release sorts before any post-release
  c = cmp(x.post === null ? -1n : x.post, y.post === null ? -1n : y.post);
  if (c) return c;
  // no dev sorts after any dev
  c = cmp(x.dev === null ? 1n << 64n : x.dev, y.dev === null ? 1n << 64n : y.dev);
  if (c) return c;
  return cmpLocal(x.local, y.local);
}

// PEP 503 name normalisation.
export function normalizePyName(name) {
  return String(name).toLowerCase().replace(/[-_.]+/g, '-');
}
