// Semantic Versioning 2.0.0 comparison (https://semver.org/#spec-item-11).
// Used for npm and for OSV ranges of type SEMVER. Lenient in two documented
// ways: a leading "v"/"=" is ignored, and missing minor/patch become 0.
// Returns null for anything it cannot parse; callers must treat null as
// "unknown", never as "not affected".

const MAX_VERSION_LEN = 256;
// Linear: no nested or overlapping quantifiers.
const SEMVER_RE = /^[v=]?(\d{1,16})(?:\.(\d{1,16}))?(?:\.(\d{1,16}))?(?:-([0-9A-Za-z.-]{1,200}))?(?:\+[0-9A-Za-z.-]{1,200})?$/;
const NUMERIC_ID = /^\d{1,16}$/;

export function parseSemver(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > MAX_VERSION_LEN) return null;
  const m = SEMVER_RE.exec(input.trim());
  if (!m) return null;
  const pre = m[4] === undefined ? [] : m[4].split('.');
  if (pre.some((id) => id.length === 0)) return null;
  return {
    major: BigInt(m[1]),
    minor: BigInt(m[2] ?? '0'),
    patch: BigInt(m[3] ?? '0'),
    pre: pre.map((id) => (NUMERIC_ID.test(id) ? BigInt(id) : id))
  };
}

function cmpBig(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function cmpIdent(a, b) {
  const an = typeof a === 'bigint';
  const bn = typeof b === 'bigint';
  if (an && bn) return cmpBig(a, b);
  if (an) return -1; // numeric identifiers have lower precedence
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0; // ASCII order
}

export function compareSemver(a, b) {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) return null;
  const core = cmpBig(x.major, y.major) || cmpBig(x.minor, y.minor) || cmpBig(x.patch, y.patch);
  if (core) return core;
  if (x.pre.length === 0 && y.pre.length === 0) return 0;
  if (x.pre.length === 0) return 1; // release > pre-release
  if (y.pre.length === 0) return -1;
  const n = Math.min(x.pre.length, y.pre.length);
  for (let i = 0; i < n; i++) {
    const c = cmpIdent(x.pre[i], y.pre[i]);
    if (c) return c;
  }
  return cmpBig(BigInt(x.pre.length), BigInt(y.pre.length));
}
