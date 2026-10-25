// Debian version comparison, following deb-version(7) / dpkg's verrevcmp:
//   [epoch:]upstream_version[-debian_revision]
// "~" sorts before everything (even the end of the string), letters sort
// before non-letters, digit runs compare numerically. Ubuntu uses the same
// algorithm. Returns null for strings dpkg itself would reject.

const MAX_VERSION_LEN = 256;
const EPOCH_RE = /^\d{1,9}$/;
const ALLOWED_RE = /^[A-Za-z0-9.+~:-]+$/;

export function parseDebianVersion(input) {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (s.length === 0 || s.length > MAX_VERSION_LEN || !ALLOWED_RE.test(s)) return null;
  let epoch = 0;
  let rest = s;
  const colon = s.indexOf(':');
  if (colon !== -1) {
    const e = s.slice(0, colon);
    if (!EPOCH_RE.test(e)) return null;
    epoch = Number(e);
    rest = s.slice(colon + 1);
  }
  let upstream = rest;
  let revision = '';
  const dash = rest.lastIndexOf('-');
  if (dash !== -1) {
    upstream = rest.slice(0, dash);
    revision = rest.slice(dash + 1);
    if (revision.length === 0) return null;
  }
  if (upstream.length === 0 || !/^\d/.test(upstream)) return null;
  if (upstream.includes(':')) return null;
  return { epoch, upstream, revision };
}

function order(ch) {
  if (ch === undefined) return 0; // end of string
  if (ch === '~') return -1;
  const c = ch.charCodeAt(0);
  if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122)) return c; // letters
  return c + 256; // everything else after letters
}

function isDigit(ch) {
  return ch !== undefined && ch >= '0' && ch <= '9';
}

// Iterative and linear in the input length.
function verrevcmp(a, b) {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = order(isDigit(a[i]) ? undefined : a[i]);
      const bc = order(isDigit(b[j]) ? undefined : b[j]);
      if (ac !== bc) return ac < bc ? -1 : 1;
      i++;
      j++;
    }
    while (a[i] === '0') i++;
    while (b[j] === '0') j++;
    while (isDigit(a[i]) && isDigit(b[j])) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i++;
      j++;
    }
    if (isDigit(a[i])) return 1;
    if (isDigit(b[j])) return -1;
    if (firstDiff) return firstDiff < 0 ? -1 : 1;
  }
  return 0;
}

export function compareDebian(a, b) {
  const x = parseDebianVersion(a);
  const y = parseDebianVersion(b);
  if (!x || !y) return null;
  if (x.epoch !== y.epoch) return x.epoch < y.epoch ? -1 : 1;
  return verrevcmp(x.upstream, y.upstream) || verrevcmp(x.revision, y.revision);
}
