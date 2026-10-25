import { FormatError } from './errors.js';
import { normalizePyName } from './pep440.js';

// Parsers for local package lists. They only PARSE text that the user hands
// over; nothing here runs a package manager, reads other files, or executes
// code. Every parser is iterative (no recursion) and bounded.

export const INVENTORY_LIMITS = Object.freeze({
  maxPackages: 200000,
  maxLineLength: 8192,
  maxNameLength: 214,
  maxVersionLength: 256,
  maxNpmNodes: 500000,
  maxNpmDepth: 256,
  maxSkipped: 5000
});

// Printable, no whitespace, no control/bidi characters.
const NAME_OK = /^[^\s\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]+$/;

function validToken(s, max) {
  return typeof s === 'string' && s.length > 0 && s.length <= max && NAME_OK.test(s);
}

export function newInventory() {
  return { packages: [], skipped: [], skippedCount: 0, warnings: [] };
}

// Records why an entry was not checked. Bounded so hostile input cannot make
// the report itself huge; the total is always counted.
function skip(inv, source, name, reason) {
  inv.skippedCount = (inv.skippedCount || 0) + 1;
  if (inv.skipped.length < INVENTORY_LIMITS.maxSkipped) {
    inv.skipped.push({ source, name: String(name ?? '').slice(0, 80), reason });
  }
}

function addPackage(inv, ecosystem, name, version, source) {
  if (!validToken(name, INVENTORY_LIMITS.maxNameLength)) {
    skip(inv, source, name, 'invalid package name');
    return;
  }
  if (!validToken(version, INVENTORY_LIMITS.maxVersionLength)) {
    skip(inv, source, name, 'missing or invalid version');
    return;
  }
  if (inv.packages.length >= INVENTORY_LIMITS.maxPackages) {
    if (!inv.warnings.includes('package limit reached; remaining entries ignored')) {
      inv.warnings.push('package limit reached; remaining entries ignored');
    }
    return;
  }
  inv.packages.push({ ecosystem, name, version, source });
}

function splitLines(text) {
  if (typeof text !== 'string') throw new FormatError('input must be a string');
  return text.split(/\r?\n/);
}

// ---------------------------------------------------------------- dpkg
// /var/lib/dpkg/status: RFC822-style paragraphs. Only "install ok installed"
// (and other states where files are on disk) are counted. OSV Debian/Ubuntu
// records are keyed by SOURCE package, so we report the Source: name and the
// source version when dpkg records one, otherwise the binary name/version.
const ON_DISK = new Set(['installed', 'half-configured', 'unpacked', 'half-installed', 'triggers-awaited', 'triggers-pending']);

export function parseDpkgStatus(text, ecosystem = 'Debian', inv = newInventory()) {
  const lines = splitLines(text);
  let cur = new Map();
  let lastKey = null;
  const flush = () => {
    if (cur.size) {
      const pkg = cur.get('package');
      const status = (cur.get('status') || '').trim().split(/\s+/);
      const state = status[status.length - 1];
      if (pkg && ON_DISK.has(state)) {
        let name = pkg.trim();
        let version = (cur.get('version') || '').trim();
        const src = (cur.get('source') || '').trim();
        if (src) {
          // "Source: name" or "Source: name (version)"
          const m = /^(\S{1,214})(?:\s+\(([^()\s]{1,256})\))?$/.exec(src);
          if (m) {
            name = m[1];
            if (m[2]) version = m[2];
          }
        }
        addPackage(inv, ecosystem, name, version, 'dpkg');
      }
    }
    cur = new Map();
    lastKey = null;
  };
  for (const raw of lines) {
    if (raw.length > INVENTORY_LIMITS.maxLineLength) {
      lastKey = null;
      continue;
    }
    if (raw.trim() === '') {
      flush();
      continue;
    }
    if (raw[0] === ' ' || raw[0] === '\t') continue; // continuation lines (descriptions, conffiles)
    const idx = raw.indexOf(':');
    if (idx <= 0) continue;
    lastKey = raw.slice(0, idx).toLowerCase();
    if (lastKey === 'package' || lastKey === 'status' || lastKey === 'version' || lastKey === 'source') {
      cur.set(lastKey, raw.slice(idx + 1));
    }
  }
  flush();
  return dedupe(inv);
}

// --------------------------------------------------------------- pip
// `pip freeze` output or requirements.txt. Only exact pins (== / ===) give a
// version we can check; everything else is listed under "skipped" with the
// reason, never guessed. Includes (-r), options, URLs and editable installs
// are not followed.
// Applied after whitespace is removed and any "; marker" is cut off.
const PIP_RE = /^([A-Za-z0-9][A-Za-z0-9._-]{0,200})(?:\[[A-Za-z0-9,._-]{0,200}\])?(===|==)([A-Za-z0-9!+._*-]{1,256})$/;

function joinContinuations(lines) {
  const out = [];
  let buf = null;
  for (const l of lines) {
    if (buf !== null && buf.length + l.length > INVENTORY_LIMITS.maxLineLength) {
      out.push(buf);
      buf = null;
    }
    const cont = l.endsWith('\\');
    const part = cont ? l.slice(0, -1) : l;
    buf = buf === null ? part : buf + ' ' + part;
    if (!cont) {
      out.push(buf);
      buf = null;
    }
  }
  if (buf !== null) out.push(buf);
  return out;
}

export function parsePipList(text, inv = newInventory()) {
  for (const raw of joinContinuations(splitLines(text))) {
    if (raw.length > INVENTORY_LIMITS.maxLineLength) {
      skip(inv, 'pip', raw.slice(0, 40), 'line too long');
      continue;
    }
    let line = raw;
    const hash = line.search(/\s#|^#/);
    if (hash !== -1) line = line.slice(0, hash);
    line = line.replace(/\s--hash[= ]\S*/g, '').trim();
    if (!line) continue;
    if (line.startsWith('-')) {
      skip(inv, 'pip', line.slice(0, 80), 'option or include not followed');
      continue;
    }
    const semi = line.indexOf(';');
    const req = (semi === -1 ? line : line.slice(0, semi)).replace(/\s+/g, '');
    const m = PIP_RE.exec(req);
    if (!m) {
      const name = /^[A-Za-z0-9._-]{1,200}/.exec(req);
      skip(inv, 'pip', name ? name[0] : line.slice(0, 80), 'not an exact == pin (or URL / VCS install)');
      continue;
    }
    if (m[3].includes('*')) {
      skip(inv, 'pip', m[1], 'wildcard pin is not a single version');
      continue;
    }
    addPackage(inv, 'PyPI', normalizePyName(m[1]), m[3], 'pip');
  }
  return dedupe(inv);
}

// --------------------------------------------------------------- npm
function npmNameFromPath(p) {
  const marker = 'node_modules/';
  const i = p.lastIndexOf(marker);
  return i === -1 ? null : p.slice(i + marker.length);
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 or 3.
export function parseNpmLock(json, inv = newInventory()) {
  if (!isPlainObject(json)) throw new FormatError('package-lock: expected a JSON object');
  if (isPlainObject(json.packages)) {
    let n = 0;
    for (const [path, entry] of Object.entries(json.packages)) {
      if (++n > INVENTORY_LIMITS.maxNpmNodes) {
        inv.warnings.push('npm lockfile node limit reached');
        break;
      }
      if (path === '' || !isPlainObject(entry)) continue; // root project
      if (entry.link === true) continue; // workspace symlink, its target is listed separately
      const name = typeof entry.name === 'string' ? entry.name : npmNameFromPath(path);
      if (!name) continue;
      addPackage(inv, 'npm', name, typeof entry.version === 'string' ? entry.version : '', 'npm-lock');
    }
    return dedupe(inv);
  }
  if (isPlainObject(json.dependencies)) {
    walkNpmTree(json.dependencies, inv, 'npm-lock');
    return dedupe(inv);
  }
  inv.warnings.push('package-lock: no "packages" or "dependencies" found');
  return inv;
}

// Output of `npm ls --all --json` saved to a file by the user.
export function parseNpmLs(json, inv = newInventory()) {
  if (!isPlainObject(json)) throw new FormatError('npm ls: expected a JSON object');
  if (isPlainObject(json.dependencies)) walkNpmTree(json.dependencies, inv, 'npm-ls');
  return dedupe(inv);
}

// Iterative walk of nested { name: { version, dependencies } } trees.
function walkNpmTree(deps, inv, source) {
  const stack = [[deps, 0]];
  let nodes = 0;
  while (stack.length) {
    const [obj, depth] = stack.pop();
    if (depth > INVENTORY_LIMITS.maxNpmDepth) {
      if (!inv.warnings.includes('npm tree depth limit reached')) inv.warnings.push('npm tree depth limit reached');
      continue;
    }
    for (const [name, entry] of Object.entries(obj)) {
      if (++nodes > INVENTORY_LIMITS.maxNpmNodes) {
        inv.warnings.push('npm tree node limit reached');
        return;
      }
      if (!isPlainObject(entry)) continue;
      if (typeof entry.version === 'string' && !entry.missing) addPackage(inv, 'npm', name, entry.version, source);
      if (isPlainObject(entry.dependencies)) stack.push([entry.dependencies, depth + 1]);
    }
  }
}

// ------------------------------------------------------------- plain list
// One package per line: "name version" (needs a default ecosystem) or
// "ecosystem name version". Ecosystem names are OSV names, e.g. "PyPI",
// "npm", "Debian:12", "crates.io", "Go", "Maven".
export function parsePlainList(text, defaultEcosystem, inv = newInventory()) {
  for (const raw of splitLines(text)) {
    if (raw.length > INVENTORY_LIMITS.maxLineLength) {
      skip(inv, 'list', raw.slice(0, 40), 'line too long');
      continue;
    }
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    let eco;
    let name;
    let version;
    if (parts.length === 2 && defaultEcosystem) {
      [name, version] = parts;
      eco = defaultEcosystem;
    } else if (parts.length === 3) {
      [eco, name, version] = parts;
    } else {
      skip(inv, 'list', parts[0].slice(0, 80), defaultEcosystem ? 'expected "name version" or "ecosystem name version"' : 'expected "ecosystem name version" (or pass --ecosystem)');
      continue;
    }
    if (!validToken(eco, 64)) {
      skip(inv, 'list', name, 'invalid ecosystem');
      continue;
    }
    if (eco.toLowerCase() === 'pypi') name = normalizePyName(name);
    addPackage(inv, eco, name, version, 'list');
  }
  return dedupe(inv);
}

// ------------------------------------------------------------- os-release
// Maps /etc/os-release to an OSV ecosystem name. Only Debian and Ubuntu.
export function osvEcosystemFromOsRelease(text) {
  const vals = new Map();
  for (const raw of splitLines(String(text)).slice(0, 200)) {
    const m = /^([A-Z_]{1,40})=("?)([^"\n]{0,200})\2\s*$/.exec(raw.trim());
    if (m) vals.set(m[1], m[3]);
  }
  const id = (vals.get('ID') || '').toLowerCase();
  const ver = vals.get('VERSION_ID') || '';
  if (id === 'debian' && /^\d{1,3}$/.test(ver)) return 'Debian:' + ver;
  if (id === 'ubuntu' && /^\d{2}\.\d{2}$/.test(ver)) {
    const lts = /LTS/.test(vals.get('VERSION') || '');
    return 'Ubuntu:' + ver + (lts ? ':LTS' : '');
  }
  return null;
}

function dedupe(inv) {
  const seen = new Set();
  inv.packages = inv.packages.filter((p) => {
    const k = p.ecosystem + '\u0000' + p.name + '\u0000' + p.version;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  return inv;
}
