import { comparatorFor, ecosystemBase } from './compare.js';
import { normalizePyName } from './pep440.js';
import { clampText } from './display.js';

// OSV records (https://ossf.github.io/osv-schema/) are untrusted input. We
// copy only the fields we use, with type checks and size caps, into a fresh
// object; the raw record is never kept, rendered as HTML or interpreted.

export const OSV_LIMITS = Object.freeze({
  maxAffected: 2000,
  maxRanges: 100,
  maxEvents: 500,
  maxVersions: 50000,
  maxAliases: 200,
  maxSummary: 1000,
  maxRecords: 3000000,
  maxFindings: 500000
});

export const OSV_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CVE_RE = /^CVE-\d{4}-\d{4,9}$/;

function str(v, max) {
  return typeof v === 'string' && v.length > 0 && v.length <= max ? v : null;
}

function arr(v, max) {
  return Array.isArray(v) ? v.slice(0, max) : [];
}

function obj(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : null;
}

function normName(ecosystem, name) {
  return ecosystemBase(ecosystem).toLowerCase() === 'pypi' ? normalizePyName(name) : name;
}

function indexKey(ecosystem, name) {
  return ecosystemBase(ecosystem).toLowerCase() + '\u0000' + normName(ecosystem, name);
}

// Returns a sanitised record or { error } explaining why it was dropped.
export function normalizeRecord(raw) {
  const r = obj(raw);
  if (!r) return { error: 'not an object' };
  const id = str(r.id, 128);
  if (!id || !OSV_ID_RE.test(id)) return { error: 'missing or invalid id' };
  if (r.withdrawn !== undefined && r.withdrawn !== null) return { error: 'withdrawn', id };
  const aliases = arr(r.aliases, OSV_LIMITS.maxAliases).filter((a) => typeof a === 'string' && OSV_ID_RE.test(a));
  const upstream = arr(r.upstream, OSV_LIMITS.maxAliases).filter((a) => typeof a === 'string' && OSV_ID_RE.test(a));
  const text = typeof r.summary === 'string' && r.summary.trim() ? r.summary : r.details;
  const summary = clampText(text, OSV_LIMITS.maxSummary);
  const severity = arr(r.severity, 20).filter(obj).map((s) => ({ type: str(s.type, 40), score: str(s.score, 200) }));
  const ds = obj(r.database_specific);
  const affected = [];
  for (const a of arr(r.affected, OSV_LIMITS.maxAffected)) {
    const ao = obj(a);
    const pkg = ao && obj(ao.package);
    if (!pkg) continue;
    const ecosystem = str(pkg.ecosystem, 100);
    const name = str(pkg.name, 500);
    if (!ecosystem || !name) continue;
    const ranges = [];
    for (const rg of arr(ao.ranges, OSV_LIMITS.maxRanges)) {
      const ro = obj(rg);
      if (!ro) continue;
      const type = str(ro.type, 20);
      const events = [];
      for (const ev of arr(ro.events, OSV_LIMITS.maxEvents)) {
        const eo = obj(ev);
        if (!eo) continue;
        for (const k of ['introduced', 'fixed', 'last_affected', 'limit']) {
          const val = str(eo[k], 256);
          if (val) {
            events.push({ kind: k, version: val });
            break;
          }
        }
      }
      if (type) ranges.push({ type, events });
    }
    const versions = arr(ao.versions, OSV_LIMITS.maxVersions).filter((v) => typeof v === 'string' && v.length <= 256);
    const eds = obj(ao.ecosystem_specific);
    affected.push({
      ecosystem,
      name,
      ranges,
      versions: new Set(versions),
      hasVersions: Array.isArray(ao.versions) && ao.versions.length > 0,
      severity: arr(ao.severity, 20).filter(obj).map((s) => ({ type: str(s.type, 40), score: str(s.score, 200) })),
      ecosystem_specific: eds && typeof eds.severity === 'string' ? { severity: eds.severity.slice(0, 40) } : null
    });
  }
  return {
    record: {
      id,
      aliases,
      upstream,
      summary,
      severity,
      database_specific: ds && typeof ds.severity === 'string' ? { severity: ds.severity.slice(0, 40) } : null,
      published: str(r.published, 40),
      modified: str(r.modified, 40),
      affected
    }
  };
}

export function createIndex() {
  return { byPackage: new Map(), ids: new Set(), count: 0, dropped: new Map(), records: 0 };
}

function countDrop(index, reason) {
  index.dropped.set(reason, (index.dropped.get(reason) || 0) + 1);
}

// wanted: optional Set of index keys; records for other packages are dropped
// early so a full OSV dump does not have to fit in memory.
export function addRecord(index, raw, wanted) {
  if (index.records >= OSV_LIMITS.maxRecords) {
    countDrop(index, 'record limit reached');
    return false;
  }
  index.records++;
  const res = normalizeRecord(raw);
  if (res.error) {
    countDrop(index, res.error);
    return false;
  }
  const rec = res.record;
  if (index.ids.has(rec.id)) {
    countDrop(index, 'duplicate id');
    return false;
  }
  let used = false;
  for (let i = 0; i < rec.affected.length; i++) {
    const a = rec.affected[i];
    const key = indexKey(a.ecosystem, a.name);
    if (wanted && !wanted.has(key)) continue;
    if (!index.byPackage.has(key)) index.byPackage.set(key, []);
    index.byPackage.get(key).push({ record: rec, entry: a });
    used = true;
  }
  if (used) {
    index.ids.add(rec.id);
    index.count++;
  } else {
    countDrop(index, 'no affected package in inventory');
  }
  return used;
}

export function wantedKeys(packages) {
  return new Set(packages.map((p) => indexKey(p.ecosystem, p.name)));
}

// Accepts a parsed JSON value that is one record, an array of records, or an
// API-style { vulns: [...] } / { results: [{ vulns: [...] }] } wrapper.
export function addJsonValue(index, value, wanted) {
  if (Array.isArray(value)) {
    for (const v of value) addRecord(index, v, wanted);
    return;
  }
  const o = obj(value);
  if (!o) {
    countDrop(index, 'not an object');
    return;
  }
  if (Array.isArray(o.vulns)) {
    for (const v of o.vulns) addRecord(index, v, wanted);
    return;
  }
  if (Array.isArray(o.results)) {
    for (const res of o.results) {
      const ro = obj(res);
      if (ro && Array.isArray(ro.vulns)) for (const v of ro.vulns) addRecord(index, v, wanted);
    }
    return;
  }
  addRecord(index, o, wanted);
}

// ------------------------------------------------------------- matching

function ecosystemMatches(pkgEco, entryEco) {
  const p = pkgEco.toLowerCase();
  const e = entryEco.toLowerCase();
  if (p === e) return { ok: true, approx: false };
  if (ecosystemBase(p) !== ecosystemBase(e)) return { ok: false };
  if (!p.includes(':')) return { ok: true, approx: true, note: 'distribution release unknown; matched ' + entryEco };
  return { ok: false };
}

// OSV range evaluation (schema "Evaluation" pseudo-code). Returns
// true / false / null (cannot compare).
function evalRange(version, events, compare) {
  const evs = events.filter((e) => e.kind !== 'limit');
  if (evs.length === 0) return false;
  // Validate all versions first so sort comparator never sees null.
  for (const e of evs) {
    if (!(e.kind === 'introduced' && e.version === '0') && compare(e.version, e.version) === null) return null;
  }
  if (compare(version, version) === null) return null;
  const key = (e) => (e.kind === 'introduced' && e.version === '0' ? null : e.version);
  evs.sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    if (ka === null) return kb === null ? 0 : -1;
    if (kb === null) return 1;
    return compare(ka, kb);
  });
  let affected = false;
  for (const e of evs) {
    if (e.kind === 'introduced') {
      if (e.version === '0' || compare(version, e.version) >= 0) affected = true;
    } else if (e.kind === 'fixed') {
      if (compare(version, e.version) >= 0) affected = false;
    } else if (e.kind === 'last_affected') {
      if (compare(version, e.version) > 0) affected = false;
    }
  }
  return affected;
}

// Returns null when not affected, otherwise a match description.
export function matchEntry(pkg, entry) {
  const eco = ecosystemMatches(pkg.ecosystem, entry.ecosystem);
  if (!eco.ok) return null;
  const notes = [];
  if (eco.approx) notes.push(eco.note);
  if (entry.versions.has(pkg.version)) {
    return { status: 'affected', method: 'listed version', approximate: !!eco.approx, notes, fixed: fixesFor(pkg, entry) };
  }
  let unknown = false;
  let approximate = !!eco.approx;
  let hit = false;
  let usableRange = false;
  for (const rg of entry.ranges) {
    if (rg.type !== 'ECOSYSTEM' && rg.type !== 'SEMVER') continue; // GIT ranges need commit hashes
    usableRange = true;
    const cmp = comparatorFor(pkg.ecosystem, rg.type);
    const r = evalRange(pkg.version, rg.events, cmp.compare);
    if (r === null) unknown = true;
    else if (r === true) {
      hit = true;
      if (!cmp.exact) approximate = true;
    }
  }
  if (hit) {
    if (approximate && !notes.some((n) => n.startsWith('generic'))) {
      const cmp = comparatorFor(pkg.ecosystem, 'ECOSYSTEM');
      if (!cmp.exact) notes.push('generic version comparison for ' + ecosystemBase(pkg.ecosystem));
    }
    return { status: 'affected', method: 'version range', approximate, notes, fixed: fixesFor(pkg, entry) };
  }
  if (unknown) {
    return { status: 'unknown', method: 'version range', approximate: true, notes: notes.concat('could not compare version strings'), fixed: fixesFor(pkg, entry) };
  }
  if (!usableRange && !entry.hasVersions) {
    return { status: 'unknown', method: 'no version data', approximate: true, notes: notes.concat('record lists no comparable versions'), fixed: [] };
  }
  return null;
}

function fixesFor(pkg, entry) {
  const out = new Set();
  for (const rg of entry.ranges) {
    if (rg.type !== 'ECOSYSTEM' && rg.type !== 'SEMVER') continue;
    const cmp = comparatorFor(pkg.ecosystem, rg.type).compare;
    for (const e of rg.events) {
      if (e.kind !== 'fixed') continue;
      const c = cmp(e.version, pkg.version);
      if (c === null || c > 0) out.add(e.version);
    }
  }
  return [...out].slice(0, 20);
}

export function cveIdsOf(record) {
  const ids = new Set();
  for (const x of [record.id, ...record.aliases, ...record.upstream]) if (CVE_RE.test(x)) ids.add(x);
  return [...ids];
}

// Returns findings: one per (package, record), plus "unknown" results.
export function matchPackages(index, packages) {
  const findings = [];
  for (const pkg of packages) {
    const cands = index.byPackage.get(indexKey(pkg.ecosystem, pkg.name)) || [];
    const perRecord = new Map();
    for (const { record, entry } of cands) {
      const m = matchEntry(pkg, entry);
      if (!m) continue;
      const prev = perRecord.get(record.id);
      // prefer an "affected" verdict over "unknown" for the same record
      if (!prev || (prev.match.status === 'unknown' && m.status === 'affected')) perRecord.set(record.id, { record, entry, match: m });
    }
    for (const v of perRecord.values()) {
      if (findings.length >= OSV_LIMITS.maxFindings) {
        index.findingsTruncated = true;
        return findings;
      }
      findings.push({ pkg, ...v });
    }
  }
  return findings;
}
