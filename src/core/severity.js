// Severity extraction. CVSS v3.0/v3.1 base scores are computed from the
// vector with the formula in the FIRST CVSS v3.1 specification, section 7.
// CVSS v4 vectors are NOT scored (the v4 formula needs large lookup tables);
// for those, and for records with no vector, we fall back to the textual
// severity the source database gives, or "UNKNOWN".

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 }
};
const V3_RE = /^CVSS:3\.[01]\/([A-Za-z]{1,3}:[A-Za-z]{1,2}(?:\/[A-Za-z]{1,3}:[A-Za-z]{1,2}){0,39})\/?$/;

function roundUp(x) {
  const i = Math.round(x * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3BaseScore(vector) {
  if (typeof vector !== 'string' || vector.length > 200) return null;
  const m = V3_RE.exec(vector.trim());
  if (!m) return null;
  const v = new Map();
  for (const part of m[1].split('/')) {
    if (!part) continue;
    const [k, val] = part.split(':');
    if (v.has(k)) return null; // duplicate metric
    v.set(k, val);
  }
  const S = v.get('S');
  const av = W.AV[v.get('AV')];
  const ac = W.AC[v.get('AC')];
  const ui = W.UI[v.get('UI')];
  const c = W.CIA[v.get('C')];
  const i = W.CIA[v.get('I')];
  const a = W.CIA[v.get('A')];
  const prKey = v.get('PR');
  if ([av, ac, ui, c, i, a].some((x) => x === undefined) || (S !== 'U' && S !== 'C')) return null;
  const prTable = S === 'C' ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const pr = prTable[prKey];
  if (pr === undefined) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  const raw = S === 'U' ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10);
  return roundUp(raw);
}

export function ratingFromScore(score) {
  if (score === null || score === undefined) return 'UNKNOWN';
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

const TEXT_MAP = new Map([
  ['critical', 'CRITICAL'], ['high', 'HIGH'], ['important', 'HIGH'], ['moderate', 'MEDIUM'],
  ['medium', 'MEDIUM'], ['low', 'LOW'], ['negligible', 'LOW'], ['unimportant', 'LOW'], ['none', 'NONE']
]);

export const RATING_RANK = Object.freeze({ CRITICAL: 5, HIGH: 4, MEDIUM: 3, UNKNOWN: 2, LOW: 1, NONE: 0 });

function textRating(v) {
  return typeof v === 'string' ? TEXT_MAP.get(v.trim().toLowerCase()) || null : null;
}

// Returns { rating, score, basis } for an OSV record (already validated as an
// object). basis says where the rating came from so users can judge it.
export function severityOf(record, affectedEntry) {
  const list = Array.isArray(record.severity) ? record.severity : [];
  const entryList = affectedEntry && Array.isArray(affectedEntry.severity) ? affectedEntry.severity : [];
  let best = null;
  for (const s of list.concat(entryList).slice(0, 20)) {
    if (!s || typeof s !== 'object' || typeof s.score !== 'string') continue;
    if (s.type === 'CVSS_V3') {
      const score = cvss3BaseScore(s.score);
      if (score !== null && (best === null || score > best.score)) best = { rating: ratingFromScore(score), score, basis: 'CVSS v3 base score computed from vector' };
    }
  }
  if (best) return best;
  for (const s of list.concat(entryList).slice(0, 20)) {
    if (s && typeof s === 'object' && typeof s.score === 'string' && s.type !== 'CVSS_V3') {
      const r = textRating(s.score);
      const type = typeof s.type === 'string' && /^[A-Za-z0-9_]{1,20}$/.test(s.type) ? s.type : 'other';
      if (r) return { rating: r, score: null, basis: 'source severity label (' + type + ')' };
    }
  }
  const ds = record.database_specific;
  if (ds && typeof ds === 'object' && textRating(ds.severity)) {
    return { rating: textRating(ds.severity), score: null, basis: 'source severity label' };
  }
  const eds = affectedEntry && affectedEntry.ecosystem_specific;
  if (eds && typeof eds === 'object' && textRating(eds.severity)) {
    return { rating: textRating(eds.severity), score: null, basis: 'source severity label' };
  }
  const v4 = list.some((s) => s && s.type === 'CVSS_V4');
  return { rating: 'UNKNOWN', score: null, basis: v4 ? 'CVSS v4 vector present but not scored by this tool' : 'no severity in record' };
}
