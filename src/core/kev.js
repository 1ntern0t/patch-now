import { FormatError } from './errors.js';
import { clampText } from './display.js';

// CISA Known Exploited Vulnerabilities catalog (JSON feed). Only CVE id,
// date added, ransomware flag and due date are kept. Everything else in the
// catalog (names, descriptions, notes, URLs) is ignored.
const CVE_RE = /^CVE-\d{4}-\d{4,9}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
export const KEV_MAX_ENTRIES = 100000;

export function parseKev(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.vulnerabilities)) {
    throw new FormatError('KEV: expected an object with a "vulnerabilities" array');
  }
  const map = new Map();
  let dropped = 0;
  for (const v of value.vulnerabilities.slice(0, KEV_MAX_ENTRIES)) {
    if (!v || typeof v !== 'object' || typeof v.cveID !== 'string' || !CVE_RE.test(v.cveID)) {
      dropped++;
      continue;
    }
    map.set(v.cveID, {
      dateAdded: typeof v.dateAdded === 'string' && DATE_RE.test(v.dateAdded) ? v.dateAdded : null,
      dueDate: typeof v.dueDate === 'string' && DATE_RE.test(v.dueDate) ? v.dueDate : null,
      ransomware: typeof v.knownRansomwareCampaignUse === 'string' ? clampText(v.knownRansomwareCampaignUse, 20) : null
    });
  }
  return {
    catalogVersion: typeof value.catalogVersion === 'string' ? clampText(value.catalogVersion, 40) : null,
    entries: map,
    dropped
  };
}
