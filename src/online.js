import { addRecord, OSV_ID_RE } from './core/osv.js';
import { parseKev } from './core/kev.js';
import { TOOL_NAME, TOOL_VERSION } from './core/report.js';
import { ecosystemBase } from './core/compare.js';

// Opt-in network lookups (--online). Exactly two hosts, https only, no
// redirects, no cookies, per-request timeouts and response size caps.
//
// What is sent to api.osv.dev (see docs/LEGAL.md "Privacy"):
//   POST /v1/querybatch  {"queries":[{"package":{"name","ecosystem"},"version"}]}
//   GET  /v1/vulns/<id>  for each advisory id returned by the batch query
// Nothing else from the inventory (no file paths, hostnames, usernames,
// inventory source, or machine identifiers) is included. The servers still
// see your IP address, TLS metadata and the User-Agent below.

export const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
export const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const ALLOWED_HOSTS = new Set(['api.osv.dev', 'www.cisa.gov']);
export const USER_AGENT = `${TOOL_NAME}/${TOOL_VERSION}`;

export const NET_LIMITS = Object.freeze({
  timeoutMs: 30000,
  batchSize: 500,
  maxBatchResponseBytes: 32 * 1024 * 1024,
  maxVulnBytes: 8 * 1024 * 1024,
  maxKevBytes: 32 * 1024 * 1024,
  maxIds: 5000,
  maxTotalVulnBytes: 512 * 1024 * 1024,
  maxPageRounds: 10,
  concurrency: 4
});

export class NetError extends Error {}
class BudgetError extends NetError {}

function checkUrl(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new NetError('refusing non-https URL');
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new NetError('refusing unexpected host ' + u.hostname);
  if (u.username || u.password || u.port) throw new NetError('refusing URL with credentials or port');
  return u;
}

async function readCapped(res, maxBytes, budget) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > maxBytes) throw new NetError(`response too large (${len} bytes)`);
  if (!res.body) return Buffer.alloc(0);
  const chunks = [];
  let total = 0;
  for await (const chunk of res.body) {
    total += chunk.length;
    if (total > maxBytes) throw new NetError(`response over ${maxBytes} bytes`);
    if (budget) {
      budget.used += chunk.length;
      if (budget.used > budget.max) throw new BudgetError(`advisory downloads passed the ${budget.max}-byte total limit`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function fetchJson(url, { method = 'GET', body, maxBytes, budget, timeoutMs = NET_LIMITS.timeoutMs, fetchImpl = globalThis.fetch } = {}) {
  checkUrl(url);
  let res;
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    res = await fetchImpl(url, {
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: body === undefined ? { 'user-agent': USER_AGENT, accept: 'application/json' } : { 'user-agent': USER_AGENT, accept: 'application/json', 'content-type': 'application/json' },
      redirect: 'error',
      credentials: 'omit',
      signal
    });
  } catch (e) {
    throw new NetError(`request to ${new URL(url).hostname} failed: ${e.name === 'TimeoutError' ? 'timed out' : String(e.message).slice(0, 120)}`);
  }
  if (!res.ok) throw new NetError(`${new URL(url).hostname} answered HTTP ${res.status}`);
  let buf;
  try {
    buf = await readCapped(res, maxBytes, budget);
  } catch (e) {
    if (e instanceof NetError) throw e;
    throw new NetError(`reading response failed: ${e.name === 'TimeoutError' ? 'timed out' : String(e.message).slice(0, 120)}`);
  }
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new NetError('response was not JSON');
  }
}

// Exactly what would be sent for these packages. Packages whose ecosystem
// OSV cannot query precisely (Debian/Ubuntu without a release) are left out.
export function buildOsvQueries(packages) {
  const queries = [];
  const skipped = [];
  for (const p of packages) {
    const base = ecosystemBase(p.ecosystem).toLowerCase();
    if ((base === 'debian' || base === 'ubuntu') && !p.ecosystem.includes(':')) {
      skipped.push(p);
      continue;
    }
    queries.push({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version });
  }
  return { queries, skipped };
}

async function pool(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
}

export async function queryOsvOnline(packages, index, { fetchImpl, timeoutMs, onProgress, saveRecords } = {}) {
  const warnings = [];
  const { queries, skipped } = buildOsvQueries(packages);
  if (skipped.length) warnings.push(`${skipped.length} Debian/Ubuntu packages not queried online: distribution release unknown (pass --os-ecosystem, e.g. Debian:12)`);
  const ids = new Set();
  for (let start = 0; start < queries.length; start += NET_LIMITS.batchSize) {
    let pending = queries.slice(start, start + NET_LIMITS.batchSize);
    for (let round = 0; pending.length && round < NET_LIMITS.maxPageRounds; round++) {
      const res = await fetchJson(OSV_BATCH_URL, { method: 'POST', body: { queries: pending }, maxBytes: NET_LIMITS.maxBatchResponseBytes, fetchImpl, timeoutMs });
      const results = res && Array.isArray(res.results) ? res.results : null;
      if (!results || results.length !== pending.length) throw new NetError('unexpected querybatch response shape');
      const next = [];
      results.forEach((r, i) => {
        const vulns = r && Array.isArray(r.vulns) ? r.vulns : [];
        for (const v of vulns) if (v && typeof v.id === 'string' && OSV_ID_RE.test(v.id)) ids.add(v.id);
        if (r && typeof r.next_page_token === 'string' && r.next_page_token.length < 2048) {
          next.push({ ...pending[i], page_token: r.next_page_token });
        }
      });
      pending = next;
      if (pending.length && round + 1 === NET_LIMITS.maxPageRounds) warnings.push('OSV pagination limit reached; some results may be missing');
    }
    if (onProgress) onProgress(`queried ${Math.min(start + NET_LIMITS.batchSize, queries.length)}/${queries.length} packages`);
  }
  let idList = [...ids];
  if (idList.length > NET_LIMITS.maxIds) {
    warnings.push(`${idList.length} advisories found; only the first ${NET_LIMITS.maxIds} were fetched`);
    idList = idList.slice(0, NET_LIMITS.maxIds);
  }
  const wanted = null; // records came from a query for our packages
  let failed = 0;
  let overBudget = false;
  const budget = { used: 0, max: NET_LIMITS.maxTotalVulnBytes };
  await pool(idList, NET_LIMITS.concurrency, async (id) => {
    if (overBudget) {
      failed++;
      return;
    }
    try {
      const rec = await fetchJson(OSV_VULN_URL + encodeURIComponent(id), { maxBytes: NET_LIMITS.maxVulnBytes, budget, fetchImpl, timeoutMs });
      if (saveRecords) {
        // Saved as NDJSON. A record too deeply nested to serialise is not saved.
        try {
          saveRecords.push(JSON.stringify(rec));
        } catch (e) {
          if (!(e instanceof RangeError)) throw e;
          saveRecords.unsaved = (saveRecords.unsaved || 0) + 1;
        }
      }
      addRecord(index, rec, wanted);
    } catch (e) {
      if (!(e instanceof NetError)) throw e;
      if (e instanceof BudgetError) overBudget = true;
      failed++;
    }
  });
  if (overBudget) warnings.push(`stopped downloading after ${NET_LIMITS.maxTotalVulnBytes} bytes of advisory records`);
  if (saveRecords && saveRecords.unsaved) warnings.push(`${saveRecords.unsaved} advisory records were too deeply nested to save`);
  if (failed) warnings.push(`${failed} advisory records could not be fetched; results are incomplete`);
  if (onProgress) onProgress(`fetched ${idList.length - failed} advisory records`);
  return { queried: queries.length, ids: idList.length, failed, warnings };
}

export async function fetchKevOnline({ fetchImpl, timeoutMs } = {}) {
  const json = await fetchJson(KEV_URL, { maxBytes: NET_LIMITS.maxKevBytes, fetchImpl, timeoutMs });
  return parseKev(json);
}
