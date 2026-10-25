import { parseArgs } from 'node:util';
import { writeFile, open } from 'node:fs/promises';
import { newInventory, parseDpkgStatus, parsePipList, parseNpmLock, parseNpmLs, parsePlainList, osvEcosystemFromOsRelease } from './core/inventory.js';
import { createIndex, wantedKeys, matchPackages } from './core/osv.js';
import { parseKev } from './core/kev.js';
import { FormatError } from './core/errors.js';
import { buildReport, renderJson, renderText, TOOL_NAME, TOOL_VERSION } from './core/report.js';
import { safeText, safeJson } from './core/display.js';
import { IO_LIMITS, InputError, readText, readJson, loadOsvPath } from './io.js';
import { NetError, queryOsvOnline, fetchKevOnline, buildOsvQueries, OSV_BATCH_URL, OSV_VULN_URL, KEV_URL, USER_AGENT } from './online.js';

export const HELP = `${TOOL_NAME} ${TOOL_VERSION} - which of my installed packages have known vulnerabilities?

Usage:
  patch-now scan        [inventory] [advisories] [output]
  patch-now inventory   [inventory]            print the parsed package list only
  patch-now show-query  [inventory]            print exactly what --online would send, send nothing

Inventory (at least one; files are only read, nothing is executed):
  --dpkg <file>          dpkg status file, e.g. /var/lib/dpkg/status
  --os-ecosystem <name>  OSV ecosystem for dpkg packages, e.g. Debian:12 or Ubuntu:22.04:LTS
  --os-release <file>    read the release from this os-release file (default with --dpkg: /etc/os-release)
  --npm-lock <file>      package-lock.json / npm-shrinkwrap.json
  --npm-ls <file>        saved output of: npm ls --all --json > npm-ls.json
  --pip <file>           saved output of: pip freeze > pip.txt   (or a requirements.txt with == pins)
  --list <file>          lines of "ecosystem name version" or "name version" (with --ecosystem)
  --ecosystem <name>     default ecosystem for --list (OSV names: npm, PyPI, Go, crates.io, Maven, ...)

Advisory data (offline by default):
  --osv <path>           OSV data you downloaded: a JSON/NDJSON file or a directory of *.json
                         (e.g. unzipped https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip)
  --kev <file>           CISA KEV catalog JSON you downloaded
  --online               query api.osv.dev (sends only package name, ecosystem, version) and,
                         unless --kev is given, download the CISA KEV catalog
  --no-kev               do not use KEV even with --online
  --save-osv <file>      with --online: save fetched OSV records for later offline use
  --timeout-ms <n>       per-request timeout for --online (default 30000)

Output:
  --format text|json     default text
  --out <file>           write the report to a new file (refuses to overwrite unless --force)
  --force
  -h, --help / -v, --version

Exit codes: 0 no known vulnerabilities matched, 1 findings, 2 usage or input error.
Advisory text is untrusted data: it is printed as escaped plain text and never executed.
`;

const OPTIONS = {
  dpkg: { type: 'string' },
  'os-ecosystem': { type: 'string' },
  'os-release': { type: 'string' },
  'npm-lock': { type: 'string' },
  'npm-ls': { type: 'string' },
  pip: { type: 'string' },
  list: { type: 'string' },
  ecosystem: { type: 'string' },
  osv: { type: 'string', multiple: true },
  kev: { type: 'string' },
  online: { type: 'boolean' },
  'no-kev': { type: 'boolean' },
  'save-osv': { type: 'string' },
  'timeout-ms': { type: 'string' },
  format: { type: 'string' },
  out: { type: 'string' },
  force: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' }
};

class UsageError extends Error {}

const ECO_RE = /^[A-Za-z0-9.][A-Za-z0-9.:_ -]{0,63}$/;

async function loadInventory(v) {
  const inv = newInventory();
  if (v.dpkg) {
    let eco = v['os-ecosystem'];
    if (!eco) {
      const relPath = v['os-release'] || '/etc/os-release';
      try {
        eco = osvEcosystemFromOsRelease(await readText(relPath, 64 * 1024));
      } catch {
        eco = null;
      }
      if (!eco) {
        eco = 'Debian';
        inv.warnings.push('distribution release unknown (no --os-ecosystem and no usable os-release); dpkg matches are approximate');
      }
    }
    if (!ECO_RE.test(eco)) throw new UsageError('invalid --os-ecosystem');
    parseDpkgStatus(await readText(v.dpkg, IO_LIMITS.inventoryBytes), eco, inv);
  }
  if (v['npm-lock']) parseNpmLock(await readJson(v['npm-lock'], IO_LIMITS.inventoryBytes), inv);
  if (v['npm-ls']) parseNpmLs(await readJson(v['npm-ls'], IO_LIMITS.inventoryBytes), inv);
  if (v.pip) parsePipList(await readText(v.pip, IO_LIMITS.inventoryBytes), inv);
  if (v.list) {
    if (v.ecosystem && !ECO_RE.test(v.ecosystem)) throw new UsageError('invalid --ecosystem');
    parsePlainList(await readText(v.list, IO_LIMITS.inventoryBytes), v.ecosystem || null, inv);
  }
  return inv;
}

async function emit(text, v, io) {
  if (v.out) {
    try {
      await writeFile(v.out, text, { flag: v.force ? 'w' : 'wx', mode: 0o644 });
    } catch (e) {
      if (e.code === 'EEXIST') throw new UsageError(`${v.out} exists; pass --force to overwrite`);
      throw new InputError(`cannot write ${v.out}: ${e.code || e.message}`);
    }
    io.stderr(`wrote ${v.out}\n`);
  } else {
    io.stdout(text);
  }
}

export async function main(argv, io = defaultIo(), deps = {}) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (e) {
    io.stderr(`${safeText(e.message, 200)}\n\n${HELP}`);
    return 2;
  }
  const v = parsed.values;
  const cmd = parsed.positionals[0] || 'scan';
  if (v.help) {
    io.stdout(HELP);
    return 0;
  }
  if (v.version) {
    io.stdout(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    return 0;
  }
  try {
    if (parsed.positionals.length > 1) throw new UsageError('unexpected argument: ' + safeText(parsed.positionals[1], 80));
    if (!['scan', 'inventory', 'show-query'].includes(cmd)) throw new UsageError('unknown command: ' + safeText(cmd, 40));
    const format = v.format || 'text';
    if (format !== 'text' && format !== 'json') throw new UsageError('--format must be text or json');
    if (!v.dpkg && !v['npm-lock'] && !v['npm-ls'] && !v.pip && !v.list) throw new UsageError('give at least one inventory file (--dpkg, --npm-lock, --npm-ls, --pip or --list)');
    let timeoutMs;
    if (v['timeout-ms'] !== undefined) {
      timeoutMs = Number(v['timeout-ms']);
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 300000) throw new UsageError('--timeout-ms must be an integer between 1000 and 300000');
    }
    const inv = await loadInventory(v);

    if (cmd === 'inventory') {
      const body = format === 'json' ? safeJson(inv) + '\n'
        : inv.packages.map((p) => `${safeText(p.ecosystem, 40)}\t${safeText(p.name, 214)}\t${safeText(p.version, 256)}\t${p.source}`).join('\n') +
          `\n# ${inv.packages.length} packages, ${inv.skippedCount} skipped\n`;
      await emit(body, v, io);
      return 0;
    }
    if (cmd === 'show-query') {
      const { queries, skipped } = buildOsvQueries(inv.packages);
      await emit(safeJson({
        note: 'This is everything --online would send to api.osv.dev, in batches. Nothing was sent.',
        endpoint: OSV_BATCH_URL,
        then: OSV_VULN_URL + '<advisory id> for each id returned',
        kev_download: v['no-kev'] || v.kev ? null : KEV_URL + ' (plain GET, nothing about you is sent)',
        user_agent: USER_AGENT,
        not_queried: skipped.length,
        queries
      }) + '\n', v, io);
      return 0;
    }

    if (!v.online && !v.osv) throw new UsageError('no advisory data: pass --osv <downloaded OSV data> or opt in with --online');
    if (v['save-osv'] && !v.online) throw new UsageError('--save-osv only makes sense with --online');
    // Open the --save-osv file before any network traffic, so an existing
    // file is refused up front instead of after a long download.
    let saveHandle = null;
    if (v['save-osv']) {
      try {
        saveHandle = await open(v['save-osv'], v.force ? 'w' : 'wx', 0o644);
      } catch (e) {
        if (e.code === 'EEXIST') throw new UsageError(`${v['save-osv']} exists; pass --force to overwrite`);
        throw new InputError(`cannot write ${v['save-osv']}: ${e.code || e.message}`);
      }
    }
    const index = createIndex();
    const wanted = wantedKeys(inv.packages);
    const sources = [];
    let kev = null;
    let onlineInfo = null;
    try {
      for (const p of v.osv || []) {
        const r = await loadOsvPath(p, index, wanted);
        sources.push({ type: 'offline', files: r.files });
      }
      if (v.kev && !v['no-kev']) kev = parseKev(await readJson(v.kev, IO_LIMITS.kevBytes));
      if (v.online) {
        const saved = v['save-osv'] ? [] : null;
        const r = await queryOsvOnline(inv.packages, index, { fetchImpl: deps.fetchImpl, timeoutMs, saveRecords: saved, onProgress: (m) => io.stderr(m + '\n') });
        inv.warnings.push(...r.warnings);
        onlineInfo = { queried: r.queried, advisories: r.ids, failed: r.failed };
        sources.push({ type: 'online', host: 'api.osv.dev', ...onlineInfo });
        if (!kev && !v['no-kev']) {
          try {
            kev = await fetchKevOnline({ fetchImpl: deps.fetchImpl, timeoutMs });
          } catch (e) {
            if (!(e instanceof NetError)) throw e;
            inv.warnings.push('CISA KEV download failed (' + e.message + '); known-exploited flags are missing');
          }
        }
        if (saved) {
          try {
            for (const line of saved) await saveHandle.write(line + '\n');
          } catch (e) {
            inv.warnings.push(`could not save OSV records to ${v['save-osv']}: ${e.code || e.message}`);
          }
        }
      }
    } finally {
      if (saveHandle) await saveHandle.close();
    }
    if (!kev && !v['no-kev']) inv.warnings.push('no KEV catalog loaded: known-exploited vulnerabilities are not flagged (pass --kev <file>)');
    for (const [reason, n] of index.dropped) {
      if (reason !== 'no affected package in inventory') inv.warnings.push(`${n} OSV records ignored: ${reason}`);
    }
    const findings = matchPackages(index, inv.packages);
    if (index.findingsTruncated) inv.warnings.push('finding limit reached; the report is incomplete');
    const report = buildReport({
      inventory: inv,
      findings,
      kev,
      mode: v.online ? 'online' : 'offline',
      osvInfo: { sources, records_used: index.count }
    });
    await emit(format === 'json' ? renderJson(report) : renderText(report), v, io);
    return report.findings.length ? 1 : 0;
  } catch (e) {
    if (e instanceof UsageError || e instanceof InputError || e instanceof NetError || e instanceof FormatError) {
      io.stderr(`${TOOL_NAME}: ${safeText(e.message, 300)}\n`);
      return 2;
    }
    throw e;
  }
}

export function defaultIo() {
  return {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s)
  };
}
