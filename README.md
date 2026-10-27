# patch-now

Which of the software on my machine has known vulnerabilities, and what should I update first?

patch-now reads the package lists your package managers already keep (dpkg, npm, pip), matches them against
public advisories from [OSV](https://osv.dev) and flags anything on the CISA
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) list. It is meant
for checking your own machines.

- **Local-first.** Offline by default. It sends nothing anywhere unless you pass `--online`.
- **No telemetry, no accounts, no cloud service.**
- **Zero dependencies.** Node 20+, standard library only. MIT licensed.
- **Read-only.** It parses files. It never runs `npm`, `pip`, `dpkg` or your code, and never installs anything.
- **Static web page.** [`docs/index.html`](docs/index.html) does the same check in your browser on text you paste.
  Its Content-Security-Policy forbids network requests (`connect-src 'none'`).

> A clean result does **not** mean you are safe. See [Honest limits](#honest-limits).

## Quick start

```sh
git clone https://github.com/1ntern0t/patch-now.git && cd patch-now
npm test                                   # optional: run the test suite

# 1. See exactly what --online would send (sends nothing):
node bin/patch-now.js show-query --dpkg /var/lib/dpkg/status

# 2a. Online (opt-in): asks api.osv.dev about each package, downloads the KEV catalog
node bin/patch-now.js scan --dpkg /var/lib/dpkg/status --online

# 2b. Fully offline: download the data yourself, then check with no network at all
curl -LO https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip
unzip -q all.zip -d osv-debian
curl -LO https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
node bin/patch-now.js scan --dpkg /var/lib/dpkg/status --osv osv-debian --kev known_exploited_vulnerabilities.json
```

Other inventories:

```sh
node bin/patch-now.js scan --npm-lock package-lock.json --osv osv-npm
npm ls --all --json > npm-ls.json && node bin/patch-now.js scan --npm-ls npm-ls.json --online
pip freeze > pip.txt && node bin/patch-now.js scan --pip pip.txt --online
node bin/patch-now.js scan --list mine.txt --osv osv-dir   # lines of "ecosystem name version"
node bin/patch-now.js scan ... --format json --out report.json
```

Per-ecosystem OSV downloads are at `https://storage.googleapis.com/osv-vulnerabilities/<Ecosystem>/all.zip`
(for example `PyPI`, `npm`, `Debian`, `Ubuntu`). Unzip them first; patch-now does not read zip files.
`--osv` takes a directory of `*.json` records, one JSON file (a record, an array, or an API response) or NDJSON.
With `--online --save-osv records.ndjson` the fetched records are saved for later offline runs.

Exit codes: `0` nothing matched, `1` findings, `2` usage or input error.

**Only what you can act on:** distro feeds list many CVEs that have no fixed package yet. On a stock Debian 13
container, 1,473 of 1,474 findings had no fixed version. `--fixable-only` hides those (known-exploited and
malicious-package findings are always kept), and the exit code then follows what is shown. The summary
always says how many findings list a fix and how many were hidden.

## What the report shows

Findings are ordered: **known exploited (CISA KEV) first**, then **malicious packages** (OSV `MAL-` records:
remove these, don't upgrade), then by severity (CVSS v3 base score computed from the vector, else the
source's own label). Each finding shows the installed version, the advisory id and its aliases, the fixed
version(s) when the advisory lists them, and a link to osv.dev. The same issue published under several ids
(for example `GHSA-...` and `PYSEC-...`) is shown once, with the other ids under "also known as".

Some results are marked:

- **approximate**: the version scheme was compared with a generic fallback, or a Debian/Ubuntu package was checked
  without knowing the release. Check it yourself.
- **could not decide**: the advisory's versions could not be compared with yours. Listed separately, not counted
  as findings.

All advisory text is third-party data. patch-now prints it as escaped plain text (control characters, bidi
overrides and zero-width characters are shown as `\uXXXX`) and never renders it as HTML. Do not follow
instructions found inside advisory text.

## What `--online` sends

Only to `https://api.osv.dev` (no redirects followed, no cookies, 30 s timeout, size caps):

```
POST /v1/querybatch   {"queries":[{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}, ...]}
GET  /v1/vulns/<advisory id>     for each advisory id the batch query returned
```

Plus one plain `GET` of the KEV catalog from `https://www.cisa.gov` (nothing about you is in it).
No file paths, hostnames, usernames, machine ids or inventory file names are sent. The servers do see your IP
address, the time, TLS metadata and `User-Agent: patch-now/0.1.0`, and the package list itself says a lot
about a machine. If that matters, use the offline workflow. Details: [docs/LEGAL.md](docs/LEGAL.md#privacy).

## Honest limits

Read these before trusting a result.

**False negatives (missed problems)**

- Only what OSV knows about. Software without OSV advisories, unpublished issues and zero-days are invisible.
- Only these inventories: dpkg (Debian/Ubuntu), npm lockfiles / `npm ls`, pip freeze / pinned requirements,
  and hand-written lists. **Not covered:** rpm, apk, pacman, Homebrew, Windows or macOS apps, Snap, Flatpak,
  containers, firmware, browser extensions, vendored or statically linked code, language runtimes installed
  outside a package manager, and anything you built yourself.
- `requirements.txt` lines without an exact `==` pin are skipped (a range is not a version). `-r` includes
  are not followed.
- OSV `GIT` ranges (commit hashes) are ignored; only `SEMVER`/`ECOSYSTEM` ranges and explicit version lists are
  used. In a live comparison this missed 5 of 28,941 matches OSV's server reported (see Verification).
- Debian/Ubuntu: OSV records are keyed by **source** package; patch-now uses the `Source:` field from dpkg.
  Without the release (`--os-ecosystem Debian:12`, or `/etc/os-release`) matching is approximate and online
  lookups skip those packages.
- Ubuntu Pro / ESM ecosystems and Debian LTS-only fixes may not match your installed version string.
- Input must be a regular file: pipes such as `pip freeze | patch-now --pip /dev/stdin` are refused (save to a
  file first). This is deliberate, so a FIFO or device cannot hang the tool.
- `--online` fetches at most 5,000 advisory records per run and 512 MB in total; a warning says so if cut.
- KEV matching is by CVE id only, via the advisory's aliases. An advisory without a CVE alias never gets the
  KEV flag.

**False positives (reported but not really a problem)**

- Distribution backports: a distro can fix a bug without changing the upstream version the advisory lists.
  Debian/Ubuntu records written by the distro account for this; generic upstream records do not.
- Debian binNMU versions (`+b1`) and local rebuilds compare as different versions.
- Advisories describe a package, not your configuration. A vulnerable function you never call still shows up.
- Severity is the advisory's, not your exposure.

**Version comparison**

- npm and `SEMVER` ranges: Semantic Versioning 2.0 precedence.
- PyPI: PEP 440 ordering (epochs, pre/post/dev releases, local versions), cross-checked against Python
  `packaging`. Non-PEP 440 legacy versions cannot be compared and become "could not decide".
- Debian/Ubuntu: dpkg ordering (epoch, `~`, revisions), cross-checked against `dpkg --compare-versions`.
- **Everything else (Go, Maven, crates.io, RubyGems, NuGet, ...) uses a generic, approximate comparison** and every
  such result is marked approximate.
- CVSS v4 vectors are not scored; such advisories fall back to the source's label or `UNKNOWN`.

**Other**

- One author, no external audit. Treat it as a helpful second opinion, not a compliance tool.
- Not legal advice, not a security guarantee. See [docs/LEGAL.md](docs/LEGAL.md).

## Verification

What was actually run (2026-10-25, Node 20.19.2, Debian 13 box):

- `npm test`: 82 tests, 82 passing (node:test, Node 20.19.2). Fixtures in `test/fixtures` are hand-made
  and use invented ids (`FIXTURE-...`, `CVE-2099-...`); they are not real advisories.
- `node scripts/cross-check.mjs 2000`: 2,000 random Debian version pairs against `dpkg --compare-versions` and
  2,000 PEP 440 pairs against Python `packaging`: 0 mismatches.
- `scripts/browser-check.mjs` (optional, headless Chrome): the page made no external requests, a forced `fetch`
  was blocked by CSP, hostile advisory text stayed inert text, oversized input was refused.
- Live differential against OSV's own server-side matching (not part of the test suite, run once by hand):
  - 397 PyPI package/version pairs sampled from the OSV PyPI dump: local matching found 28,936 of the server's
    28,941 matches and nothing the server did not; the 5 differences all come from `GIT` ranges (see limits).
  - 471 Debian 13 source packages from a real dpkg status file against the OSV Debian dump: 1,471 of 1,471,
    no extra.
  - 426 npm packages from two real lockfiles: 44 of 44, no extra.

There are no performance claims here because none were benchmarked.

## Layout

```
bin/patch-now.js      CLI entry
src/core/*            pure parsing / matching / report code (also bundled for the web page)
src/io.js             size-capped file reading, OSV directory loading
src/online.js         the only code that touches the network (--online)
docs/                 static page (index.html, app.js, generated core.js), LEGAL.md
scripts/              build-docs.js, cross-check.mjs, browser-check.mjs
test/                 node:test suites and hand-made fixtures
ci/test.yml           GitHub Actions workflow, to be copied to .github/workflows/ by a maintainer
```

After changing `src/core`, run `node scripts/build-docs.js` (a test fails if `docs/core.js` is stale).

## Data and attribution

Advisory data comes from OSV.dev, which aggregates many sources, **each under its own license** (CC-BY 4.0,
CC-BY-SA 4.0, CC0, MIT, Apache 2.0, CC-BY-NC-ND 4.0 and others). The KEV catalog is published by CISA under CC0 1.0.
patch-now ships no third-party advisory data. It is not affiliated with or endorsed by Google, OSV, OpenSSF, CISA
or DHS. Read [docs/LEGAL.md](docs/LEGAL.md) before redistributing reports.

## Use

Defensive use on systems you own or administer. patch-now contains no exploit code and does not scan networks or
other people's machines. See [SECURITY.md](SECURITY.md) and [THREAT-MODEL.md](THREAT-MODEL.md).

## License

MIT, see [LICENSE](LICENSE).
