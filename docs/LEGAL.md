# Legal notes: data sources, privacy, acceptable use

**Not legal advice.** This page is the author's plain-English reading of public terms, written so users and
contributors know what to check. Licenses and terms change; follow the links and read the current text. If
you plan to redistribute reports or ship patch-now inside a product, ask a lawyer.

Last checked: **2026-10-25**.

## 1. Data sources

patch-now **ships no third-party advisory data**. The repository contains only hand-made test fixtures
(`test/fixtures`, `docs/demo.js`) with invented ids. Users fetch real data themselves, either with `--online`
or by downloading it.

### OSV.dev (api.osv.dev and the `osv-vulnerabilities` bucket)

| What | Where | Found |
|---|---|---|
| Data sources and their licenses | https://google.github.io/osv.dev/data/ | Each source keeps its own license (table below). |
| API docs / FAQ | https://google.github.io/osv.dev/faq/ , https://google.github.io/osv.dev/api/ | The FAQ states there is no API rate limit; HTTP/1.1 responses are capped at 32 MiB. `querybatch` returns ids only and paginates large result sets. |
| osv.dev software | https://github.com/google/osv.dev | Apache-2.0. This covers OSV's code, not the advisory data. |
| Terms of service / privacy | none found linked from osv.dev or its docs on 2026-10-25 | OSV.dev is run by Google. No separate ToS was found, so assume Google's general terms and privacy policy (https://policies.google.com/) may apply to the API. **Unverified.** |

Per-source data licenses as listed by OSV on 2026-10-25 (a record's source is visible from its id prefix,
for example `GHSA-`, `PYSEC-`, `RUSTSEC-`, `DSA-`/`DLA-`, `USN-`/`UBUNTU-`, `MAL-`, `CGA-`):

| Source | License | What it means for you (plain English) |
|---|---|---|
| GitHub Advisory Database, PyPI Advisory DB (PyPA), Go Vulnerability DB, OSS-Fuzz, Python Software Foundation, Erlang EEF CNA, Android, Julia, Red Hat | CC-BY 4.0 | Free to use and share, **with attribution**. |
| Rust Advisory DB (RustSec), Global Security Database, Haskell, opam | CC0 1.0 | No conditions. |
| OpenSSF Malicious Packages, Bitnami, RConsortium, CleanStart, V8/Chromium | Apache 2.0 | Keep notices when redistributing. |
| AlmaLinux, Drupal, Azure Linux, BellSoft, curl | MIT | Keep the notice when redistributing. |
| Rocky Linux | BSD | Keep the notice. |
| Ubuntu, Alpine SecDB (converted) | CC-BY-SA 4.0 | Attribution **and share-alike**: if you publish a report that reuses this text, the reused part may have to be shared under CC-BY-SA too. |
| Chainguard / Wolfi | CC-BY-NC-ND 4.0 | **Non-commercial and no derivatives.** Do not reuse this text in commercial reports, and do not modify it. |
| Debian Security Advisories (converted by OSV) | **No license stated by OSV** | The data comes from the Debian security tracker and debian.org (website: MIT/Expat or GPL-2+ for material since 2012, Open Publication License for older material, per https://www.debian.org/license). **Unverified for the OSV records.** |
| NVD CVEs (converted) | NVD is US-government data; OSV lists no license | Generally treated as public domain in the US. **Unverified.** |

**What patch-now does about this:**

- Every text report and the web page include an attribution block naming OSV.dev and pointing here.
- Every finding links to `https://osv.dev/vulnerability/<id>`, where the original record and its source are shown.
- Advisory summaries may be shortened and have control characters escaped, and the attribution block says
  so (CC-BY asks you to indicate changes).

**What you should do:** for private use on your own machines, nothing more is needed. If you **publish or
sell** reports, keep the attribution, keep the links, check each record's source license, and leave out or
license-check CC-BY-SA, CC-BY-NC-ND and unknown-license text.

### CISA Known Exploited Vulnerabilities catalog

| What | Where | Found |
|---|---|---|
| Catalog (JSON) | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Version 2026.10.23, 1,756 entries when checked. |
| License | https://www.cisa.gov/sites/default/files/licenses/kev/license.txt | **CC0 1.0** (public domain dedication). Links inside the catalog to third-party sites fall under those sites' own terms. The CISA logo and DHS seal may not be used to suggest endorsement. |

patch-now uses only the CVE id, date added, due date and the "known ransomware use" field. It does not use
CISA or DHS logos and is not endorsed by CISA or DHS.

### Use of names

"OSV" and "OSV.dev" (Google / OpenSSF), "CISA" and "DHS", "Debian" (Software in the Public Interest), "Ubuntu"
(Canonical), "npm", "PyPI", "GitHub" and other names are trademarks of their owners, used here only to say
where data comes from. patch-now is not affiliated with or endorsed by any of them.

## 2. Privacy

- **Default (offline):** nothing leaves your machine. patch-now reads the files you name and prints a report.
  No telemetry, no update checks, no crash reports, no analytics.
- **`--online` (opt-in):** patch-now contacts exactly two hosts over HTTPS. Redirects are refused and no
  cookies are sent.
  - `api.osv.dev`, `POST /v1/querybatch`: a JSON list of `{package: {name, ecosystem}, version}` for each
    package. Then `GET /v1/vulns/<id>` for each advisory id returned.
  - `www.cisa.gov`: one `GET` of the KEV catalog (skip it with `--no-kev` or `--kev <file>`).
  - Never sent: file paths, file names, hostnames, usernames, IP addresses of other machines, environment
    variables, or which inventory format was used.
  - What the servers can still see: your IP address, request times, TLS metadata, the `User-Agent`
    (`patch-now/0.1.0`), and the package list itself, which can reveal a lot about a machine (OS release,
    software in use, how out of date it is). Google operates OSV.dev.
  - `patch-now show-query ...` prints the exact payload without sending anything.
- **Web page:** runs only on text you paste. Its Content-Security-Policy blocks all network requests, so
  nothing you paste can be sent anywhere by the page. The hosting provider (for example GitHub Pages) sees the
  page request itself, as for any website.

## 3. Acceptable use

- **Defensive use only:** for checking software on systems you own or are authorised to administer.
- **No exploit code:** patch-now contains none and will not accept contributions that add it.
- **No scanning:** patch-now does not probe networks, ports or other people's machines. It reads package
  lists that you provide. Running it on someone else's inventory without their permission may break the law
  where you are (for example computer-misuse or privacy law) even though the tool itself is passive.
- Matching public advisories against a software list is ordinary defensive practice. The author's reading
  (not legal advice) is that export-control rules on "intrusion software" are aimed at exploitation tooling
  and do not cover a read-only inventory checker like this; if you distribute it commercially across borders,
  confirm that with counsel.

## 4. No warranty

MIT licensed, provided "as is" (see [LICENSE](../LICENSE)). Results can be wrong in both directions (see the
README's "Honest limits"). Do not rely on patch-now as your only control or as evidence of compliance.

## 5. Points worth a lawyer's attention

1. Redistributing reports that include advisory text from CC-BY-SA (Ubuntu, Alpine), CC-BY-NC-ND (Chainguard)
   or unlicensed (Debian, NVD-derived) sources, especially commercially.
2. Whether Google terms apply to automated use of the OSV.dev API (no OSV-specific ToS found).
3. Privacy duties if patch-now is run by an organisation on employees' or customers' machines with
   `--online`: the package list goes to a third party (Google) in the US.
4. Trademark/endorsement wording if the project is promoted or packaged.
