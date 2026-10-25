# Threat model

patch-now reads a package inventory and advisory data, and prints a report. This document lists what can go
wrong and what the code does about it. File references point at the code that implements each defence.

## Assets

1. The user's machine: it must not run code, write unexpected files or hang because of patch-now.
2. The user's privacy: the package list describes their machine.
3. The truth of the report: a wrong "all clear" is the most harmful failure.

## Trust boundaries and threats

| # | Threat | Source | Defence | Where |
|---|---|---|---|---|
| T1 | Code execution from inventory files (malicious `package-lock.json`, requirements with `-e`/URLs) | Untrusted project files | Files are parsed as data. Nothing is executed, imported or installed; no shell is spawned. Editable/URL requirements are skipped. | `src/core/inventory.js` |
| T2 | Terminal escape / bidi / zero-width tricks in advisory text ("Trojan Source"-style display spoofing, fake prompts) | Advisory databases, a tampered dump | `safeText` escapes C0/C1 controls, bidi controls, zero-width characters, U+2028/2029 and BOM as `\uXXXX`, and truncates. JSON output escapes the same set. | `src/core/display.js` |
| T3 | HTML/script injection on the web page | Pasted advisory JSON | Only `textContent`; no `innerHTML`, `eval`, `Function`, or network APIs (a test enforces this). CSP: `default-src 'none'; script-src 'self'; connect-src 'none'; ...`. Verified in headless Chrome by `scripts/browser-check.mjs`. | `docs/app.js`, `docs/index.html` |
| T4 | Prompt injection: advisory text telling a human or an AI assistant to ignore findings | Advisory text | Reports label summaries "(untrusted)" and print a standing note not to follow instructions in them. Text never changes the verdict: matching uses only structured version fields. | `src/core/report.js` |
| T5 | Regex denial of service | Any string input | All regexes are anchored with bounded repetition and no overlapping quantifiers; risky ones were rewritten (pip line parsing, CVSS vector). A fuzz test with ~1,000 adversarial strings per parser fails if any call takes over 1 s (measured worst ~5 ms). | `src/core/*.js`, `test/injection.test.js` |
| T6 | Memory/CPU exhaustion | Huge or deeply nested inputs | Caps on file sizes (64 MB inventory, 256 MB single OSV file, 16 MB per file in a directory, 32 MB KEV), on packages, npm tree nodes and depth, OSV affected/ranges/events/versions/aliases per record, total records, findings, and skipped-entry lists. Parsers and tree walks are iterative. | `src/io.js`, `src/core/inventory.js`, `src/core/osv.js` |
| T7 | Hang on special files (`/dev/zero`, a FIFO) | Command-line paths | Files opened with `O_NONBLOCK`, then `fstat` must say regular file; reads are capped even if the file grows. | `src/io.js` |
| T8 | Path traversal / reading outside the chosen OSV directory | Symlinks in a downloaded dump | Directory walks never follow symlinks (`readdir` types plus `O_NOFOLLOW` on open), have a depth limit and an entry limit. | `src/io.js` |
| T9 | Overwriting user files | `--out`, `--save-osv` | Both open with exclusive create (`wx`) unless `--force`. `--save-osv` is opened before any network traffic. | `src/cli.js` |
| T10 | Network attacker or hostile server | `--online` | HTTPS only, two allow-listed hosts, no redirects, no credentials or ports in URLs, per-request timeout, per-response size caps, a 512 MB total download budget, at most 5,000 records and 10 pagination rounds. Advisory ids are validated before being put in a URL. Responses go through the same validation as offline data. | `src/online.js` |
| T11 | Privacy leak | `--online` | Opt-in only; payload limited to name, ecosystem and version; `show-query` prints it without sending. The web page cannot make requests. | `src/online.js`, `docs/LEGAL.md` |
| T12 | Wrong "all clear" | Parsing or comparison bugs | Per-ecosystem comparators (semver, PEP 440, dpkg) cross-checked against reference implementations; results that cannot be compared are reported as "could not decide" instead of being dropped; approximate comparisons are labelled; withdrawn records are ignored; the README lists known blind spots. | `src/core/compare.js`, `scripts/cross-check.mjs` |
| T13 | Secrets in the repository | Development mistakes | No credentials are needed or stored. gitleaks runs before commits and in CI. | `ci/test.yml` |

## Out of scope

- A compromised advisory source publishing false data (patch-now reports what the source says).
- A compromised Node.js runtime, operating system or browser.
- Attacks that need write access to the user's own inventory files: that attacker already controls the machine.
- Completeness of advisory databases.
