# Security policy

## Reporting a vulnerability

Please report security problems in patch-now privately through GitHub's
"Report a vulnerability" (Security tab > Advisories) on https://github.com/1ntern0t/patch-now.
Do not open a public issue for an unfixed problem. Include the version, the input that triggers it and what
happens. There is no bug bounty and no paid support; this is a single-maintainer personal project, so expect a
best-effort reply.

In scope: anything that makes patch-now run code from its input, write or read files it should not, send data it
should not, hang or exhaust memory on hostile input below its documented limits, render advisory text as HTML,
or report a wrong result because of a parsing bug.

Out of scope: vulnerabilities in the packages patch-now reports on (report those upstream or to the advisory
source), and missing advisories (report those to OSV or the original database).

## Design summary

See [THREAT-MODEL.md](THREAT-MODEL.md). In short:

- Offline by default; `--online` talks only to `api.osv.dev` and `www.cisa.gov` over HTTPS, refuses
  redirects, applies timeouts and response size caps, and sends only package name, ecosystem and version.
- Inputs are parsed, never executed. Only regular files are read (no FIFOs or devices), with size caps; OSV
  directory walks do not follow symlinks and have depth and entry limits.
- All advisory text is treated as untrusted: control, bidi and zero-width characters are escaped on output, and
  the web page writes it only through `textContent` under a CSP that forbids scripts from other origins and all
  network requests.
- No dependencies. No telemetry. No secrets in the repository (checked with gitleaks before each commit).

## Supported versions

Only the latest commit on `main`.
